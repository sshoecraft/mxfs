// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */

#include "xfs_platform.h"
#include <linux/namei.h>
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_btree.h"
#include "xfs_bmap.h"
#include "xfs_alloc.h"
#include "xfs_fsops.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"	/* sess39: xfs_ail_push_all_sync for sync_fs */
#include "xfs_buf_item.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_dir2.h"
#include "xfs_extfree_item.h"
#include "xfs_mru_cache.h"
#include "xfs_inode_item.h"
#include "xfs_icache.h"
#include "xfs_trace.h"
#include "xfs_icreate_item.h"
#include "xfs_filestream.h"
#include "xfs_quota.h"
#include "xfs_sysfs.h"
#include "xfs_ondisk.h"
#include "xfs_rmap_item.h"
#include "xfs_refcount_item.h"
#include "xfs_bmap_item.h"
#include "xfs_reflink.h"
#include "xfs_pwork.h"
#include "xfs_ag.h"
#include "xfs_defer.h"
#include "xfs_attr_item.h"
#include "xfs_xattr.h"
#include "xfs_error.h"
#include "xfs_errortag.h"
#include "xfs_iunlink_item.h"
#include "xfs_dahash_test.h"
#include "xfs_rtbitmap.h"
#include "xfs_exchmaps_item.h"
#include "xfs_parent.h"
#include "xfs_rtalloc.h"
#include "xfs_zone_alloc.h"
#include "xfs_healthmon.h"
#include "scrub/stats.h"
#include "scrub/rcbag_btree.h"

#include <mxfs/mxfs_super.h>
#include "../../dlm/v5_mount.h"
#include "../../xfs/xfs_mxfs_dlm.h"
#include <linux/magic.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/fserror.h>

static const struct super_operations xfs_super_operations;

static struct dentry *xfs_debugfs;	/* top-level xfs debugfs dir */
static struct kset *xfs_kset;		/* top-level xfs sysfs dir */
#ifdef DEBUG
static struct xfs_kobj xfs_dbg_kobj;	/* global debug sysfs attrs */
#endif

enum xfs_dax_mode {
	XFS_DAX_INODE = 0,
	XFS_DAX_ALWAYS = 1,
	XFS_DAX_NEVER = 2,
};

/* Were quota mount options provided?  Must use the upper 16 bits of qflags. */
#define XFS_QFLAGS_MNTOPTS	(1U << 31)

static void
xfs_mount_set_dax_mode(
	struct xfs_mount	*mp,
	enum xfs_dax_mode	mode)
{
	switch (mode) {
	case XFS_DAX_INODE:
		mp->m_features &= ~(XFS_FEAT_DAX_ALWAYS | XFS_FEAT_DAX_NEVER);
		break;
	case XFS_DAX_ALWAYS:
		mp->m_features |= XFS_FEAT_DAX_ALWAYS;
		mp->m_features &= ~XFS_FEAT_DAX_NEVER;
		break;
	case XFS_DAX_NEVER:
		mp->m_features |= XFS_FEAT_DAX_NEVER;
		mp->m_features &= ~XFS_FEAT_DAX_ALWAYS;
		break;
	}
}

static const struct constant_table dax_param_enums[] = {
	{"inode",	XFS_DAX_INODE },
	{"always",	XFS_DAX_ALWAYS },
	{"never",	XFS_DAX_NEVER },
	{}
};

/*
 * Table driven mount option parser.
 */
enum {
	Op_deprecated, Opt_logbufs, Opt_logbsize, Opt_logdev, Opt_rtdev,
	Opt_wsync, Opt_noalign, Opt_swalloc, Opt_sunit, Opt_swidth, Opt_nouuid,
	Opt_grpid, Opt_nogrpid, Opt_bsdgroups, Opt_sysvgroups,
	Opt_allocsize, Opt_norecovery, Opt_inode64, Opt_inode32,
	Opt_largeio, Opt_nolargeio,
	Opt_filestreams, Opt_quota, Opt_noquota, Opt_usrquota, Opt_grpquota,
	Opt_prjquota, Opt_uquota, Opt_gquota, Opt_pquota,
	Opt_uqnoenforce, Opt_gqnoenforce, Opt_pqnoenforce, Opt_qnoenforce,
	Opt_discard, Opt_nodiscard, Opt_dax, Opt_dax_enum, Opt_max_open_zones,
	Opt_lifetime, Opt_nolifetime, Opt_max_atomic_write, Opt_errortag,
};

#define fsparam_dead(NAME) \
	__fsparam(NULL, (NAME), Op_deprecated, fs_param_deprecated, NULL)

static const struct fs_parameter_spec xfs_fs_parameters[] = {
	/*
	 * These mount options were supposed to be deprecated in September 2025
	 * but the deprecation warning was buggy, so not all users were
	 * notified.  The deprecation is now obnoxiously loud and postponed to
	 * September 2030.
	 */
	fsparam_dead("attr2"),
	fsparam_dead("noattr2"),
	fsparam_dead("ikeep"),
	fsparam_dead("noikeep"),

	fsparam_u32("logbufs",		Opt_logbufs),
	fsparam_string("logbsize",	Opt_logbsize),
	fsparam_string("logdev",	Opt_logdev),
	fsparam_string("rtdev",		Opt_rtdev),
	fsparam_flag("wsync",		Opt_wsync),
	fsparam_flag("noalign",		Opt_noalign),
	fsparam_flag("swalloc",		Opt_swalloc),
	fsparam_u32("sunit",		Opt_sunit),
	fsparam_u32("swidth",		Opt_swidth),
	fsparam_flag("nouuid",		Opt_nouuid),
	fsparam_flag("grpid",		Opt_grpid),
	fsparam_flag("nogrpid",		Opt_nogrpid),
	fsparam_flag("bsdgroups",	Opt_bsdgroups),
	fsparam_flag("sysvgroups",	Opt_sysvgroups),
	fsparam_string("allocsize",	Opt_allocsize),
	fsparam_flag("norecovery",	Opt_norecovery),
	fsparam_flag("inode64",		Opt_inode64),
	fsparam_flag("inode32",		Opt_inode32),
	fsparam_flag("largeio",		Opt_largeio),
	fsparam_flag("nolargeio",	Opt_nolargeio),
	fsparam_flag("filestreams",	Opt_filestreams),
	fsparam_flag("quota",		Opt_quota),
	fsparam_flag("noquota",		Opt_noquota),
	fsparam_flag("usrquota",	Opt_usrquota),
	fsparam_flag("grpquota",	Opt_grpquota),
	fsparam_flag("prjquota",	Opt_prjquota),
	fsparam_flag("uquota",		Opt_uquota),
	fsparam_flag("gquota",		Opt_gquota),
	fsparam_flag("pquota",		Opt_pquota),
	fsparam_flag("uqnoenforce",	Opt_uqnoenforce),
	fsparam_flag("gqnoenforce",	Opt_gqnoenforce),
	fsparam_flag("pqnoenforce",	Opt_pqnoenforce),
	fsparam_flag("qnoenforce",	Opt_qnoenforce),
	fsparam_flag("discard",		Opt_discard),
	fsparam_flag("nodiscard",	Opt_nodiscard),
	fsparam_flag("dax",		Opt_dax),
	fsparam_enum("dax",		Opt_dax_enum, dax_param_enums),
	fsparam_u32("max_open_zones",	Opt_max_open_zones),
	fsparam_flag("lifetime",	Opt_lifetime),
	fsparam_flag("nolifetime",	Opt_nolifetime),
	fsparam_string("max_atomic_write",	Opt_max_atomic_write),
	fsparam_string("errortag",	Opt_errortag),
	{}
};

struct proc_xfs_info {
	uint64_t	flag;
	char		*str;
};

static int
xfs_fs_show_options(
	struct seq_file		*m,
	struct dentry		*root)
{
	static struct proc_xfs_info xfs_info_set[] = {
		/* the few simple ones we can get from the mount struct */
		{ XFS_FEAT_WSYNC,		",wsync" },
		{ XFS_FEAT_NOALIGN,		",noalign" },
		{ XFS_FEAT_SWALLOC,		",swalloc" },
		{ XFS_FEAT_NOUUID,		",nouuid" },
		{ XFS_FEAT_NORECOVERY,		",norecovery" },
		{ XFS_FEAT_FILESTREAMS,		",filestreams" },
		{ XFS_FEAT_GRPID,		",grpid" },
		{ XFS_FEAT_DISCARD,		",discard" },
		{ XFS_FEAT_LARGE_IOSIZE,	",largeio" },
		{ XFS_FEAT_DAX_ALWAYS,		",dax=always" },
		{ XFS_FEAT_DAX_NEVER,		",dax=never" },
		{ XFS_FEAT_NOLIFETIME,		",nolifetime" },
		{ 0, NULL }
	};
	struct xfs_mount	*mp = XFS_M(root->d_sb);
	struct proc_xfs_info	*xfs_infop;

	for (xfs_infop = xfs_info_set; xfs_infop->flag; xfs_infop++) {
		if (mp->m_features & xfs_infop->flag)
			seq_puts(m, xfs_infop->str);
	}

	seq_printf(m, ",inode%d", xfs_has_small_inums(mp) ? 32 : 64);

	if (xfs_has_allocsize(mp))
		seq_printf(m, ",allocsize=%dk",
			   (1 << mp->m_allocsize_log) >> 10);

	if (mp->m_logbufs > 0)
		seq_printf(m, ",logbufs=%d", mp->m_logbufs);
	if (mp->m_logbsize > 0)
		seq_printf(m, ",logbsize=%dk", mp->m_logbsize >> 10);

	if (mp->m_logname)
		seq_show_option(m, "logdev", mp->m_logname);
	if (mp->m_rtname)
		seq_show_option(m, "rtdev", mp->m_rtname);

	if (mp->m_dalign > 0)
		seq_printf(m, ",sunit=%d",
				(int)XFS_FSB_TO_BB(mp, mp->m_dalign));
	if (mp->m_swidth > 0)
		seq_printf(m, ",swidth=%d",
				(int)XFS_FSB_TO_BB(mp, mp->m_swidth));

	if (mp->m_qflags & XFS_UQUOTA_ENFD)
		seq_puts(m, ",usrquota");
	else if (mp->m_qflags & XFS_UQUOTA_ACCT)
		seq_puts(m, ",uqnoenforce");

	if (mp->m_qflags & XFS_PQUOTA_ENFD)
		seq_puts(m, ",prjquota");
	else if (mp->m_qflags & XFS_PQUOTA_ACCT)
		seq_puts(m, ",pqnoenforce");

	if (mp->m_qflags & XFS_GQUOTA_ENFD)
		seq_puts(m, ",grpquota");
	else if (mp->m_qflags & XFS_GQUOTA_ACCT)
		seq_puts(m, ",gqnoenforce");

	if (!(mp->m_qflags & XFS_ALL_QUOTA_ACCT))
		seq_puts(m, ",noquota");

	if (mp->m_max_open_zones)
		seq_printf(m, ",max_open_zones=%u", mp->m_max_open_zones);
	if (mp->m_awu_max_bytes)
		seq_printf(m, ",max_atomic_write=%lluk",
				mp->m_awu_max_bytes >> 10);

	return 0;
}

static bool
xfs_set_inode_alloc_perag(
	struct xfs_perag	*pag,
	xfs_ino_t		ino,
	xfs_agnumber_t		max_metadata)
{
	if (!xfs_is_inode32(pag_mount(pag))) {
		set_bit(XFS_AGSTATE_ALLOWS_INODES, &pag->pag_opstate);
		clear_bit(XFS_AGSTATE_PREFERS_METADATA, &pag->pag_opstate);
		return false;
	}

	if (ino > XFS_MAXINUMBER_32) {
		clear_bit(XFS_AGSTATE_ALLOWS_INODES, &pag->pag_opstate);
		clear_bit(XFS_AGSTATE_PREFERS_METADATA, &pag->pag_opstate);
		return false;
	}

	set_bit(XFS_AGSTATE_ALLOWS_INODES, &pag->pag_opstate);
	if (pag_agno(pag) < max_metadata)
		set_bit(XFS_AGSTATE_PREFERS_METADATA, &pag->pag_opstate);
	else
		clear_bit(XFS_AGSTATE_PREFERS_METADATA, &pag->pag_opstate);
	return true;
}

/*
 * Set parameters for inode allocation heuristics, taking into account
 * filesystem size and inode32/inode64 mount options; i.e. specifically
 * whether or not XFS_FEAT_SMALL_INUMS is set.
 *
 * Inode allocation patterns are altered only if inode32 is requested
 * (XFS_FEAT_SMALL_INUMS), and the filesystem is sufficiently large.
 * If altered, XFS_OPSTATE_INODE32 is set as well.
 *
 * An agcount independent of that in the mount structure is provided
 * because in the growfs case, mp->m_sb.sb_agcount is not yet updated
 * to the potentially higher ag count.
 *
 * Returns the maximum AG index which may contain inodes.
 */
xfs_agnumber_t
xfs_set_inode_alloc(
	struct xfs_mount *mp,
	xfs_agnumber_t	agcount)
{
	xfs_agnumber_t	index;
	xfs_agnumber_t	maxagi = 0;
	xfs_sb_t	*sbp = &mp->m_sb;
	xfs_agnumber_t	max_metadata;
	xfs_agino_t	agino;
	xfs_ino_t	ino;

	/*
	 * Calculate how much should be reserved for inodes to meet
	 * the max inode percentage.  Used only for inode32.
	 */
	if (M_IGEO(mp)->maxicount) {
		uint64_t	icount;

		icount = sbp->sb_dblocks * sbp->sb_imax_pct;
		do_div(icount, 100);
		icount += sbp->sb_agblocks - 1;
		do_div(icount, sbp->sb_agblocks);
		max_metadata = icount;
	} else {
		max_metadata = agcount;
	}

	/* Get the last possible inode in the filesystem */
	agino =	XFS_AGB_TO_AGINO(mp, sbp->sb_agblocks - 1);
	ino = XFS_AGINO_TO_INO(mp, agcount - 1, agino);

	/*
	 * If user asked for no more than 32-bit inodes, and the fs is
	 * sufficiently large, set XFS_OPSTATE_INODE32 if we must alter
	 * the allocator to accommodate the request.
	 */
	if (xfs_has_small_inums(mp) && ino > XFS_MAXINUMBER_32)
		xfs_set_inode32(mp);
	else
		xfs_clear_inode32(mp);

	for (index = 0; index < agcount; index++) {
		struct xfs_perag	*pag;

		ino = XFS_AGINO_TO_INO(mp, index, agino);

		pag = xfs_perag_get(mp, index);
		if (xfs_set_inode_alloc_perag(pag, ino, max_metadata))
			maxagi++;
		xfs_perag_put(pag);
	}

	return xfs_is_inode32(mp) ? maxagi : agcount;
}

static int
xfs_setup_dax_always(
	struct xfs_mount	*mp)
{
	if (!mp->m_ddev_targp->bt_daxdev &&
	    (!mp->m_rtdev_targp || !mp->m_rtdev_targp->bt_daxdev)) {
		xfs_alert(mp,
			"DAX unsupported by block device. Turning off DAX.");
		goto disable_dax;
	}

	if (mp->m_super->s_blocksize != PAGE_SIZE) {
		xfs_alert(mp,
			"DAX not supported for blocksize. Turning off DAX.");
		goto disable_dax;
	}

	if (xfs_has_reflink(mp) &&
	    bdev_is_partition(mp->m_ddev_targp->bt_bdev)) {
		xfs_alert(mp,
			"DAX and reflink cannot work with multi-partitions!");
		return -EINVAL;
	}

	return 0;

disable_dax:
	xfs_mount_set_dax_mode(mp, XFS_DAX_NEVER);
	return 0;
}

STATIC int
xfs_blkdev_get(
	xfs_mount_t		*mp,
	const char		*name,
	struct file		**bdev_filep)
{
	int			error = 0;
	blk_mode_t		mode;

	mode = sb_open_mode(mp->m_super->s_flags);
	*bdev_filep = bdev_file_open_by_path(name, mode,
			mp->m_super, &fs_holder_ops);
	if (IS_ERR(*bdev_filep)) {
		error = PTR_ERR(*bdev_filep);
		*bdev_filep = NULL;
		xfs_warn(mp, "Invalid device [%s], error=%d", name, error);
	}

	return error;
}

STATIC void
xfs_shutdown_devices(
	struct xfs_mount	*mp)
{
	/*
	 * Udev is triggered whenever anyone closes a block device or unmounts
	 * a file systemm on a block device.
	 * The default udev rules invoke blkid to read the fs super and create
	 * symlinks to the bdev under /dev/disk.  For this, it uses buffered
	 * reads through the page cache.
	 *
	 * xfs_db also uses buffered reads to examine metadata.  There is no
	 * coordination between xfs_db and udev, which means that they can run
	 * concurrently.  Note there is no coordination between the kernel and
	 * blkid either.
	 *
	 * On a system with 64k pages, the page cache can cache the superblock
	 * and the root inode (and hence the root directory) with the same 64k
	 * page.  If udev spawns blkid after the mkfs and the system is busy
	 * enough that it is still running when xfs_db starts up, they'll both
	 * read from the same page in the pagecache.
	 *
	 * The unmount writes updated inode metadata to disk directly.  The XFS
	 * buffer cache does not use the bdev pagecache, so it needs to
	 * invalidate that pagecache on unmount.  If the above scenario occurs,
	 * the pagecache no longer reflects what's on disk, xfs_db reads the
	 * stale metadata, and fails to find /a.  Most of the time this succeeds
	 * because closing a bdev invalidates the page cache, but when processes
	 * race, everyone loses.
	 */
	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp) {
		blkdev_issue_flush(mp->m_logdev_targp->bt_bdev);
		invalidate_bdev(mp->m_logdev_targp->bt_bdev);
	}
	if (mp->m_rtdev_targp) {
		blkdev_issue_flush(mp->m_rtdev_targp->bt_bdev);
		invalidate_bdev(mp->m_rtdev_targp->bt_bdev);
	}
	blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	invalidate_bdev(mp->m_ddev_targp->bt_bdev);
}

/*
 * The file system configurations are:
 *	(1) device (partition) with data and internal log
 *	(2) logical volume with data and log subvolumes.
 *	(3) logical volume with data, log, and realtime subvolumes.
 *
 * We only have to handle opening the log and realtime volumes here if
 * they are present.  The data subvolume has already been opened by
 * get_sb_bdev() and is stored in sb->s_bdev.
 */
STATIC int
xfs_open_devices(
	struct xfs_mount	*mp)
{
	struct super_block	*sb = mp->m_super;
	struct block_device	*ddev = sb->s_bdev;
	struct file		*logdev_file = NULL, *rtdev_file = NULL;
	int			error;

	/*
	 * Open real time and log devices - order is important.
	 */
	if (mp->m_logname) {
		error = xfs_blkdev_get(mp, mp->m_logname, &logdev_file);
		if (error)
			return error;
	}

	if (mp->m_rtname) {
		error = xfs_blkdev_get(mp, mp->m_rtname, &rtdev_file);
		if (error)
			goto out_close_logdev;

		if (file_bdev(rtdev_file) == ddev ||
		    (logdev_file &&
		     file_bdev(rtdev_file) == file_bdev(logdev_file))) {
			xfs_warn(mp,
	"Cannot mount filesystem with identical rtdev and ddev/logdev.");
			error = -EINVAL;
			goto out_close_rtdev;
		}
	}

	/*
	 * Setup xfs_mount buffer target pointers
	 */
	mp->m_ddev_targp = xfs_alloc_buftarg(mp, mxfs_sb_bdev_file(sb));
	if (IS_ERR(mp->m_ddev_targp)) {
		error = PTR_ERR(mp->m_ddev_targp);
		mp->m_ddev_targp = NULL;
		goto out_close_rtdev;
	}

	if (rtdev_file) {
		mp->m_rtdev_targp = xfs_alloc_buftarg(mp, rtdev_file);
		if (IS_ERR(mp->m_rtdev_targp)) {
			error = PTR_ERR(mp->m_rtdev_targp);
			mp->m_rtdev_targp = NULL;
			goto out_free_ddev_targ;
		}
	}

	if (logdev_file && file_bdev(logdev_file) != ddev) {
		mp->m_logdev_targp = xfs_alloc_buftarg(mp, logdev_file);
		if (IS_ERR(mp->m_logdev_targp)) {
			error = PTR_ERR(mp->m_logdev_targp);
			mp->m_logdev_targp = NULL;
			goto out_free_rtdev_targ;
		}
	} else {
		mp->m_logdev_targp = mp->m_ddev_targp;
		/* Handle won't be used, drop it */
		if (logdev_file)
			bdev_fput(logdev_file);
	}

	return 0;

 out_free_rtdev_targ:
	if (mp->m_rtdev_targp)
		xfs_free_buftarg(mp->m_rtdev_targp);
 out_free_ddev_targ:
	xfs_free_buftarg(mp->m_ddev_targp);
 out_close_rtdev:
	 if (rtdev_file)
		bdev_fput(rtdev_file);
 out_close_logdev:
	if (logdev_file)
		bdev_fput(logdev_file);
	return error;
}

/*
 * Setup xfs_mount buffer target pointers based on superblock
 */
STATIC int
xfs_setup_devices(
	struct xfs_mount	*mp)
{
	int			error;

	error = xfs_configure_buftarg(mp->m_ddev_targp, mp->m_sb.sb_sectsize,
			mp->m_sb.sb_dblocks);
	if (error)
		return error;

	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp) {
		unsigned int	log_sector_size = BBSIZE;

		if (xfs_has_sector(mp))
			log_sector_size = mp->m_sb.sb_logsectsize;
		error = xfs_configure_buftarg(mp->m_logdev_targp,
				log_sector_size, mp->m_sb.sb_logblocks);
		if (error)
			return error;
	}

	if (mp->m_sb.sb_rtstart) {
		if (mp->m_rtdev_targp) {
			xfs_warn(mp,
		"can't use internal and external rtdev at the same time");
			return -EINVAL;
		}
		mp->m_rtdev_targp = mp->m_ddev_targp;
	} else if (mp->m_rtname) {
		error = xfs_configure_buftarg(mp->m_rtdev_targp,
				mp->m_sb.sb_sectsize, mp->m_sb.sb_rblocks);
		if (error)
			return error;
	}

	return 0;
}

STATIC int
xfs_init_mount_workqueues(
	struct xfs_mount	*mp)
{
	mp->m_buf_workqueue = alloc_workqueue("xfs-buf/%s",
			XFS_WQFLAGS(WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_PERCPU),
			1, mp->m_super->s_id);
	if (!mp->m_buf_workqueue)
		goto out;

	mp->m_unwritten_workqueue = alloc_workqueue("xfs-conv/%s",
			XFS_WQFLAGS(WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_PERCPU),
			0, mp->m_super->s_id);
	if (!mp->m_unwritten_workqueue)
		goto out_destroy_buf;

	mp->m_reclaim_workqueue = alloc_workqueue("xfs-reclaim/%s",
			XFS_WQFLAGS(WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_PERCPU),
			0, mp->m_super->s_id);
	if (!mp->m_reclaim_workqueue)
		goto out_destroy_unwritten;

	mp->m_blockgc_wq = alloc_workqueue("xfs-blockgc/%s",
			XFS_WQFLAGS(WQ_UNBOUND | WQ_FREEZABLE | WQ_MEM_RECLAIM),
			0, mp->m_super->s_id);
	if (!mp->m_blockgc_wq)
		goto out_destroy_reclaim;

	mp->m_inodegc_wq = alloc_workqueue("xfs-inodegc/%s",
			XFS_WQFLAGS(WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_PERCPU),
			1, mp->m_super->s_id);
	if (!mp->m_inodegc_wq)
		goto out_destroy_blockgc;

	mp->m_sync_workqueue = alloc_workqueue("xfs-sync/%s",
			XFS_WQFLAGS(WQ_FREEZABLE | WQ_PERCPU), 0,
			mp->m_super->s_id);
	if (!mp->m_sync_workqueue)
		goto out_destroy_inodegc;

	/*
	 * v0.3.147 sess33: ordered workqueue for AG BAST work fns.  See
	 * struct xfs_mount comment.  WQ_MEM_RECLAIM because writeback
	 * reclaim paths can block on AG-DLM acquire which depends on
	 * peer's bast_work_fn completing.
	 */
	mp->m_mxfs_ag_bast_wq = alloc_ordered_workqueue("mxfs-ag-bast/%s",
			WQ_MEM_RECLAIM, mp->m_super->s_id);
	if (!mp->m_mxfs_ag_bast_wq)
		goto out_destroy_sync;

	/*
	 * sess116 (ccloop 4eef1f39): dedicated workqueue for INODE BAST work
	 * fns so xfs_fs_put_super can flush them before the log is torn down
	 * (see m_mxfs_inode_bast_wq comment in xfs_mount.h).  UNBOUND for the
	 * same per-inode concurrency the old system_wq provided (multiple
	 * inode demotes run in parallel); WQ_MEM_RECLAIM because the bast
	 * flush/drain path can be reached from reclaim.
	 */
	/*
	 * sess3 (ccloop 26c41354): bound concurrency to avoid block-layer
	 * request-tag exhaustion when a hot-inode BAST storm queues hundreds of
	 * no-inode releases (each does a synchronous FUA read).  mxfs_bast_wq_max_active
	 * default 0 = kernel default (old unbounded ~512); a small positive cap
	 * (e.g. 16) keeps concurrent bast FUA reads under the device tag depth.
	 * See the param comment in xfs_mxfs_dlm.c.
	 */
	{
		extern int mxfs_bast_wq_max_active;
		mp->m_mxfs_inode_bast_wq = alloc_workqueue("mxfs-ino-bast/%s",
				WQ_UNBOUND | WQ_MEM_RECLAIM,
				mxfs_bast_wq_max_active, mp->m_super->s_id);
	}
	if (!mp->m_mxfs_inode_bast_wq)
		goto out_destroy_ag_bast;

	/* v0.10.38: dir-EX-BAST idle-PR sweep (runs on the inode-bast wq). */
	INIT_WORK(&mp->m_mxfs_pr_sweep_work, mxfs_dlm_pr_sweep_work_fn);
	mp->m_mxfs_pr_sweep_last = 0;

	/* sess37: bast-arm gate (D-DWORK-TEARDOWN-LASTREF-LEAK class fix). */
	spin_lock_init(&mp->m_mxfs_arm_lock);
	mp->m_mxfs_arms_off = false;

	/* sess18: release-side device-flush coalescing state. */
	atomic64_set(&mp->m_mxfs_flush_req, 0);
	atomic64_set(&mp->m_mxfs_flush_done, 0);
	mutex_init(&mp->m_mxfs_flush_lock);

	/* sess43 deferred-publish: per-node unpublished-inode list. */
	INIT_LIST_HEAD(&mp->m_mxfs_unpub_list);
	atomic_set(&mp->m_mxfs_pubdrain_active, 0);
	spin_lock_init(&mp->m_mxfs_unpub_lock);
	/* v0.5.4 sess24: background dir-slot publisher (runs on
	 * m_mxfs_inode_bast_wq; flushed with it at put_super). */
	INIT_WORK(&mp->m_mxfs_publish_work, mxfs_dlm_publish_dirs_work);
	/* ccloop c7ee71c6 sess2: coalesced destage kick (see xfs_mount.h). */
	{
		extern void mxfs_destage_kick_fn(struct work_struct *);
		INIT_DELAYED_WORK(&mp->m_mxfs_destage_kick,
				  mxfs_destage_kick_fn);
	}

	return 0;

out_destroy_ag_bast:
	destroy_workqueue(mp->m_mxfs_ag_bast_wq);
out_destroy_sync:
	destroy_workqueue(mp->m_sync_workqueue);

out_destroy_inodegc:
	destroy_workqueue(mp->m_inodegc_wq);
out_destroy_blockgc:
	destroy_workqueue(mp->m_blockgc_wq);
out_destroy_reclaim:
	destroy_workqueue(mp->m_reclaim_workqueue);
out_destroy_unwritten:
	destroy_workqueue(mp->m_unwritten_workqueue);
out_destroy_buf:
	destroy_workqueue(mp->m_buf_workqueue);
out:
	return -ENOMEM;
}

STATIC void
xfs_destroy_mount_workqueues(
	struct xfs_mount	*mp)
{
	/* sess5: publish drain workers that outlived their bounded wait run
	 * detached on system_unbound_wq and still dereference mp — wait them
	 * out (bounded: their claims fail fast once the DLM is down). */
	{
		int pd_laps = 0;

		while (atomic_read(&mp->m_mxfs_pubdrain_active) > 0 &&
		       pd_laps++ < 3000)
			msleep(10);
		if (atomic_read(&mp->m_mxfs_pubdrain_active) > 0)
			pr_warn("mxfs: P-PUBDRAIN-TEARDOWN-TIMEOUT active=%d after 30s — proceeding\n",
				atomic_read(&mp->m_mxfs_pubdrain_active));
	}
	if (mp->m_mxfs_inode_bast_wq)
		destroy_workqueue(mp->m_mxfs_inode_bast_wq);
	if (mp->m_mxfs_ag_bast_wq)
		destroy_workqueue(mp->m_mxfs_ag_bast_wq);
	destroy_workqueue(mp->m_sync_workqueue);
	destroy_workqueue(mp->m_blockgc_wq);
	destroy_workqueue(mp->m_inodegc_wq);
	destroy_workqueue(mp->m_reclaim_workqueue);
	destroy_workqueue(mp->m_unwritten_workqueue);
	destroy_workqueue(mp->m_buf_workqueue);
}

static void
xfs_flush_inodes_worker(
	struct work_struct	*work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_flush_inodes_work);
	struct super_block	*sb = mp->m_super;

	if (down_read_trylock(&sb->s_umount)) {
		sync_inodes_sb(sb);
		up_read(&sb->s_umount);
	}
}

/*
 * Flush all dirty data to disk. Must not be called while holding an XFS_ILOCK
 * or a page lock. We use sync_inodes_sb() here to ensure we block while waiting
 * for IO to complete so that we effectively throttle multiple callers to the
 * rate at which IO is completing.
 */
void
xfs_flush_inodes(
	struct xfs_mount	*mp)
{
	/*
	 * If flush_work() returns true then that means we waited for a flush
	 * which was already in progress.  Don't bother running another scan.
	 */
	if (flush_work(&mp->m_flush_inodes_work))
		return;

	queue_work(mp->m_sync_workqueue, &mp->m_flush_inodes_work);
	flush_work(&mp->m_flush_inodes_work);
}

/* Catch misguided souls that try to use this interface on XFS */
STATIC struct inode *
xfs_fs_alloc_inode(
	struct super_block	*sb)
{
	BUG();
	return NULL;
}

/*
 * Now that the generic code is guaranteed not to be accessing
 * the linux inode, we can inactivate and reclaim the inode.
 */
STATIC void
xfs_fs_destroy_inode(
	struct inode		*inode)
{
	struct xfs_inode	*ip = XFS_I(inode);

	trace_xfs_destroy_inode(ip);

	ASSERT(!rwsem_is_locked(&inode->i_rwsem));
	XFS_STATS_INC(ip->i_mount, vn_rele);
	XFS_STATS_INC(ip->i_mount, vn_remove);
	/*
	 * sess5 shadow ledger: __destroy_inode (which just ran) DECS
	 * s_remove_count for i_nlink==0 — verify the zero was accounted,
	 * and clear the flag so a later recycle's re-inc is expected.
	 */
	if (inode->i_nlink == 0) {
		if (!xfs_iflags_test(ip, MXFS_IF_RMC_ACCT)) {
			static atomic_t p9dst_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p9dst_n) <= 50) {
				pr_alert("mxfs: P9-RMC-UNPAIRED-DESTROY ino=%llu rmcnt=%ld last0=%pS lastclr=%pS comm=%s — destroy-at-0 dec with UNACCOUNTED zero\n",
					(unsigned long long)ip->i_ino,
					atomic_long_read(&inode->i_sb->s_remove_count),
					ip->i_rmc_last0_ra,
					ip->i_rmc_lastclr_ra,
					current->comm);
				dump_stack();
			}
		}
		xfs_iflags_clear(ip, MXFS_IF_RMC_ACCT);
		ip->i_rmc_lastclr_ra = __builtin_return_address(0);
	}
	xfs_inode_mark_reclaimable(ip);
}

/*
 * Slab object creation initialisation for the XFS inode.
 * This covers only the idempotent fields in the XFS inode;
 * all other fields need to be initialised on allocation
 * from the slab. This avoids the need to repeatedly initialise
 * fields in the xfs inode that left in the initialise state
 * when freeing the inode.
 */
STATIC void
xfs_fs_inode_init_once(
	void			*inode)
{
	struct xfs_inode	*ip = inode;

	memset(ip, 0, sizeof(struct xfs_inode));

	/* vfs inode */
	inode_init_once(VFS_I(ip));

	/* xfs inode */
	atomic_set(&ip->i_pincount, 0);
	spin_lock_init(&ip->i_flags_lock);
	init_rwsem(&ip->i_lock);
}

/*
 * We do an unlocked check for XFS_IDONTCACHE here because we are already
 * serialised against cache hits here via the inode->i_lock and igrab() in
 * xfs_iget_cache_hit(). Hence a lookup that might clear this flag will not be
 * racing with us, and it avoids needing to grab a spinlock here for every inode
 * we drop the final reference on.
 */
STATIC int
xfs_fs_drop_inode(
	struct inode		*inode)
{
	struct xfs_inode	*ip = XFS_I(inode);

	/*
	 * If this unlinked inode is in the middle of recovery, don't
	 * drop the inode just yet; log recovery will take care of
	 * that.  See the comment for this inode flag.
	 */
	if (ip->i_flags & XFS_IRECOVERY) {
		ASSERT(xlog_recovery_needed(ip->i_mount->m_log));
		return 0;
	}

	/*
	 * ccloop c7ee71c6 sess27 (D-UNMOUNT-BUSY-INODES).  This callback runs
	 * from iput_final(), i.e. AT the i_count->0 transition — the one place a
	 * filesystem can observe it.  Open a fresh grab-attribution tenure here
	 * so the table reported at unmount contains ONLY the grabs that built
	 * the surviving reference.  See the field comments in xfs_inode.h.
	 */
	mxfs_inode_tenure_reset(ip);

	return inode_generic_drop(inode);
}

STATIC void
xfs_fs_evict_inode(
	struct inode		*inode)
{
	if (IS_DAX(inode))
		dax_break_layout_final(inode);

	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	if (IS_ENABLED(CONFIG_XFS_RT) &&
	    S_ISREG(inode->i_mode) && inode->i_private) {
		xfs_open_zone_put(inode->i_private);
		inode->i_private = NULL;
	}
}

static void
xfs_mount_free(
	struct xfs_mount	*mp)
{
	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp)
		xfs_free_buftarg(mp->m_logdev_targp);
	if (mp->m_rtdev_targp && mp->m_rtdev_targp != mp->m_ddev_targp)
		xfs_free_buftarg(mp->m_rtdev_targp);
	if (mp->m_ddev_targp)
		xfs_free_buftarg(mp->m_ddev_targp);

	debugfs_remove(mp->m_debugfs);
	kfree(mp->m_rtname);
	kfree(mp->m_logname);
#ifdef DEBUG
	kfree(mp->m_errortag);
#endif
	kfree(mp);
}

STATIC int
xfs_fs_sync_fs(
	struct super_block	*sb,
	int			wait)
{
	struct xfs_mount	*mp = XFS_M(sb);
	int			error;

	trace_xfs_fs_sync_fs(mp, __return_address);

	/*
	 * Doing anything during the async pass would be counterproductive.
	 */
	if (!wait)
		return 0;

	error = xfs_log_force(mp, XFS_LOG_SYNC);
	if (error)
		return error;

	/*
	 * MXFS cross-node coherence (sess39): a peer reads our metadata from
	 * the on-disk inode/dir CLUSTERS via FUA, NOT from our log.  Plain
	 * xfs_log_force only commits dirty di_size/dirents to the LOG; the
	 * on-disk inode cluster still holds the old value (the iflush is done
	 * lazily by xfsaild) and the device write cache hasn't reached the
	 * backing store.  So after a writer's sync(2), a peer that FUA-reads
	 * the inode cluster still sees di_size=0 -> the file appears EMPTY
	 * (the dominant cross-node empty-content failure in cache_coherency /
	 * rename_visibility, confirmed: peer stat size=0).  POSIX sync should
	 * make our writes durable AND, in a cluster, visible to peers.  Push
	 * the AIL to write all dirty metadata into its cluster blocks, then
	 * flush the device write cache to the platter.  ONE AIL push + ONE
	 * flush per sync() (NOT per DLM release — per-release flushing added
	 * latency that widened other races and made things worse, sess39).
	 * Multi-node only; single-node keeps the cheap upstream behavior.
	 */
	{ extern int mxfs_sync_iflush; if (mxfs_sync_iflush &&
	    mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		/*
		 * sess39: the AIL push is REQUIRED for correctness — A/B proved
		 * it: with xfs_ail_push_all_sync the cross-node empty-content
		 * drops to ~5 fails/240; with blkdev_issue_flush ALONE it is ~46
		 * (di_size stays in the AIL, never reaches the cluster a peer
		 * FUA-reads).  So the iflush is the lever, not the flush.  Caveat:
		 * the WHOLE-AIL sync push is too slow under sustained 4-node
		 * contention (test wall 148s, sometimes >200s timeout) — the next
		 * step is a TARGETED iflush of only the inodes dirtied since the
		 * last sync (or a bounded per-AG push), not xfs_ail_push_all_sync.
		 */
		/*
		 * sess39: a SECOND log_force+ail_push pass here (to catch the
		 * async CIL->AIL insert race for the residual ~3 empty-content)
		 * was tested and made things WORSE (14 fails, cluster degraded) —
		 * the extra AIL contention widens the race (consistent with the
		 * opposite-latency-sensitivity finding).  Single pass only.
		 */
		/*
		 * sess39: PER-AG push (not whole-AIL).  The whole-AIL
		 * xfs_ail_push_all_sync[_bounded] WEDGES under the unlink test via
		 * the documented cross-AG xfsaild deadlock.  Push only THIS node's
		 * preferred AG (slot % agcount) — where its dirty FILE inodes live,
		 * so it iflushes their di_size for cross-node visibility — which
		 * the node already holds, avoiding the cross-AG lock cycle.  Gated
		 * off by default (mxfs_sync_iflush) pending validation that this
		 * does NOT wedge the full cache_coherency criterion.
		 */
		{
			int slot = mxfs_v5_dlm_get_node_slot(mp->m_mxfs_dlm);
			xfs_agnumber_t pref = 0;

			if (slot >= 0 && mp->m_sb.sb_agcount > 0)
				pref = (xfs_agnumber_t)slot % mp->m_sb.sb_agcount;
			/*
			 * sess40: BOUNDED per-AG push.  The unbounded wrapper
			 * (xfs_ail_push_ag_sync) loops until this AG drains; if
			 * our own AG's inode items are momentarily pinned by a
			 * peer grant, that wedges the sync(2) caller.  Use the
			 * bounded variant with a stall-abort: min_iters=10
			 * (~100ms warmup so xfsaild gets to iflush our dirty
			 * di_size into the cluster), stall_iters=30 (~300ms of
			 * no forward progress -> give up rather than wedge).
			 * Normal case (a node's ~20 dirty inodes) drains in a
			 * handful of iters; the cap only bites under contention.
			 */
			(void)xfs_ail_push_ag_sync_bounded(mp->m_ail, pref,
							   30, 10);
		}
		blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	} }

	/*
	 * If we are called with page faults frozen out, it means we are about
	 * to freeze the transaction subsystem. Take the opportunity to shut
	 * down inodegc because once SB_FREEZE_FS is set it's too late to
	 * prevent inactivation races with freeze. The fs doesn't get called
	 * again by the freezing process until after SB_FREEZE_FS has been set,
	 * so it's now or never.  Same logic applies to speculative allocation
	 * garbage collection.
	 *
	 * We don't care if this is a normal syncfs call that does this or
	 * freeze that does this - we can run this multiple times without issue
	 * and we won't race with a restart because a restart can only occur
	 * when the state is either SB_FREEZE_FS or SB_FREEZE_COMPLETE.
	 */
	if (sb->s_writers.frozen == SB_FREEZE_PAGEFAULT) {
		xfs_inodegc_stop(mp);
		xfs_blockgc_stop(mp);
		xfs_zone_gc_stop(mp);
	}

	return 0;
}

static xfs_extlen_t
xfs_internal_log_size(
	struct xfs_mount	*mp)
{
	if (!mp->m_sb.sb_logstart)
		return 0;
	return mp->m_sb.sb_logblocks;
}

static void
xfs_statfs_data(
	struct xfs_mount	*mp,
	struct kstatfs		*st)
{
	int64_t			fdblocks =
		xfs_sum_freecounter(mp, XC_FREE_BLOCKS);
	uint64_t		pa_ic, pa_if, pa_fdb;

	/* sess39 D-STATFS fix: on multi-node mounts the percpu counter above
	 * drifts (local-only deltas); report the cluster-coherent physical
	 * per-AG sum instead.  Residual: omits foreign in-flight delalloc
	 * (seconds-scale), vs unbounded monotonic drift. */
	if (mxfs_statfs_perag_sums(mp, &pa_ic, &pa_if, &pa_fdb))
		fdblocks = pa_fdb;

	/* make sure st->f_bfree does not underflow */
	st->f_bfree = max(0LL,
		fdblocks - xfs_freecounter_unavailable(mp, XC_FREE_BLOCKS));

	/*
	 * sb_dblocks can change during growfs, but nothing cares about reporting
	 * the old or new value during growfs.
	 */
	st->f_blocks = mp->m_sb.sb_dblocks - xfs_internal_log_size(mp);
}

/*
 * When stat(v)fs is called on a file with the realtime bit set or a directory
 * with the rtinherit bit, report freespace information for the RT device
 * instead of the main data device.
 */
static void
xfs_statfs_rt(
	struct xfs_mount	*mp,
	struct kstatfs		*st)
{
	st->f_bfree = xfs_rtbxlen_to_blen(mp,
			xfs_sum_freecounter(mp, XC_FREE_RTEXTENTS));
	st->f_blocks = mp->m_sb.sb_rblocks - xfs_rtbxlen_to_blen(mp,
			mp->m_free[XC_FREE_RTEXTENTS].res_total);
}

static void
xfs_statfs_inodes(
	struct xfs_mount	*mp,
	struct kstatfs		*st)
{
	uint64_t		icount = percpu_counter_sum(&mp->m_icount);
	uint64_t		ifree = percpu_counter_sum(&mp->m_ifree);
	uint64_t		fakeinos;
	uint64_t		pa_ic, pa_if, pa_fdb;

	/* sess39 D-STATFS fix (see xfs_statfs_data): cluster-coherent per-AG
	 * inode sums on multi-node mounts; the percpu counters drift under
	 * cross-node create/free asymmetry (measured: ifree > icount). */
	if (mxfs_statfs_perag_sums(mp, &pa_ic, &pa_if, &pa_fdb)) {
		icount = pa_ic;
		ifree = pa_if;
	}
	fakeinos = XFS_FSB_TO_INO(mp, st->f_bfree);

	st->f_files = min(icount + fakeinos, (uint64_t)XFS_MAXINUMBER);
	if (M_IGEO(mp)->maxicount)
		st->f_files = min_t(typeof(st->f_files), st->f_files,
					M_IGEO(mp)->maxicount);

	/* If sb_icount overshot maxicount, report actual allocation */
	st->f_files = max_t(typeof(st->f_files), st->f_files,
			mp->m_sb.sb_icount);

	/* Make sure st->f_ffree does not underflow */
	st->f_ffree = max_t(int64_t, 0, st->f_files - (icount - ifree));
}

STATIC int
xfs_fs_statfs(
	struct dentry		*dentry,
	struct kstatfs		*st)
{
	struct xfs_mount	*mp = XFS_M(dentry->d_sb);
	struct xfs_inode	*ip = XFS_I(d_inode(dentry));

	/*
	 * Expedite background inodegc but don't wait. We do not want to block
	 * here waiting hours for a billion extent file to be truncated.
	 */
	xfs_inodegc_push(mp);

	st->f_type = XFS_SUPER_MAGIC;
	st->f_namelen = MAXNAMELEN - 1;
	st->f_bsize = mp->m_sb.sb_blocksize;
	st->f_fsid = u64_to_fsid(huge_encode_dev(mp->m_ddev_targp->bt_dev));

	xfs_statfs_data(mp, st);
	xfs_statfs_inodes(mp, st);

	if (XFS_IS_REALTIME_MOUNT(mp) &&
	    (ip->i_diflags & (XFS_DIFLAG_RTINHERIT | XFS_DIFLAG_REALTIME)))
		xfs_statfs_rt(mp, st);

	if ((ip->i_diflags & XFS_DIFLAG_PROJINHERIT) &&
	    ((mp->m_qflags & (XFS_PQUOTA_ACCT|XFS_PQUOTA_ENFD))) ==
			      (XFS_PQUOTA_ACCT|XFS_PQUOTA_ENFD))
		xfs_qm_statvfs(ip, st);

	/*
	 * XFS does not distinguish between blocks available to privileged and
	 * unprivileged users.
	 */
	st->f_bavail = st->f_bfree;
	return 0;
}

STATIC void
xfs_save_resvblks(
	struct xfs_mount	*mp)
{
	enum xfs_free_counter	i;

	for (i = 0; i < XC_FREE_NR; i++) {
		mp->m_free[i].res_saved = mp->m_free[i].res_total;
		xfs_reserve_blocks(mp, i, 0);
	}
}

STATIC void
xfs_restore_resvblks(
	struct xfs_mount	*mp)
{
	uint64_t		resblks;
	enum xfs_free_counter	i;

	for (i = 0; i < XC_FREE_NR; i++) {
		if (mp->m_free[i].res_saved) {
			resblks = mp->m_free[i].res_saved;
			mp->m_free[i].res_saved = 0;
		} else
			resblks = xfs_default_resblks(mp, i);
		xfs_reserve_blocks(mp, i, resblks);
	}
}

/*
 * Second stage of a freeze. The data is already frozen so we only
 * need to take care of the metadata. Once that's done sync the superblock
 * to the log to dirty it in case of a crash while frozen. This ensures that we
 * will recover the unlinked inode lists on the next mount.
 */
STATIC int
xfs_fs_freeze(
	struct super_block	*sb)
{
	struct xfs_mount	*mp = XFS_M(sb);
	unsigned int		flags;
	int			ret;

	/*
	 * The filesystem is now frozen far enough that memory reclaim
	 * cannot safely operate on the filesystem. Hence we need to
	 * set a GFP_NOFS context here to avoid recursion deadlocks.
	 */
	flags = memalloc_nofs_save();
	xfs_save_resvblks(mp);
	ret = xfs_log_quiesce(mp);
	memalloc_nofs_restore(flags);

	/*
	 * For read-write filesystems, we need to restart the inodegc on error
	 * because we stopped it at SB_FREEZE_PAGEFAULT level and a thaw is not
	 * going to be run to restart it now.  We are at SB_FREEZE_FS level
	 * here, so we can restart safely without racing with a stop in
	 * xfs_fs_sync_fs().
	 */
	if (ret && !xfs_is_readonly(mp)) {
		xfs_blockgc_start(mp);
		xfs_inodegc_start(mp);
		xfs_zone_gc_start(mp);
	}

	return ret;
}

STATIC int
xfs_fs_unfreeze(
	struct super_block	*sb)
{
	struct xfs_mount	*mp = XFS_M(sb);

	xfs_restore_resvblks(mp);
	xfs_log_work_queue(mp);

	/*
	 * Don't reactivate the inodegc worker on a readonly filesystem because
	 * inodes are sent directly to reclaim.  Don't reactivate the blockgc
	 * worker because there are no speculative preallocations on a readonly
	 * filesystem.
	 */
	if (!xfs_is_readonly(mp)) {
		xfs_zone_gc_start(mp);
		xfs_blockgc_start(mp);
		xfs_inodegc_start(mp);
	}

	return 0;
}

/*
 * This function fills in xfs_mount_t fields based on mount args.
 * Note: the superblock _has_ now been read in.
 */
STATIC int
xfs_finish_flags(
	struct xfs_mount	*mp)
{
	/* Fail a mount where the logbuf is smaller than the log stripe */
	if (xfs_has_logv2(mp)) {
		if (mp->m_logbsize <= 0 &&
		    mp->m_sb.sb_logsunit > XLOG_BIG_RECORD_BSIZE) {
			mp->m_logbsize = mp->m_sb.sb_logsunit;
		} else if (mp->m_logbsize > 0 &&
			   mp->m_logbsize < mp->m_sb.sb_logsunit) {
			xfs_warn(mp,
		"logbuf size must be greater than or equal to log stripe size");
			return -EINVAL;
		}
	} else {
		/* Fail a mount if the logbuf is larger than 32K */
		if (mp->m_logbsize > XLOG_BIG_RECORD_BSIZE) {
			xfs_warn(mp,
		"logbuf size for version 1 logs must be 16K or 32K");
			return -EINVAL;
		}
	}

	/*
	 * prohibit r/w mounts of read-only filesystems
	 */
	if ((mp->m_sb.sb_flags & XFS_SBF_READONLY) && !xfs_is_readonly(mp)) {
		xfs_warn(mp,
			"cannot mount a read-only filesystem as read-write");
		return -EROFS;
	}

	if ((mp->m_qflags & XFS_GQUOTA_ACCT) &&
	    (mp->m_qflags & XFS_PQUOTA_ACCT) &&
	    !xfs_has_pquotino(mp)) {
		xfs_warn(mp,
		  "Super block does not support project and group quota together");
		return -EINVAL;
	}

	if (!xfs_has_zoned(mp)) {
		if (mp->m_max_open_zones) {
			xfs_warn(mp,
"max_open_zones mount option only supported on zoned file systems.");
			return -EINVAL;
		}
		if (mp->m_features & XFS_FEAT_NOLIFETIME) {
			xfs_warn(mp,
"nolifetime mount option only supported on zoned file systems.");
			return -EINVAL;
		}
	}

	return 0;
}

static int
xfs_init_percpu_counters(
	struct xfs_mount	*mp)
{
	int			error;
	int			i;

	error = percpu_counter_init(&mp->m_icount, 0, GFP_KERNEL);
	if (error)
		return -ENOMEM;

	error = percpu_counter_init(&mp->m_ifree, 0, GFP_KERNEL);
	if (error)
		goto free_icount;

	error = percpu_counter_init(&mp->m_delalloc_blks, 0, GFP_KERNEL);
	if (error)
		goto free_ifree;

	error = percpu_counter_init(&mp->m_delalloc_rtextents, 0, GFP_KERNEL);
	if (error)
		goto free_delalloc;

	for (i = 0; i < XC_FREE_NR; i++) {
		error = percpu_counter_init(&mp->m_free[i].count, 0,
				GFP_KERNEL);
		if (error)
			goto free_freecounters;
	}

	return 0;

free_freecounters:
	while (--i >= 0)
		percpu_counter_destroy(&mp->m_free[i].count);
	percpu_counter_destroy(&mp->m_delalloc_rtextents);
free_delalloc:
	percpu_counter_destroy(&mp->m_delalloc_blks);
free_ifree:
	percpu_counter_destroy(&mp->m_ifree);
free_icount:
	percpu_counter_destroy(&mp->m_icount);
	return -ENOMEM;
}

void
xfs_reinit_percpu_counters(
	struct xfs_mount	*mp)
{
	percpu_counter_set(&mp->m_icount, mp->m_sb.sb_icount);
	percpu_counter_set(&mp->m_ifree, mp->m_sb.sb_ifree);
	xfs_set_freecounter(mp, XC_FREE_BLOCKS, mp->m_sb.sb_fdblocks);
	if (!xfs_has_zoned(mp))
		xfs_set_freecounter(mp, XC_FREE_RTEXTENTS,
				mp->m_sb.sb_frextents);
}

static void
xfs_destroy_percpu_counters(
	struct xfs_mount	*mp)
{
	enum xfs_free_counter	i;

	for (i = 0; i < XC_FREE_NR; i++)
		percpu_counter_destroy(&mp->m_free[i].count);
	percpu_counter_destroy(&mp->m_icount);
	percpu_counter_destroy(&mp->m_ifree);
	ASSERT(xfs_is_shutdown(mp) ||
	       percpu_counter_sum(&mp->m_delalloc_rtextents) == 0);
	percpu_counter_destroy(&mp->m_delalloc_rtextents);
	ASSERT(xfs_is_shutdown(mp) ||
	       percpu_counter_sum(&mp->m_delalloc_blks) == 0);
	percpu_counter_destroy(&mp->m_delalloc_blks);
}

static int
xfs_inodegc_init_percpu(
	struct xfs_mount	*mp)
{
	struct xfs_inodegc	*gc;
	int			cpu;

	mp->m_inodegc = alloc_percpu(struct xfs_inodegc);
	if (!mp->m_inodegc)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		gc = per_cpu_ptr(mp->m_inodegc, cpu);
		gc->cpu = cpu;
		gc->mp = mp;
		init_llist_head(&gc->list);
		gc->items = 0;
		gc->error = 0;
		INIT_DELAYED_WORK(&gc->work, xfs_inodegc_worker);
	}
	return 0;
}

static void
xfs_inodegc_free_percpu(
	struct xfs_mount	*mp)
{
	if (!mp->m_inodegc)
		return;
	free_percpu(mp->m_inodegc);
}

static void
xfs_fs_put_super(
	struct super_block	*sb)
{
	struct xfs_mount	*mp = XFS_M(sb);
	uint64_t		pr_late_key = 0;

	xfs_notice(mp, "Unmounting Filesystem %pU", &mp->m_sb.sb_uuid);

	/* sess39: retire this mount from the write-triggered diagnostics. */
	if (READ_ONCE(mxfs_dbg_mp) == mp)
		WRITE_ONCE(mxfs_dbg_mp, NULL);

	/*
	 * sess116 (ccloop 4eef1f39): drain in-flight INODE bast work BEFORE
	 * anything is torn down.  Each pending mxfs_dlm_bast_work_fn holds an
	 * inode reference and calls xfs_log_force(); if left pending it both
	 * (a) keeps its inode "busy" so xfs_unmountfs reclaim skips it (and
	 * never cancels the work), and (b) eventually runs after xfs_unmountfs
	 * has freed mp->m_log, NULL-derefing in xfs_log_force (CR2=0x10, wedging
	 * the module at refcount -1).  Flushing here runs them while m_log and
	 * the DLM are still valid, releasing the refs so reclaim can complete.
	 */
	/*
	 * sess37 D-DWORK-TEARDOWN-LASTREF-LEAK class fix.  Close the
	 * bast-arm gate FIRST: every per-inode bast work/dwork arm routes
	 * through mxfs_bast_arm_queue*() (xfs_mxfs_dlm.c), which refuses
	 * once m_mxfs_arms_off is set — the caller then drops the arm's
	 * igrab ref via its existing queued-false path.  Arms landing
	 * after the flush below would otherwise re-open the sess116
	 * window.
	 */
	spin_lock(&mp->m_mxfs_arm_lock);
	mp->m_mxfs_arms_off = true;
	spin_unlock(&mp->m_mxfs_arm_lock);

	if (mp->m_mxfs_inode_bast_wq) {
		/* v0.10.38: the sweep re-queues per-inode dworks — settle it
		 * before flushing so nothing re-arms after the flush. */
		cancel_work_sync(&mp->m_mxfs_pr_sweep_work);
		flush_workqueue(mp->m_mxfs_inode_bast_wq);
	}

	/*
	 * sess37 part 2: break last-ref circulars the flush cannot see.
	 * A delayed work still on its 4ms TIMER is not in the workqueue,
	 * so flush_workqueue ignores it; when its igrab ref is the
	 * inode's LAST ref, the eviction whose P204 cancel would disarm
	 * it can never run.  The timer then fires after xfs_free_perag,
	 * the pag ident check fails, and the P142 last-ref guard leaks
	 * the inode (captured live sess36: ino 31457413, P6G src=10 ->
	 * P142-DWORK-STALE pag=NULL -> P142-DWORK-LASTREF -> P202 at
	 * unload).  Sweep the surviving s_inodes (evict_inodes already
	 * ran — anything left is busy, i.e. exactly this class), sync-
	 * cancel each armed bast work/dwork OUTSIDE all spinlocks, and
	 * drop the ref each canceled arm owned; the inode becomes
	 * evictable and normal reclaim handles it while pag and DLM are
	 * still alive.  Gate closed => nothing can re-arm, so every
	 * processed inode stays clear and the restart scan terminates.
	 */
	if (mp->m_mxfs_inode_bast_wq) {
		struct inode	*vinode;
		int		p6s_cancels = 0, p6s_refs = 0;

restart_armsweep:
		spin_lock(&sb->s_inode_list_lock);
		list_for_each_entry(vinode, &sb->s_inodes, i_sb_list) {
			struct xfs_inode *sip = XFS_I(vinode);
			bool c_w, c_d;
			int n;

			if (!work_pending(&sip->i_dlm_bast_work) &&
			    !delayed_work_pending(&sip->i_dlm_bast_dwork))
				continue;
			if (!igrab(vinode))
				continue;  /* evicting — its own cancel runs */
			spin_unlock(&sb->s_inode_list_lock);

			c_w = cancel_work_sync(&sip->i_dlm_bast_work);
			c_d = cancel_delayed_work_sync(&sip->i_dlm_bast_dwork);
			n = (c_w ? 1 : 0) + (c_d ? 1 : 0);
			p6s_cancels += n;
			/* One arm == one igrab (every site's contract).
			 * cnt must cover the arm ref(s) PLUS our pin. */
			while (n--) {
				int cnt = atomic_read(&vinode->i_count);

				if (cnt < 2 ||
				    (vinode->i_state & (I_FREEING | I_CLEAR))) {
					pr_warn("mxfs: P6S-SWEEP-BADREF ino=%llu i_count=%d i_state=0x%lx — NOT releasing\n",
						(unsigned long long)sip->i_ino,
						cnt, vinode->i_state);
					break;
				}
				xfs_irele(sip);
				p6s_refs++;
			}
			iput(vinode);
			goto restart_armsweep;
		}
		spin_unlock(&sb->s_inode_list_lock);
		if (p6s_cancels || p6s_refs)
			pr_warn("mxfs: P6S-ARMSWEEP cancels=%d arm_refs_dropped=%d — teardown bast-arm sweep engaged\n",
				p6s_cancels, p6s_refs);
	}

	/* Shut down MXFS DLM before XFS unmount */
	if (mp->m_mxfs_dlm) {
		void *v5dlm = mp->m_mxfs_dlm;

		/* ICLUSTER (ccloop 72513a13 sess3): drop this mount's
		 * cluster-lock objects.  Must run while inodes are already
		 * evicted (refs all zero) and BEFORE the v5 ctx goes away;
		 * held disk grants are swept by caw release_all inside
		 * v5_shutdown.  Stale objects surviving into a later mount
		 * at the same mp address would false-hit the (mp,base)
		 * hash with a stale disk_mode — this call is load-bearing
		 * once mxfs.icluster_dlm=1. */
		mxfs_iclus_purge_all(mp);
		mxfs_dlm_ag_force_release_all(mp);
		/*
		 * sess171: retire the selftest trigger BEFORE the ctx is
		 * NULLed/freed.  debugfs_remove waits out any in-flight
		 * write handler (debugfs proxy), so a mid-run selftest —
		 * which dereferences the ctx for seconds — completes and
		 * releases its grants before teardown proceeds, and no new
		 * run can arm.  m_debugfs itself is only removed in
		 * xfs_mount_free, far too late for this file.
		 */
		debugfs_remove(mp->m_mxfs_pwtest_dentry);
		mp->m_mxfs_pwtest_dentry = NULL;
		/*
		 * sess9 (ccloop a864): settle the shutdown-withdraw work
		 * BEFORE freeing the ctx.  NULL the pointer first so a
		 * withdraw queued in the window no-ops instead of using the
		 * ctx v5_shutdown is about to free.
		 */
		mp->m_mxfs_dlm = NULL;
		cancel_work_sync(&mp->m_mxfs_withdraw_work);
		mxfs_defer_reap_destroy(mp);
		/*
		 * v0.11.74: keep our PR registration alive across
		 * xfs_unmountfs.  Unregistering inside v5 shutdown fenced
		 * our OWN unmount log record on WE-RO targets whenever a
		 * peer still held the reservation (EBADE -> log-error
		 * shutdown on every clean non-holder umount, unmount record
		 * lost, dirty slice recovered on next mount).  The key is
		 * unregistered below, after the final log write.
		 */
		pr_late_key = mxfs_v5_dlm_detach_pr_key(v5dlm);
		mxfs_v5_dlm_shutdown(v5dlm);
		/*
		 * v0.5.0: drain any pending foreign-slice replay while
		 * mp->m_log is still valid.  No new replays can queue —
		 * the heartbeat thread is gone.  Work was INIT'd in
		 * mxfs_dlm_cache_init, which ran iff m_mxfs_dlm was set.
		 */
		cancel_work_sync(&mp->m_mxfs_foreign_replay_work);
		/*
		 * sess151: settle the DLM-stuck shutdown work AFTER
		 * mxfs_v5_dlm_shutdown — its emitters (the owed worker,
		 * the teardown escalate defer) are joined or channel-
		 * closed in there, so nothing re-queues behind this
		 * cancel.  A canceled escalation loses nothing: the CAW
		 * layer recorded the failure synchronously and stop()'s
		 * departure verdict already read it.
		 */
		cancel_work_sync(&mp->m_mxfs_dlm_stuck_work);
	}
	/* ccloop c7ee71c6 sess2: stop the destage kick while mp->m_log is
	 * still valid (same teardown-ordering family as foreign_replay). */
	cancel_delayed_work_sync(&mp->m_mxfs_destage_kick);

	xfs_filestream_unmount(mp);
	xfs_unmountfs(mp);

	xfs_rtmount_freesb(mp);
	xfs_freesb(mp);
	xchk_mount_stats_free(mp);
	free_percpu(mp->m_stats.xs_stats);
	xfs_inodegc_free_percpu(mp);
	xfs_destroy_percpu_counters(mp);
	xfs_destroy_mount_workqueues(mp);
	xfs_shutdown_devices(mp);

	/*
	 * Deferred PR unregister — LAST, after every device I/O this mount
	 * will ever issue.
	 *
	 * v0.11.74 moved the unregister after xfs_unmountfs so our own unmount
	 * log record could not bounce EBADE on a WE-RO target.  That was
	 * necessary but not sufficient: xfs_shutdown_devices() ends with an
	 * unconditional blkdev_issue_flush() on the data device (inherited
	 * upstream, for bdev-pagecache coherency with udev/blkid), and it ran
	 * AFTER the unregister — so every clean unmount of a PR-protected LUN
	 * ended in a FAILED Synchronize Cache:
	 *   "reservation conflict error, dev dm-1, sector 0 op 0x1:(WRITE)
	 *    flags 0x800 phys_seg 0"
	 * (D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER, sess43; measured on
	 * multiple nodes at 8/caw).  Harmless for durability — the log and its
	 * unmount record were already flushed while registered — but a failed
	 * I/O on a clean path is not acceptable output, and it poisons every
	 * health check that greps for reservation conflicts.
	 *
	 * xfs_shutdown_devices() only flushes and invalidates; it does not
	 * release the buftargs, so bt_bdev is still valid here.  Keeping the
	 * registration until after it means no MXFS-issued or XFS-issued I/O
	 * can ever be rejected by our own de-registration.
	 */
	if (pr_late_key) {
		int prret = mxfs_pal_scsi_pr_unregister_bdev(
				mp->m_ddev_targp->bt_bdev, pr_late_key);
		if (prret)
			xfs_notice(mp,
				   "MXFS: late PR unregister failed: %d",
				   prret);
	}
}

static long
xfs_fs_nr_cached_objects(
	struct super_block	*sb,
	struct shrink_control	*sc)
{
	/* Paranoia: catch incorrect calls during mount setup or teardown */
	if (WARN_ON_ONCE(!sb->s_fs_info))
		return 0;
	return xfs_reclaim_inodes_count(XFS_M(sb));
}

static long
xfs_fs_free_cached_objects(
	struct super_block	*sb,
	struct shrink_control	*sc)
{
	return xfs_reclaim_inodes_nr(XFS_M(sb), sc->nr_to_scan);
}

static void
xfs_fs_shutdown(
	struct super_block	*sb)
{
	xfs_force_shutdown(XFS_M(sb), SHUTDOWN_DEVICE_REMOVED);
}

static int
xfs_fs_show_stats(
	struct seq_file		*m,
	struct dentry		*root)
{
	struct xfs_mount	*mp = XFS_M(root->d_sb);

	if (xfs_has_zoned(mp) && IS_ENABLED(CONFIG_XFS_RT))
		xfs_zoned_show_stats(m, mp);
	return 0;
}

static void
xfs_fs_report_error(
	const struct fserror_event	*event)
{
	/* healthmon already knows about non-inode and metadata errors */
	if (event->inode && event->type != FSERR_METADATA)
		xfs_healthmon_report_file_ioerror(XFS_I(event->inode), event);
}

static const struct super_operations xfs_super_operations = {
	.alloc_inode		= xfs_fs_alloc_inode,
	.destroy_inode		= xfs_fs_destroy_inode,
	.drop_inode		= xfs_fs_drop_inode,
	.evict_inode		= xfs_fs_evict_inode,
	.put_super		= xfs_fs_put_super,
	.sync_fs		= xfs_fs_sync_fs,
	.freeze_fs		= xfs_fs_freeze,
	.unfreeze_fs		= xfs_fs_unfreeze,
	.statfs			= xfs_fs_statfs,
	.show_options		= xfs_fs_show_options,
	.nr_cached_objects	= xfs_fs_nr_cached_objects,
	.free_cached_objects	= xfs_fs_free_cached_objects,
	.shutdown		= xfs_fs_shutdown,
	.show_stats		= xfs_fs_show_stats,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	.report_error		= xfs_fs_report_error,
#endif
};

static int
suffix_kstrtoint(
	const char	*s,
	unsigned int	base,
	int		*res)
{
	int		last, shift_left_factor = 0, _res;
	char		*value;
	int		ret = 0;

	value = kstrdup(s, GFP_KERNEL);
	if (!value)
		return -ENOMEM;

	last = strlen(value) - 1;
	if (value[last] == 'K' || value[last] == 'k') {
		shift_left_factor = 10;
		value[last] = '\0';
	}
	if (value[last] == 'M' || value[last] == 'm') {
		shift_left_factor = 20;
		value[last] = '\0';
	}
	if (value[last] == 'G' || value[last] == 'g') {
		shift_left_factor = 30;
		value[last] = '\0';
	}

	if (kstrtoint(value, base, &_res))
		ret = -EINVAL;
	kfree(value);
	*res = _res << shift_left_factor;
	return ret;
}

static int
suffix_kstrtoull(
	const char		*s,
	unsigned int		base,
	unsigned long long	*res)
{
	int			last, shift_left_factor = 0;
	unsigned long long	_res;
	char			*value;
	int			ret = 0;

	value = kstrdup(s, GFP_KERNEL);
	if (!value)
		return -ENOMEM;

	last = strlen(value) - 1;
	if (value[last] == 'K' || value[last] == 'k') {
		shift_left_factor = 10;
		value[last] = '\0';
	}
	if (value[last] == 'M' || value[last] == 'm') {
		shift_left_factor = 20;
		value[last] = '\0';
	}
	if (value[last] == 'G' || value[last] == 'g') {
		shift_left_factor = 30;
		value[last] = '\0';
	}

	if (kstrtoull(value, base, &_res))
		ret = -EINVAL;
	kfree(value);
	*res = _res << shift_left_factor;
	return ret;
}

static inline void
xfs_fs_warn_deprecated(
	struct fs_context	*fc,
	struct fs_parameter	*param)
{
	/*
	 * Always warn about someone passing in a deprecated mount option.
	 * Previously we wouldn't print the warning if we were reconfiguring
	 * and current mount point already had the flag set, but that was not
	 * the right thing to do.
	 *
	 * Many distributions mount the root filesystem with no options in the
	 * initramfs and rely on mount -a to remount the root fs with the
	 * options in fstab.  However, the old behavior meant that there would
	 * never be a warning about deprecated mount options for the root fs in
	 * /etc/fstab.  On a single-fs system, that means no warning at all.
	 *
	 * Compounding this problem are distribution scripts that copy
	 * /proc/mounts to fstab, which means that we can't remove mount
	 * options unless we're 100% sure they have only ever been advertised
	 * in /proc/mounts in response to explicitly provided mount options.
	 */
	xfs_warn(fc->s_fs_info, "%s mount option is deprecated.", param->key);
}

/*
 * Set mount state from a mount option.
 *
 * NOTE: mp->m_super is NULL here!
 */
static int
xfs_fs_parse_param(
	struct fs_context	*fc,
	struct fs_parameter	*param)
{
	struct xfs_mount	*parsing_mp = fc->s_fs_info;
	struct fs_parse_result	result;
	int			size = 0;
	int			opt;

	BUILD_BUG_ON(XFS_QFLAGS_MNTOPTS & XFS_MOUNT_QUOTA_ALL);

	opt = fs_parse(fc, xfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Op_deprecated:
		xfs_fs_warn_deprecated(fc, param);
		return 0;
	case Opt_logbufs:
		parsing_mp->m_logbufs = result.uint_32;
		return 0;
	case Opt_logbsize:
		if (suffix_kstrtoint(param->string, 10, &parsing_mp->m_logbsize))
			return -EINVAL;
		return 0;
	case Opt_logdev:
		kfree(parsing_mp->m_logname);
		parsing_mp->m_logname = kstrdup(param->string, GFP_KERNEL);
		if (!parsing_mp->m_logname)
			return -ENOMEM;
		return 0;
	case Opt_rtdev:
		kfree(parsing_mp->m_rtname);
		parsing_mp->m_rtname = kstrdup(param->string, GFP_KERNEL);
		if (!parsing_mp->m_rtname)
			return -ENOMEM;
		return 0;
	case Opt_allocsize:
		if (suffix_kstrtoint(param->string, 10, &size))
			return -EINVAL;
		parsing_mp->m_allocsize_log = ffs(size) - 1;
		parsing_mp->m_features |= XFS_FEAT_ALLOCSIZE;
		return 0;
	case Opt_grpid:
	case Opt_bsdgroups:
		parsing_mp->m_features |= XFS_FEAT_GRPID;
		return 0;
	case Opt_nogrpid:
	case Opt_sysvgroups:
		parsing_mp->m_features &= ~XFS_FEAT_GRPID;
		return 0;
	case Opt_wsync:
		parsing_mp->m_features |= XFS_FEAT_WSYNC;
		return 0;
	case Opt_norecovery:
		parsing_mp->m_features |= XFS_FEAT_NORECOVERY;
		return 0;
	case Opt_noalign:
		parsing_mp->m_features |= XFS_FEAT_NOALIGN;
		return 0;
	case Opt_swalloc:
		parsing_mp->m_features |= XFS_FEAT_SWALLOC;
		return 0;
	case Opt_sunit:
		parsing_mp->m_dalign = result.uint_32;
		return 0;
	case Opt_swidth:
		parsing_mp->m_swidth = result.uint_32;
		return 0;
	case Opt_inode32:
		parsing_mp->m_features |= XFS_FEAT_SMALL_INUMS;
		return 0;
	case Opt_inode64:
		parsing_mp->m_features &= ~XFS_FEAT_SMALL_INUMS;
		return 0;
	case Opt_nouuid:
		parsing_mp->m_features |= XFS_FEAT_NOUUID;
		return 0;
	case Opt_largeio:
		parsing_mp->m_features |= XFS_FEAT_LARGE_IOSIZE;
		return 0;
	case Opt_nolargeio:
		parsing_mp->m_features &= ~XFS_FEAT_LARGE_IOSIZE;
		return 0;
	case Opt_filestreams:
		parsing_mp->m_features |= XFS_FEAT_FILESTREAMS;
		return 0;
	case Opt_noquota:
		parsing_mp->m_qflags &= ~XFS_ALL_QUOTA_ACCT;
		parsing_mp->m_qflags &= ~XFS_ALL_QUOTA_ENFD;
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_quota:
	case Opt_uquota:
	case Opt_usrquota:
		parsing_mp->m_qflags |= (XFS_UQUOTA_ACCT | XFS_UQUOTA_ENFD);
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_qnoenforce:
	case Opt_uqnoenforce:
		parsing_mp->m_qflags |= XFS_UQUOTA_ACCT;
		parsing_mp->m_qflags &= ~XFS_UQUOTA_ENFD;
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_pquota:
	case Opt_prjquota:
		parsing_mp->m_qflags |= (XFS_PQUOTA_ACCT | XFS_PQUOTA_ENFD);
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_pqnoenforce:
		parsing_mp->m_qflags |= XFS_PQUOTA_ACCT;
		parsing_mp->m_qflags &= ~XFS_PQUOTA_ENFD;
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_gquota:
	case Opt_grpquota:
		parsing_mp->m_qflags |= (XFS_GQUOTA_ACCT | XFS_GQUOTA_ENFD);
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_gqnoenforce:
		parsing_mp->m_qflags |= XFS_GQUOTA_ACCT;
		parsing_mp->m_qflags &= ~XFS_GQUOTA_ENFD;
		parsing_mp->m_qflags |= XFS_QFLAGS_MNTOPTS;
		return 0;
	case Opt_discard:
		parsing_mp->m_features |= XFS_FEAT_DISCARD;
		return 0;
	case Opt_nodiscard:
		parsing_mp->m_features &= ~XFS_FEAT_DISCARD;
		return 0;
#ifdef CONFIG_FS_DAX
	case Opt_dax:
		xfs_mount_set_dax_mode(parsing_mp, XFS_DAX_ALWAYS);
		return 0;
	case Opt_dax_enum:
		xfs_mount_set_dax_mode(parsing_mp, result.uint_32);
		return 0;
#endif
	case Opt_max_open_zones:
		parsing_mp->m_max_open_zones = result.uint_32;
		return 0;
	case Opt_lifetime:
		parsing_mp->m_features &= ~XFS_FEAT_NOLIFETIME;
		return 0;
	case Opt_nolifetime:
		parsing_mp->m_features |= XFS_FEAT_NOLIFETIME;
		return 0;
	case Opt_max_atomic_write:
		if (suffix_kstrtoull(param->string, 10,
				     &parsing_mp->m_awu_max_bytes)) {
			xfs_warn(parsing_mp,
 "max atomic write size must be positive integer");
			return -EINVAL;
		}
		return 0;
	case Opt_errortag:
		return xfs_errortag_add_name(parsing_mp, param->string);
	default:
		xfs_warn(parsing_mp, "unknown mount option [%s].", param->key);
		return -EINVAL;
	}

	return 0;
}

static int
xfs_fs_validate_params(
	struct xfs_mount	*mp)
{
	/* No recovery flag requires a read-only mount */
	if (xfs_has_norecovery(mp) && !xfs_is_readonly(mp)) {
		xfs_warn(mp, "no-recovery mounts must be read-only.");
		return -EINVAL;
	}

	if (xfs_has_noalign(mp) && (mp->m_dalign || mp->m_swidth)) {
		xfs_warn(mp,
	"sunit and swidth options incompatible with the noalign option");
		return -EINVAL;
	}

	if (!IS_ENABLED(CONFIG_XFS_QUOTA) &&
	    (mp->m_qflags & ~XFS_QFLAGS_MNTOPTS)) {
		xfs_warn(mp, "quota support not available in this kernel.");
		return -EINVAL;
	}

	if ((mp->m_dalign && !mp->m_swidth) ||
	    (!mp->m_dalign && mp->m_swidth)) {
		xfs_warn(mp, "sunit and swidth must be specified together");
		return -EINVAL;
	}

	if (mp->m_dalign && (mp->m_swidth % mp->m_dalign != 0)) {
		xfs_warn(mp,
	"stripe width (%d) must be a multiple of the stripe unit (%d)",
			mp->m_swidth, mp->m_dalign);
		return -EINVAL;
	}

	if (mp->m_logbufs != -1 &&
	    mp->m_logbufs != 0 &&
	    (mp->m_logbufs < XLOG_MIN_ICLOGS ||
	     mp->m_logbufs > XLOG_MAX_ICLOGS)) {
		xfs_warn(mp, "invalid logbufs value: %d [not %d-%d]",
			mp->m_logbufs, XLOG_MIN_ICLOGS, XLOG_MAX_ICLOGS);
		return -EINVAL;
	}

	if (mp->m_logbsize != -1 &&
	    mp->m_logbsize !=  0 &&
	    (mp->m_logbsize < XLOG_MIN_RECORD_BSIZE ||
	     mp->m_logbsize > XLOG_MAX_RECORD_BSIZE ||
	     !is_power_of_2(mp->m_logbsize))) {
		xfs_warn(mp,
			"invalid logbufsize: %d [not 16k,32k,64k,128k or 256k]",
			mp->m_logbsize);
		return -EINVAL;
	}

	if (xfs_has_allocsize(mp) &&
	    (mp->m_allocsize_log > XFS_MAX_IO_LOG ||
	     mp->m_allocsize_log < XFS_MIN_IO_LOG)) {
		xfs_warn(mp, "invalid log iosize: %d [not %d-%d]",
			mp->m_allocsize_log, XFS_MIN_IO_LOG, XFS_MAX_IO_LOG);
		return -EINVAL;
	}

	return 0;
}

struct dentry *
xfs_debugfs_mkdir(
	const char	*name,
	struct dentry	*parent)
{
	struct dentry	*child;

	/* Apparently we're expected to ignore error returns?? */
	child = debugfs_create_dir(name, parent);
	if (IS_ERR(child))
		return NULL;

	return child;
}

/*
 * v5 sess33: forward decl for module-level cache caps populated by
 * mxfs_compute_cache_caps at module init.  Definition + module params
 * are below near init_xfs_fs.  fill_super reads these to populate
 * per-mount mxfs_v5_dlm_opts.max_dlm_lock_caw.
 */
struct mxfs_cache_caps {
	int inode;
	int dlm_lock;
	int dir;
	int block;
};
static struct mxfs_cache_caps mxfs_cache_caps;

/*
 * DEAD-NODE DETECTION WINDOW in ms.  0 = disklock compile-time default
 * (62 s, production-conservative).  Test rigs set e.g. 15000 so crash
 * recovery — lock purge + foreign-slice replay — fires promptly.
 *
 * sess93 — THE NAME `lease_timeout_ms` IS A LIE, and it is kept only for
 * compatibility.  It has never configured the lease: mxfs_v5_dlm_init feeds
 * it to mxfs_disklock_set_dead_timeout_ms() and nothing else.  The lease's
 * own timeout is MXFS_LEASE_TIMEOUT_DEFAULT_MS (600000, lease.h) and nothing
 * ever changes it.  An operator setting lease_timeout_ms=15000 expecting a
 * 15 s lease gets a 15 s DISKLOCK threshold and a still-10-minute lease.
 *
 * And the lease deliberately does NOT track it (sess43): a node that dies and
 * rejoins takes a NEW node_id, so peers keep the dead identity ACTIVE in
 * their lease table for up to ten minutes after every fault-injecting event.
 * That long window is correct self-healing behaviour — shortening it to match
 * the disklock threshold would make a rejoining node race its own ghost.  The
 * authoritative membership is the on-disk HB table, not the lease beacon.
 *
 * `dead_timeout_ms` is the canonical name.  `lease_timeout_ms` still works
 * and, when it is the one actually set, says so at load.
 */
static unsigned int mxfs_dead_timeout_ms;
static unsigned int mxfs_lease_timeout_ms;

static unsigned int mxfs_resolve_dead_timeout_ms(void)
{
	return mxfs_dead_timeout_ms ? mxfs_dead_timeout_ms
				    : mxfs_lease_timeout_ms;
}

/*
 * sess42 C7 version gate: explicit, logged, UNSAFE opt-out that lets a
 * legacy (pre-protogate) cluster format mount RW — e.g. to migrate data
 * off an old format.  Default 0 = bit-absent cluster RW is refused
 * (module param defined with the others below).
 */
static unsigned int mxfs_legacy_rw;

/*
 * sess38: mxfs dentry revalidation for cluster coordination.
 *
 * Upstream XFS installs no dentry_operations (single-node).  Without
 * d_revalidate, cached dentry lookups short-circuit through the VFS
 * dcache and never consult the DLM, so a cross-node create-race loser
 * keeps a STALE NEGATIVE dentry: a later stat() returns ENOENT from the
 * dcache even though a peer created the name (the EEXIST-loser bug that
 * partitions the cluster-test barriers).
 *
 * On each cached lookup (ref-walk; RCU-walk bails to -ECHILD) take the
 * parent ILOCK SHARED — routing through mxfs_dlm_ilock_begin for a
 * coordinated, reload-if-stale view — and re-resolve the name.  For a
 * positive dentry, drop it if the name no longer resolves to the same
 * inode.  For a negative dentry, drop it if the name now DOES resolve
 * (peer created it).  Self-gates to a no-op for single-node mounts so
 * single-node path-walk cost is unchanged.
 */
static int
mxfs_drevalidate(struct dentry *dentry, unsigned int flags)
{
	struct dentry		*parent;
	struct inode		*dir;
	struct xfs_inode	*dp;
	struct xfs_inode	*ip;
	struct xfs_name		xname;
	xfs_ino_t		actual_ino = 0;
	int			error;
	int			ret;

	/* RCU-walk can't block; force ref-walk retry. */
	if (flags & LOOKUP_RCU)
		return -ECHILD;
	if (!dentry)
		return 1;

	parent = dget_parent(dentry);
	dir = d_inode(parent);
	if (!dir) {
		dput(parent);
		return 1;
	}
	dp = XFS_I(dir);

	if (!dp->i_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
		dput(parent);
		return 1;
	}

	/*
	 * sess45: cheap, targeted revalidation.  The historical version took
	 * the parent-dir ILOCK_SHARED (→ DLM) on EVERY cached lookup, which
	 * under load ping-ponged the shared dir's DLM and caused barrier
	 * timeouts.  Restrict the coordinated revalidation to the only case it
	 * is needed for here:
	 *   - NEGATIVE dentry: the cross-node create-race (stale negative) is
	 *     already closed by the xfs_iget_cache_miss stale-cluster fix and
	 *     the cross_/rename_visibility tests pass without revalidation —
	 *     so skip it (return valid) to avoid per-failed-lookup DLM cost.
	 *   - POSITIVE dentry for an inode in OUR OWN affine AG: under
	 *     node-affine allocation we own it; our dcache is authoritative.
	 *     Skip (no DLM) — this is the common path-walk case.
	 *   - POSITIVE dentry for a PEER's affine-AG inode: a peer may have
	 *     unlinked/renamed it (test_unlink_visibility).  Do the
	 *     coordinated parent-dir lookup and drop the dentry if the name no
	 *     longer resolves to the same inode.
	 */
	/*
	 * sess45 fast-path: a POSITIVE dentry for an inode in OUR OWN affine AG
	 * is authoritative in our dcache under node-affine allocation — skip
	 * the coordinated lookup (no parent DLM).  This is the common
	 * path-walk case (a node walking its own files) and keeps revalidation
	 * cheap.  NEGATIVE dentries and PEER-AG positive dentries still take
	 * the coordinated path below: negative → catch a peer's create
	 * (cross_visibility); peer-AG positive → catch a peer's unlink/rename
	 * (unlink_visibility).
	 */
	/*
	 * sess45 coordinated revalidation, sess49 made deadlock-safe.
	 *   - POSITIVE dentry, inode in OUR OWN affine AG: authoritative under
	 *     node-affine allocation; keep it (return 1) with NO lock — the
	 *     common path-walk case stays cheap.
	 *   - POSITIVE dentry for a PEER's affine-AG inode: a peer may have
	 *     unlinked/renamed it (unlink_visibility) → coordinated lookup, drop
	 *     if the name no longer resolves to the same inode.
	 *   - NEGATIVE dentry: a peer may have created the name (barrier-dir
	 *     EEXIST-loser) → coordinated lookup, drop if it now resolves.
	 * The coordinated xfs_dir_lookup takes dp ILOCK_SHARED → mxfs_dlm_ilock_
	 * begin → (if stale) mxfs_dlm_reload_inode.  That reload USED to do a
	 * blocking down_write(&dp->i_lock) and wedge this path-walk context
	 * permanently (sess49 hung-task); it now uses a bounded trylock and bails
	 * (leaving i_dlm_stale set) so this call can never deadlock — at worst the
	 * lookup reads a slightly-stale dir block and a later access re-resolves.
	 */
	pr_warn_once("mxfs: H37-MXFS-DREVALIDATE active (sess49 coordinated+deadlock-safe)\n");

	if (d_really_is_positive(dentry)) {
		ip = XFS_I(d_inode(dentry));
		/*
		 * sess86 Part A (Gemini RULE-5): respect a stale flag already set
		 * on the cached child inode — either by the disklock eviction ring
		 * (XFS_ISTALE_CAW) or by the gen-mismatch check below on a prior
		 * revalidation (i_dlm_stale).  d_revalidate historically returned
		 * "valid" whenever the name still resolved to the SAME inode number,
		 * which is exactly the reused-inode case (dir rm-rf'd + recreated,
		 * same number, same type) — so a flagged-stale inode kept being
		 * served from the dcache and xfs_lookup's eviction never ran.
		 * Return INVALID so VFS drops the dentry and re-resolves through
		 * xfs_lookup, which evicts (d_prune_aliases + irele + re-iget) and
		 * re-reads the current incarnation.  This check is unconditional
		 * (own- and peer-AG) and cheap (two flag reads, no I/O, no lock).
		 */
		if (ip->i_dlm_stale ||
		    xfs_iflags_test(ip, XFS_ISTALE_CAW)) {
			/*
			 * Force re-resolution through xfs_lookup, which re-reads the
			 * current dir block + evicts a genuinely-reused inode.  The
			 * stuck-XFS_ISTALE_CAW false-positive loop (sess91) is broken
			 * in xfs_lookup AFTER the fresh dir lookup (so rename/unlink
			 * content stays visible), NOT here — clearing the flag here
			 * removed the dir-content re-read trigger and regressed
			 * rename_visibility.
			 */
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				pr_warn_ratelimited(
					"mxfs: P-DREVAL-STALEFLAG ino=%llu istale_caw=%d dlm_stale=%d name=%.*s\n",
					(unsigned long long)ip->i_ino,
					!!xfs_iflags_test(ip, XFS_ISTALE_CAW),
					ip->i_dlm_stale,
					dentry->d_name.len, dentry->d_name.name);
			dput(parent);
			return 0;
		}
		/*
		 * v0.5.1 DLM hold-epoch fast path (RULE 4 proven, sess19 ccloop:
		 * 32/43 rsync stack samples sat in mxfs_pal_scsi_read_fua_bdev
		 * under mxfs_drevalidate — a synchronous SCSI FUA read per
		 * cached DIR lookup made a solo rsync with one IDLE peer 127 s
		 * vs ~5 s truly-single-node).  Every staleness mode this
		 * function guards against (peer unlink/rename of the name,
		 * inode-number reuse, type flip) requires the peer to take the
		 * parent dir's DLM EX — which requires THIS node to first lose
		 * its cached grant (i_dlm_mode -> NL bumps i_dlm_epoch).  So:
		 * if we still hold dp's grant, dp carries no stale flag, and
		 * this dentry was last validated under the CURRENT hold epoch
		 * (d_time == i_dlm_epoch), no peer can have changed anything —
		 * return valid with ZERO disk I/O.  First validation of a
		 * dentry (d_time 0 != epoch >= 1) and any validation after a
		 * lock bounce still take the full coordinated path below.
		 */
		if (READ_ONCE(dp->i_dlm_mode) != MXFS_LOCK_NL &&
		    !READ_ONCE(dp->i_dlm_stale) &&
		    !xfs_iflags_test(dp, XFS_ISTALE_CAW) &&
		    dentry->d_time == READ_ONCE(dp->i_dlm_epoch)) {
			dput(parent);
			return 1;
		}
		/*
		 * sess126 FIX (RULE 4 proven + RULE 5 Gemini): EXCLUDE DIRECTORY
		 * inodes from the affine fast-path.  The fast-path blesses a
		 * positive dentry in our OWN affine AG as valid with NO coordinated
		 * re-lookup, on the premise that node-affine allocation makes us
		 * authoritative.  That premise is FALSE for a SHARED DIRECTORY:
		 * every node adds/removes children in it regardless of which AG it
		 * lives in.  PROVEN root of test_unlink_visibility: `.mxfs_test`
		 * (ino 131, SHORTFORM dir, in node1's affine AG) has children added
		 * by peers (the winner's `unlink_visibility` dirent); node1's affine
		 * fast-path served its STALE cached 131, so a child lookup returned
		 * ENOENT and the race-loser's 30 file creates ALL failed (never
		 * reached the FS) before the laggy async DIR_MODIFY signal refreshed
		 * 131.  Letting a DIR dentry fall through to the coordinated lookup
		 * below takes dp ILOCK_SHARED → mxfs_dlm_ilock_begin → reload-if-
		 * stale, refreshing the shared dir's child list.  Cheap under
		 * fua_disable=1 (plain reads).  Regular FILES keep the fast-path
		 * (they are genuinely authoritative under node-affine allocation).
		 */
		if (dp->i_mount->m_maxagi &&
		    !S_ISDIR(VFS_I(ip)->i_mode) &&
		    XFS_INO_TO_AGNO(dp->i_mount, ip->i_ino) ==
			(dp->i_mount->m_mxfs_node_slot % dp->i_mount->m_maxagi)) {
			/*
			 * sess10 (ccloop c7ee71c6) P165: this is the ONLY positive-
			 * dentry exit that ignores the parent hold-epoch.  Suspected
			 * vector for the cc uv 127/128 lost create: a STALE positive
			 * dentry (name -> own-affine-AG recycled ino) from a dead
			 * incarnation of the parent dir is blessed here forever, so
			 * open(O_CREAT) truncates the CURRENT occupant of the reused
			 * ino instead of creating (test16 node16_file1 -> live
			 * node16_after_1, run 233839Z).  Decisive probe: log every
			 * affine blessing whose d_time does not match dp's CURRENT
			 * dlm epoch — a fresh binding validated this epoch never
			 * mismatches, a resurrected/stale one always does.
			 */
			if (dentry->d_time != READ_ONCE(dp->i_dlm_epoch)) {
				static atomic_t p165n = ATOMIC_INIT(0);

				if (atomic_inc_return(&p165n) <= 100000)
					pr_warn("mxfs: P165-AFFINE-STALE name=%.*s ino=%llu dp=%llu d_time=%lu dp_epoch=%lu dp_mode=%d child_gen=%u realns=%llu\n",
						dentry->d_name.len,
						dentry->d_name.name,
						(unsigned long long)ip->i_ino,
						(unsigned long long)dp->i_ino,
						dentry->d_time,
						(unsigned long)READ_ONCE(dp->i_dlm_epoch),
						READ_ONCE(dp->i_dlm_mode),
						VFS_I(ip)->i_generation,
						(unsigned long long)ktime_get_real_ns());
			}
			dput(parent);
			return 1;
		}
	} else {
		ip = NULL;
		/*
		 * v0.5.1 hold-epoch fast path, negative-dentry side: a name
		 * can only START resolving if someone creates it.  A local
		 * create instantiates this dentry positive (never reaches
		 * here); a peer create requires dp's DLM EX, i.e. our grant
		 * loss -> epoch bump.  Grant held + epoch match => still a
		 * valid negative dentry, zero I/O.
		 */
		if (READ_ONCE(dp->i_dlm_mode) != MXFS_LOCK_NL &&
		    !READ_ONCE(dp->i_dlm_stale) &&
		    !xfs_iflags_test(dp, XFS_ISTALE_CAW) &&
		    dentry->d_time == READ_ONCE(dp->i_dlm_epoch)) {
			dput(parent);
			return 1;
		}
	}

	xname.name = dentry->d_name.name;
	xname.len = dentry->d_name.len;
	xname.type = XFS_DIR3_FT_UNKNOWN;

	{
	uint8_t dirent_ftype = XFS_DIR3_FT_UNKNOWN;
	/*
	 * v0.5.1: epoch to stamp into dentry->d_time if this coordinated
	 * validation succeeds.  Read BEFORE the lookup: if dp's grant
	 * bounces mid-validation the stamp is already stale and the next
	 * cached lookup re-validates — never the reverse.
	 */
	unsigned long dp_epoch = READ_ONCE(dp->i_dlm_epoch);

	/*
	 * sess133 PROVEN ROOT FIX (RULE 4, live /proc/pid/stack +
	 * P132-ILOCK-STUCK forensics on test13): do NOT take dp's ILOCK
	 * here — xfs_dir_lookup takes xfs_ilock_data_map_shared(dp)
	 * INTERNALLY (that inner, coordinated acquire is also what runs
	 * mxfs_dlm_ilock_begin → reload-if-stale).  Holding an outer
	 * ILOCK_SHARED across it is a RECURSIVE rwsem read acquire: the
	 * moment a writer (peer-storm mkdir in xfs_create wanting
	 * ILOCK_EXCL) queues between our two read acquires, rwsem
	 * writer-fairness blocks the inner down_read behind the queued
	 * writer while we still hold the outer read → self-deadlock.
	 * The BAST release worker's drain down_read then never succeeds,
	 * our on-disk EX bit on the shared dir never clears, and the
	 * whole cluster starves into 120s-timeout storms (the
	 * zero_silent_loss dpn=100 wedge).  PROVEN: touch pid blocked at
	 * xfs_dir_lookup+0x132 → xfs_ilock_data_map_shared with rd_last =
	 * mxfs_drevalidate+0x188 (this site) recorded as the live holder,
	 * rwsem count 0x102 (1 reader + waiters).
	 */
	error = xfs_dir_lookup(NULL, dp, &xname, &actual_ino, NULL,
			       &dirent_ftype);

	if (!ip) {
		/* negative dentry: valid only while name still doesn't resolve */
		ret = error ? 1 : 0;
	} else if (error) {
		ret = 0;			/* name gone (peer unlinked) */
	} else if (actual_ino != ip->i_ino) {
		ret = 0;			/* peer renamed/recreated */
	} else {
		ret = 1;
		/*
		 * sess86 Part C (Gemini RULE-5): reused-inode (SAME number, SAME
		 * type) staleness.  A peer doing `rm -rf dir; mkdir dir` reallocates
		 * the inode number for the new directory with a BUMPED generation.
		 * The name still resolves to the same number (ret=1 above) and the
		 * ftype matches (dir->dir), so every type-based defense is blind and
		 * this node keeps serving the STALE prior incarnation -> ENOTDIR on
		 * path-walk into it, or a hard wedge on its reload.  Disambiguate
		 * with a single LOCKLESS FUA read of just the on-disk dinode's di_gen
		 * (mxfs_inode_disk_di_size reads the inode-cluster sector via SCSI
		 * READ(16) FUA, bypassing the XFS buffer cache and ALL inode locks —
		 * no ILOCK, no DLM, no deadlock).  If the platter incarnation differs
		 * from our cached one, mark it stale and return INVALID so xfs_lookup
		 * evicts + re-igets the fresh dir.  Bounded to peer-AG DIRECTORIES
		 * (we reach here only for peer-AG positive dentries; own-AG dirs took
		 * the affine fast-path above), so the FUA cost stays off the hot
		 * own-files path and off the empty-marker reg-file path (sess51).
		 */
		/*
		 * v0.5.2: all three lockless FUA oracles below (GENMISS /
		 * RESURRECT / TYPEMISS) are gated on ip's grant being NL.
		 * With publish-only durable_signal the platter lags the log
		 * until AIL push, so while WE hold a grant on ip our in-core
		 * copy is authoritative and the FUA read can return a
		 * previous-incarnation dinode (re-mkfs'd LUN: valid-looking
		 * old generations) → false stale-mark → DIRMISS/names=[]
		 * clobber chain.  Only at NL can a peer have changed the
		 * inode, and the BAST release drain (invariant #1) guarantees
		 * the platter is current before any peer grant — exactly the
		 * case the oracles exist for.
		 */
		if (S_ISDIR(VFS_I(ip)->i_mode) &&
		    READ_ONCE(ip->i_dlm_mode) == MXFS_LOCK_NL) {
			uint32_t disk_gen = 0;
			extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *,
							uint16_t *, uint32_t *);

			(void)mxfs_inode_disk_di_size(ip, NULL, &disk_gen);
			if (disk_gen != 0 &&
			    disk_gen != (uint32_t)VFS_I(ip)->i_generation) {
				pr_warn_ratelimited(
					"mxfs: P-DREVAL-GENMISS ino=%llu incore_gen=%u disk_gen=%u name=%.*s\n",
					(unsigned long long)ip->i_ino,
					(uint32_t)VFS_I(ip)->i_generation,
					disk_gen,
					dentry->d_name.len, dentry->d_name.name);
				ip->i_dlm_stale = true; ip->i_dlm_stale_src = 21;
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				ret = 0;
			}
		} else if (VFS_I(ip)->i_mode == 0 &&
			   READ_ONCE(ip->i_dlm_mode) == MXFS_LOCK_NL &&
			   dp->i_mount->m_mxfs_dlm &&
			   !mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm)) {
			/*
			 * sess126 ROOT FIX (RULE 4 step 2b, proven by P-IRESURRECT):
			 * reused-inode STALE-CACHE on the winner DIRECTORY inode
			 * (unlink_visibility ino 4194433).  This node cached the inode
			 * as a stale FREED incarnation (incore i_mode==0, looks like a
			 * free inode) while the on-disk incarnation is a LIVE directory
			 * a peer allocated (disk_mode=040755, disk_gen=incore_gen+1).
			 * The name still resolves to the SAME number (ret=1 above), so
			 * the GENMISS recheck (gated on S_ISDIR(incore)) and TYPEMISS
			 * recheck (gated on incore mode!=0) are BOTH skipped —
			 * d_revalidate returns VALID for the mode==0 stale inode, it is
			 * never evicted, and readdir on a "free" inode returns 0 entries
			 * / create+rm hit ENOENT (node1/2/3 unlink_visibility FAIL;
			 * node4, whose cached copy IS the live dir, passes).
			 *
			 * A genuinely-free inode that a dir entry still names is a
			 * contradiction — the dir entry above resolved to this number,
			 * so on disk it must be live.  Confirm with ONE lockless FUA
			 * read of the on-disk dinode mode (same primitive as
			 * GENMISS/TYPEMISS, no ILOCK/DLM/deadlock).  If disk says LIVE
			 * (disk_mode!=0), our cached mode==0 incarnation is stale: mark
			 * it + return INVALID so xfs_lookup's ISTALE_CAW block evicts
			 * (incore mode==0 matches neither FALSEPOS nor SAMETYPE →
			 * ISTALE-CAW-EVICT → retry_iget) and re-reads the live dir.
			 */
			uint16_t disk_mode = 0;
			uint32_t disk_gen = 0;
			extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *,
							uint16_t *, uint32_t *);

			(void)mxfs_inode_disk_di_size(ip, &disk_mode, &disk_gen);
			if (disk_mode != 0) {
				pr_warn_ratelimited(
					"mxfs: P-DREVAL-RESURRECT ino=%llu incore_gen=%u disk_mode=0%o disk_gen=%u name=%.*s\n",
					(unsigned long long)ip->i_ino,
					(uint32_t)VFS_I(ip)->i_generation,
					disk_mode, disk_gen,
					dentry->d_name.len, dentry->d_name.name);
				ip->i_dlm_stale = true; ip->i_dlm_stale_src = 22;
				xfs_iflags_set(ip, XFS_ISTALE_CAW);
				ret = 0;
			}
		}
	}

	/*
	 * sess71 INSTR (RULE 4): Face A = inode-number REUSE type confusion.
	 * A cached POSITIVE dentry resolves to the SAME ino number but the
	 * in-core inode's S_IFMT disagrees with the dir entry's on-disk ftype
	 * (e.g. cached as DIR, on-disk now a REG file).  The ino-match check
	 * above returns ret=1 (valid) → `cat` opens the stale DIR inode →
	 * EISDIR.  Detect-only here (do NOT change ret yet); confirm this
	 * fires on the failing peer before patching.  Always-on, ratelimited.
	 */
	if (ip && !error && actual_ino == ip->i_ino &&
	    READ_ONCE(ip->i_dlm_mode) == MXFS_LOCK_NL &&
	    xfs_has_ftype(dp->i_mount) &&
	    dirent_ftype != XFS_DIR3_FT_UNKNOWN &&
	    dirent_ftype < XFS_DIR3_FT_MAX &&
	    VFS_I(ip)->i_mode != 0 &&
	    xfs_mode_to_ftype(VFS_I(ip)->i_mode) != dirent_ftype) {
		/*
		 * sess89 (RULE 4): convert sess71's detect-only TYPEMISS into a
		 * disambiguating fix.  A peer-AG positive dentry resolves to the
		 * SAME ino but the in-core inode's S_IFMT disagrees with the dir
		 * entry's on-disk ftype (e.g. cached REG, dirent says DIR).  The
		 * old code logged and returned ret=1 (valid) → VFS kept serving
		 * the wrong-typed cached inode → callers loop / barrier dirs hang
		 * 120 s (cv_verify_done: incore REG vs dirent DIR, sess88 repro).
		 *
		 * Disambiguate with ONE lockless FUA read of the on-disk dinode
		 * mode (no ILOCK/DLM — same primitive as the GENMISS path above):
		 *   (a) disk ftype == dirent ftype => our CACHED inode is the
		 *       stale prior incarnation (peer freed+reallocated this ino
		 *       as a different type).  Mark stale + return INVALID so
		 *       xfs_lookup evicts and re-igets the fresh on-disk inode.
		 *   (b) disk ftype == in-core ftype => the dirent / parent dir
		 *       block we just read is itself STALE (the inode is fine);
		 *       evicting the inode would loop forever.  Leave ret as-is
		 *       and log distinctly (dir-block coherency miss, separate
		 *       surface).
		 */
		uint16_t disk_mode = 0;
		uint8_t disk_ftype = XFS_DIR3_FT_UNKNOWN;
		extern uint64_t mxfs_inode_disk_di_size(struct xfs_inode *,
						uint16_t *, uint32_t *);

		(void)mxfs_inode_disk_di_size(ip, &disk_mode, NULL);
		if (disk_mode != 0)
			disk_ftype = xfs_mode_to_ftype(disk_mode);
		if (disk_ftype != XFS_DIR3_FT_UNKNOWN &&
		    disk_ftype == dirent_ftype) {
			ip->i_dlm_stale = true; ip->i_dlm_stale_src = 23;
			xfs_iflags_set(ip, XFS_ISTALE_CAW);
			ret = 0;
		}
		pr_warn_ratelimited(
			"mxfs: P-DREVAL-TYPEMISS ino=%llu incore_ftype=%u dirent_ftype=%u disk_ftype=%u disk_mode=0%o ret=%d name=%.*s\n",
			(unsigned long long)ip->i_ino,
			xfs_mode_to_ftype(VFS_I(ip)->i_mode),
			dirent_ftype, disk_ftype, disk_mode, ret,
			dentry->d_name.len, dentry->d_name.name);
	}
	/*
	 * v0.5.1: coordinated validation passed — stamp the pre-lookup
	 * hold-epoch so the next cached lookup under an unbounced grant
	 * takes the zero-I/O fast path above.
	 */
	if (ret == 1)
		dentry->d_time = dp_epoch;
	}
	dput(parent);
	return ret;
}

/* d_revalidate gained (dir, name) params in v6.17 (the dentry and flags
 * args still carry everything mxfs_drevalidate needs -- dir/name are
 * unused here, this is purely a calling-convention adapter). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
static int
mxfs_drevalidate_v617(struct inode *dir, const struct qstr *name,
		      struct dentry *dentry, unsigned int flags)
{
	return mxfs_drevalidate(dentry, flags);
}
#endif

static const struct dentry_operations mxfs_dentry_operations = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
	.d_revalidate = mxfs_drevalidate_v617,
#else
	.d_revalidate = mxfs_drevalidate,
#endif
};

static int
xfs_fs_fill_super(
	struct super_block	*sb,
	struct fs_context	*fc)
{
	struct xfs_mount	*mp = sb->s_fs_info;
	struct inode		*root;
	int			flags = 0, error;

	mp->m_super = sb;

	/*
	 * Copy VFS mount flags from the context now that all parameter parsing
	 * is guaranteed to have been completed by either the old mount API or
	 * the newer fsopen/fsconfig API.
	 */
	if (fc->sb_flags & SB_RDONLY)
		xfs_set_readonly(mp);
	if (fc->sb_flags & SB_DIRSYNC)
		mp->m_features |= XFS_FEAT_DIRSYNC;
	if (fc->sb_flags & SB_SYNCHRONOUS)
		mp->m_features |= XFS_FEAT_WSYNC;

	error = xfs_fs_validate_params(mp);
	if (error)
		return error;

	if (!sb_min_blocksize(sb, BBSIZE)) {
		xfs_err(mp, "unable to set blocksize");
		return -EINVAL;
	}
	sb->s_xattr = xfs_xattr_handlers;
	sb->s_export_op = &xfs_export_operations;
#ifdef CONFIG_XFS_QUOTA
	sb->s_qcop = &xfs_quotactl_operations;
	sb->s_quota_types = QTYPE_MASK_USR | QTYPE_MASK_GRP | QTYPE_MASK_PRJ;
#endif
	sb->s_op = &xfs_super_operations;

	/*
	 * sess38: install mxfs dentry operations so cached (incl. negative)
	 * dentry lookups are revalidated against the cluster-coordinated
	 * parent dir.  Without this, a cross-node create-race loser keeps a
	 * stale negative dentry and a later stat() returns ENOENT from the
	 * dcache without ever consulting XFS (the EEXIST-loser bug).
	 * mxfs_drevalidate self-gates to a no-op in single-node mounts.
	 *
	 * sess38: DISABLED — d_revalidate takes xfs_ilock(dp, SHARED) (→ CAW
	 * poll) on every cached path-walk lookup, which under 4-node load
	 * caused severe slowdown / barrier timeouts (test_unlink_visibility
	 * "uv_verify got 0/4") and risks the ILOCK-across-CAW-poll wedge.
	 * The stale-inode-cluster-buffer fix in xfs_iget_cache_miss already
	 * closes the concurrent-mkdir coherency (repro_modea 0/16) without
	 * it, so the per-lookup DLM cost is unnecessary.  Kept for reference.
	 */
	/*
	 * sess45: RE-ENABLED with a cheap, node-affine-gated mxfs_drevalidate
	 * (peer-AG positive dentries only; own-AG + negative dentries skip the
	 * DLM).  This closes test_unlink_visibility (a peer's unlink was
	 * invisible because node1's cached positive dentry for the peer's file
	 * was never revalidated → stat() found a stale-but-deleted inode).
	 */
	/* set_default_d_op() replaces direct sb->s_d_op assignment in v6.17 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
	set_default_d_op(sb, &mxfs_dentry_operations);
#else
	sb->s_d_op = &mxfs_dentry_operations;
#endif

	/*
	 * Delay mount work if the debug hook is set. This is debug
	 * instrumention to coordinate simulation of xfs mount failures with
	 * VFS superblock operations
	 */
	if (xfs_globals.mount_delay) {
		xfs_notice(mp, "Delaying mount for %d seconds.",
			xfs_globals.mount_delay);
		msleep(xfs_globals.mount_delay * 1000);
	}

	if (fc->sb_flags & SB_SILENT)
		flags |= XFS_MFSI_QUIET;

	error = xfs_open_devices(mp);
	if (error)
		return error;

	if (xfs_debugfs) {
		mp->m_debugfs = xfs_debugfs_mkdir(mp->m_super->s_id,
						  xfs_debugfs);
	} else {
		mp->m_debugfs = NULL;
	}

	error = xfs_init_mount_workqueues(mp);
	if (error)
		goto out_shutdown_devices;

	error = xfs_init_percpu_counters(mp);
	if (error)
		goto out_destroy_workqueues;

	error = xfs_inodegc_init_percpu(mp);
	if (error)
		goto out_destroy_counters;

	/* Allocate stats memory before we do operations that might use it */
	mp->m_stats.xs_stats = alloc_percpu(struct xfsstats);
	if (!mp->m_stats.xs_stats) {
		error = -ENOMEM;
		goto out_destroy_inodegc;
	}

	error = xchk_mount_stats_alloc(mp);
	if (error)
		goto out_free_stats;

	/*
	 * Check for MXFS envelope at sector 0.  If present, set the buftarg
	 * sector offset so all XFS I/O is redirected past the envelope,
	 * journal, and disklock regions to the XFS data area.
	 */
	{
		struct mxfs_ondisk_super *msup;

		msup = kmalloc(MXFS_SUPER_SIZE, GFP_KERNEL);
		if (msup) {
			int ret = xfs_rw_bdev(mp->m_ddev_targp->bt_bdev, 0,
					MXFS_SUPER_SIZE, (char *)msup,
					REQ_OP_READ);
			if (ret == 0 && msup->magic == MXFS_FORMAT_MAGIC) {
				xfs_daddr_t off = msup->xfs_data_offset >>
						  BBSHIFT;

				/*
				 * sess42 C7: refuse unknown envelope flag bits
				 * — a flag we do not understand marks a format
				 * evolution this code cannot honour (the same
				 * contract as XFS sb_features_incompat).
				 */
				if (msup->flags & ~MXFS_FORMAT_F_KNOWN) {
					xfs_alert(mp,
	"MXFS envelope has unknown incompatible flags 0x%x — this kernel is too old for this format; refusing mount",
						  msup->flags &
						  ~MXFS_FORMAT_F_KNOWN);
					kfree(msup);
					error = -EINVAL;
					goto out_free_scrub_stats;
				}
				mp->m_ddev_targp->bt_sector_offset = off;
				mp->m_mxfs_has_envelope = true;
				mp->m_mxfs_journal_offset = msup->journal_offset;
				mp->m_mxfs_disklock_offset = msup->disklock_offset;
				mp->m_mxfs_max_nodes = msup->max_nodes;
				mp->m_mxfs_log_node_count =
					msup->xfs_log_node_count;
				mp->m_mxfs_log_slice_bblks =
					msup->xfs_log_slice_bblks;
				mp->m_mxfs_protogate =
					(msup->flags & MXFS_FORMAT_F_PROTOGATE);
				mp->m_mxfs_cluster_proto_gen =
					mp->m_mxfs_protogate ?
						msup->cluster_proto_gen : 0;
				xfs_notice(mp,
					"MXFS envelope v%u: XFS data at offset %llu (%llu sectors) proto_gen=%u",
					msup->version,
					(unsigned long long)msup->xfs_data_offset,
					(unsigned long long)off,
					mp->m_mxfs_cluster_proto_gen);
			}
			kfree(msup);
		}
	}

	/*
	 * sess-tcp: one-shot FUA-capability probe.  mxfs's cross-node read
	 * coherency re-reads metadata via SCSI READ(16)+FUA; some targets
	 * (LIO/tcm_loop, write-through) REJECT that CDB (ILLEGAL REQUEST), in
	 * which case mxfs_pal_scsi_read_fua_bdev latches an "unsupported" flag
	 * and falls back to a coherent plain bio read.  Without this probe the
	 * flag only latches on the FIRST real FUA read — and that first
	 * cross-node read returns its garbage to the dinode verifier
	 * (EFSCORRUPTED "Structure needs cleaning") before the fallback engages.
	 * Issue one throwaway FUA read of the device super sector here so the
	 * capability is known before any filesystem I/O.
	 */
	{
		extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
			uint64_t, void *, uint32_t);
		void *probe = kmalloc(512, GFP_KERNEL);
		if (probe) {
			(void)mxfs_pal_scsi_read_fua_bdev(
				mp->m_ddev_targp->bt_bdev, 0, probe, 512);
			kfree(probe);
		}
	}

	error = xfs_readsb(mp, flags);
	if (error)
		goto out_free_scrub_stats;

	error = xfs_finish_flags(mp);
	if (error)
		goto out_free_sb;

	error = xfs_setup_devices(mp);
	if (error)
		goto out_free_sb;

	/*
	 * V4 support is undergoing deprecation.
	 *
	 * Note: this has to use an open coded m_features check as xfs_has_crc
	 * always returns false for !CONFIG_XFS_SUPPORT_V4.
	 */
	if (!(mp->m_features & XFS_FEAT_CRC)) {
		if (!IS_ENABLED(CONFIG_XFS_SUPPORT_V4)) {
			xfs_warn(mp,
	"Deprecated V4 format (crc=0) not supported by kernel.");
			error = -EINVAL;
			goto out_free_sb;
		}
		xfs_warn_once(mp,
	"Deprecated V4 format (crc=0) will not be supported after September 2030.");
	}

	/* ASCII case insensitivity is undergoing deprecation. */
	if (xfs_has_asciici(mp)) {
#ifdef CONFIG_XFS_SUPPORT_ASCII_CI
		xfs_warn_once(mp,
	"Deprecated ASCII case-insensitivity feature (ascii-ci=1) will not be supported after September 2030.");
#else
		xfs_warn(mp,
	"Deprecated ASCII case-insensitivity feature (ascii-ci=1) not supported by kernel.");
		error = -EINVAL;
		goto out_free_sb;
#endif
	}

	/*
	 * Filesystem claims it needs repair, so refuse the mount unless
	 * norecovery is also specified, in which case the filesystem can
	 * be mounted with no risk of further damage.
	 */
	if (xfs_has_needsrepair(mp) && !xfs_has_norecovery(mp)) {
		xfs_warn(mp, "Filesystem needs repair.  Please run xfs_repair.");
		error = -EFSCORRUPTED;
		goto out_free_sb;
	}

	/*
	 * Don't touch the filesystem if a user tool thinks it owns the primary
	 * superblock.  mkfs doesn't clear the flag from secondary supers, so
	 * we don't check them at all.
	 */
	if (mp->m_sb.sb_inprogress) {
		xfs_warn(mp, "Offline file system operation in progress!");
		error = -EFSCORRUPTED;
		goto out_free_sb;
	}

	if (mp->m_sb.sb_blocksize > PAGE_SIZE) {
		size_t max_folio_size = mapping_max_folio_size_supported();

		if (!xfs_has_crc(mp)) {
			xfs_warn(mp,
"V4 Filesystem with blocksize %d bytes. Only pagesize (%ld) or less is supported.",
				mp->m_sb.sb_blocksize, PAGE_SIZE);
			error = -ENOSYS;
			goto out_free_sb;
		}

		if (mp->m_sb.sb_blocksize > max_folio_size) {
			xfs_warn(mp,
"block size (%u bytes) not supported; Only block size (%zu) or less is supported",
				mp->m_sb.sb_blocksize, max_folio_size);
			error = -ENOSYS;
			goto out_free_sb;
		}
	}

	/* Ensure this filesystem fits in the page cache limits */
	if (xfs_sb_validate_fsb_count(&mp->m_sb, mp->m_sb.sb_dblocks) ||
	    xfs_sb_validate_fsb_count(&mp->m_sb, mp->m_sb.sb_rblocks)) {
		xfs_warn(mp,
		"file system too large to be mounted on this system.");
		error = -EFBIG;
		goto out_free_sb;
	}

	/*
	 * XFS block mappings use 54 bits to store the logical block offset.
	 * This should suffice to handle the maximum file size that the VFS
	 * supports (currently 2^63 bytes on 64-bit and ULONG_MAX << PAGE_SHIFT
	 * bytes on 32-bit), but as XFS and VFS have gotten the s_maxbytes
	 * calculation wrong on 32-bit kernels in the past, we'll add a WARN_ON
	 * to check this assertion.
	 *
	 * Avoid integer overflow by comparing the maximum bmbt offset to the
	 * maximum pagecache offset in units of fs blocks.
	 */
	if (!xfs_verify_fileoff(mp, XFS_B_TO_FSBT(mp, MAX_LFS_FILESIZE))) {
		xfs_warn(mp,
"MAX_LFS_FILESIZE block offset (%llu) exceeds extent map maximum (%llu)!",
			 XFS_B_TO_FSBT(mp, MAX_LFS_FILESIZE),
			 XFS_MAX_FILEOFF);
		error = -EINVAL;
		goto out_free_sb;
	}

	error = xfs_rtmount_readsb(mp);
	if (error)
		goto out_free_sb;

	error = xfs_filestream_mount(mp);
	if (error)
		goto out_free_rtsb;

	/*
	 * we must configure the block size in the superblock before we run the
	 * full mount process as the mount process can lookup and cache inodes.
	 */
	sb->s_magic = XFS_SUPER_MAGIC;
	sb->s_blocksize = mp->m_sb.sb_blocksize;
	sb->s_blocksize_bits = ffs(sb->s_blocksize) - 1;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_max_links = XFS_MAXLINK;
	sb->s_time_gran = 1;
	if (xfs_has_bigtime(mp)) {
		sb->s_time_min = xfs_bigtime_to_unix(XFS_BIGTIME_TIME_MIN);
		sb->s_time_max = xfs_bigtime_to_unix(XFS_BIGTIME_TIME_MAX);
	} else {
		sb->s_time_min = XFS_LEGACY_TIME_MIN;
		sb->s_time_max = XFS_LEGACY_TIME_MAX;
	}
	trace_xfs_inode_timestamp_range(mp, sb->s_time_min, sb->s_time_max);
	sb->s_iflags |= SB_I_CGROUPWB | SB_I_ALLOW_HSM;

	set_posix_acl_flag(sb);

	/* version 5 superblocks support inode version counters. */
	if (xfs_has_crc(mp))
		sb->s_flags |= SB_I_VERSION;

	/*
	 * sess2 (ccloop a9a03929) MXFS: default to NOATIME.  An atime-only
	 * update is a logged CORE change; on a shared-LUN cluster every such
	 * inode must be checkpointed + cluster-written-back before its DLM
	 * grant can move, so a read-mostly phase (8 nodes × 800 md5sum reads,
	 * relatime fires on every fresh file since atime==mtime) leaves the
	 * whole working set dirty-in-AIL and the next owner's pull pays a
	 * ~7ms drain per file (P2D-DRAINWHY in_ail=1 fields=0x1 = the whole
	 * 10.6s rm phase).  Cross-node atime coherency is not worth a
	 * per-file coherency stall — the same reasoning GFS2/OCFS2 document
	 * for noatime on cluster mounts.  Unconditional: MXFS is the cluster
	 * fs; atime is not part of its coherency contract.
	 */
	sb->s_flags |= SB_NOATIME;

	if (xfs_has_dax_always(mp)) {
		error = xfs_setup_dax_always(mp);
		if (error)
			goto out_filestream_unmount;
	}

	if (xfs_has_discard(mp) && !bdev_max_discard_sectors(sb->s_bdev)) {
		xfs_warn(mp,
	"mounting with \"discard\" option, but the device does not support discard");
		mp->m_features &= ~XFS_FEAT_DISCARD;
	}

	if (xfs_has_zoned(mp)) {
		if (!xfs_has_metadir(mp)) {
			xfs_alert(mp,
		"metadir feature required for zoned realtime devices.");
			error = -EINVAL;
			goto out_filestream_unmount;
		}
		xfs_warn_experimental(mp, XFS_EXPERIMENTAL_ZONED);
	}

	if (xfs_has_reflink(mp)) {
		if (xfs_has_realtime(mp) &&
		    !xfs_reflink_supports_rextsize(mp, mp->m_sb.sb_rextsize)) {
			xfs_alert(mp,
	"reflink not compatible with realtime extent size %u!",
					mp->m_sb.sb_rextsize);
			error = -EINVAL;
			goto out_filestream_unmount;
		}

		if (xfs_has_zoned(mp)) {
			xfs_alert(mp,
	"reflink not compatible with zoned RT device!");
			error = -EINVAL;
			goto out_filestream_unmount;
		}

		if (xfs_globals.always_cow) {
			xfs_info(mp, "using DEBUG-only always_cow mode.");
			mp->m_always_cow = true;
		}
	}

	/*
	 * If no quota mount options were provided, maybe we'll try to pick
	 * up the quota accounting and enforcement flags from the ondisk sb.
	 */
	if (!(mp->m_qflags & XFS_QFLAGS_MNTOPTS))
		xfs_set_resuming_quotaon(mp);
	mp->m_qflags &= ~XFS_QFLAGS_MNTOPTS;

	/*
	 * Initialize MXFS DLM before mountfs — xfs_log_mount (called
	 * inside xfs_mountfs) needs m_mxfs_node_slot to select the
	 * per-node log slice.
	 */
	if (mp->m_mxfs_has_envelope) {
		/*
		 * sess41 (GPT audit C10/G6) refused icluster_dlm=1 +
		 * open_tracking outright: routed files never claimed the
		 * per-inode slot the open_holders bits live on, so open
		 * publication silently no-op'd and a peer's unlink could
		 * free a file this node holds open.
		 *
		 * sess46: LIFTED — routed open tracking is now implemented
		 * per the GPT C9-ordering ruling: the icluster release is
		 * GATED on a durable standalone per-inode SET for every
		 * covered inode with protected activity
		 * (mxfs_iclus_publish_open_bits), opens pass the icluster
		 * admission gate (mxfs_iclus_open_admit), and the routed
		 * freer's B6 reads via the claim-less chain probe
		 * (mxfs_v5_dlm_inode_open_probe) with provable-absence
		 * semantics.  Mixed-version clusters are excluded by the C7
		 * proto_gen heartbeat gate; flipping icluster_dlm's DEFAULT
		 * is the protocol change that must bump MXFS_PROTO_GEN.
		 */
		if (mxfs_icluster_dlm &&
		    ({ extern unsigned int mxfs_open_tracking;
		       mxfs_open_tracking; }))
			xfs_notice(mp,
	"mxfs: icluster_dlm=1 with routed open-unlink protection (gated release publication + admission gate + probe-based B6)");
		/*
		 * sess42 C7 version gate — admission policy (GPT ruling: no
		 * hard-safe RW mode without the on-disk gate).  A cluster
		 * (envelope) volume without the PROTOGATE format bits could be
		 * mounted RW by a PRE-GATE kernel at any moment — such a
		 * kernel ignores open_holders bits, replay tagging, and purge
		 * rules, and the heartbeat-level fence can only stop it
		 * seconds AFTER its first unsafe writes.  So bit-absent
		 * cluster RW is not a safe configuration and is refused by
		 * default; mxfs.legacy_rw=1 is the explicit, logged, unsafe
		 * opt-out (e.g. to migrate data off an old format).  Gate
		 * present ⇒ generations must match exactly.
		 */
		if (mp->m_mxfs_protogate) {
			if (mp->m_mxfs_cluster_proto_gen != MXFS_PROTO_GEN) {
				xfs_alert(mp,
	"mxfs: C7 gate: filesystem cluster_proto_gen=%u but this kernel speaks %u — refusing mount (upgrade the mismatched side)",
					  mp->m_mxfs_cluster_proto_gen,
					  (unsigned)MXFS_PROTO_GEN);
				error = -EPROTONOSUPPORT;
				goto out_filestream_unmount;
			}
			if (!xfs_sb_has_incompat_feature(&mp->m_sb,
					XFS_SB_FEAT_INCOMPAT_MXFS_PROTOGATE)) {
				xfs_alert(mp,
	"mxfs: C7 gate: envelope is gated but the XFS sb lacks INCOMPAT_MXFS_PROTOGATE — half-upgraded format; run chk_mxfs --upgrade-protogate");
				error = -EPROTONOSUPPORT;
				goto out_filestream_unmount;
			}
		} else if (!mxfs_legacy_rw) {
			xfs_alert(mp,
	"mxfs: C7 gate: legacy (pre-protogate) cluster format — old kernels could mount it RW and corrupt open-unlink state undetected for seconds. Refusing mount; run chk_mxfs --upgrade-protogate (offline, all nodes unmounted), or set mxfs.legacy_rw=1 to explicitly accept the exposure.");
			error = -EPROTONOSUPPORT;
			goto out_filestream_unmount;
		} else {
			xfs_warn(mp,
	"mxfs: C7 gate: LEGACY RW mount (mxfs.legacy_rw=1) — no protection against pre-gate kernels joining this LUN");
		}
		/*
		 * v5 sess33: pick max_dlm_lock_caw from the per-mount override
		 * (set via mount option, future work) or fall back to the
		 * module-wide auto-sized mxfs_cache_caps.dlm_lock computed at
		 * module load.
		 */
		int max_dlm_caw = mp->m_mxfs_max_dlm_lock_caw > 0 ?
				  mp->m_mxfs_max_dlm_lock_caw :
				  mxfs_cache_caps.dlm_lock;
		struct mxfs_v5_dlm_opts dlm_opts = {
			.transport = MXFS_V5_TRANSPORT_CAW,
			.disklock_offset = mp->m_mxfs_disklock_offset,
			.journal_offset = mp->m_mxfs_journal_offset,
			.max_nodes = mp->m_mxfs_max_nodes,
			.bdev = mp->m_ddev_targp->bt_bdev,
			.max_dlm_lock_caw = max_dlm_caw,
			.lease_timeout_ms = mxfs_resolve_dead_timeout_ms(),
			/* sess65: the log-slice divisor, read from the
			 * envelope above.  The durable recovery descriptor
			 * records which slice a recovery covers. */
			.log_node_count = mp->m_mxfs_log_node_count,
		};
		memcpy(dlm_opts.volume_uuid, &mp->m_sb.sb_uuid, 16);
		/* sess6 (46efd8b6): flush epoch starts at 1 so a buffer stamp
		 * of 0 unambiguously means "never written by this node". */
		atomic64_set(&mp->m_mxfs_flush_epoch, 1);
		mp->m_mxfs_dlm = mxfs_v5_dlm_init(&dlm_opts);
		if (!mp->m_mxfs_dlm) {
			/*
			 * v0.11.77 fail-closed: an envelope volume is a
			 * cluster volume.  With no DLM this node cannot see
			 * peers, cannot be fenced, and cannot prove it is
			 * alone — mounting anyway means a possible second
			 * uncoordinated writer on a shared LUN (observed
			 * 2026-07-25: PR-register abort inside v5_dlm_init
			 * left BOTH test nodes mounted "single-node" on one
			 * LUN).  Abort the mount; repair tooling (chk_mxfs)
			 * works on the unmounted device.
			 */
			xfs_alert(mp, "MXFS DLM init failed — aborting mount of cluster (envelope) volume");
			error = -ENOTCONN;
			goto out_filestream_unmount;
		} else {
			mp->m_mxfs_dlm_was_active = true;
			mp->m_mxfs_node_slot =
				mxfs_v5_dlm_get_node_slot(mp->m_mxfs_dlm);
			/* sess32: pass-2 fresh HB claim => the log slice we
			 * inherit may be an already-recovered incarnation's;
			 * xfs_log_mount gates image re-application on this. */
			mp->m_mxfs_slice_adopted =
				mxfs_v5_dlm_slice_adopted(mp->m_mxfs_dlm);
			/* sess9 (ccloop a864): armed by xfs_do_force_shutdown
			 * to withdraw this node from the cluster DLM (fence
			 * acquires + stop heartbeat).  INIT here, immediately
			 * after the ctx exists, so any shutdown from this
			 * point on can queue it. */
			mxfs_defer_reap_init(mp);
			INIT_WORK(&mp->m_mxfs_withdraw_work,
				  mxfs_dlm_withdraw_work_fn);
		}
	}

	error = xfs_mountfs(mp);
	if (error)
		goto out_filestream_unmount;

	/* Post-mountfs DLM setup — cache init needs mounted FS (AIL etc.) */
	if (mp->m_mxfs_dlm) {
		mxfs_dlm_cache_init(mp);
		/* sess54 (D-FOREIGN-REPLAY step 4a): our log recovery has run
		 * and replayed images authored under the previous
		 * incarnation's authority bits, which step 4 deliberately
		 * KEPT.  Make that durable, then release them and route the
		 * peers deferred at step 6.5 into fence + slice recovery.
		 * Must follow cache_init: the settle needs the slice-replay
		 * hook it registers. */
		mxfs_dlm_mount_recovery_settle(mp);
	}

	/* sess39 D-STATFS fix: baseline every AGF+AGI so the cluster-coherent
	 * statfs perag sums cover AGs this node never touches, and expose the
	 * mount to the write-triggered diagnostics (pin_census). */
	if (mp->m_mxfs_dlm) {
		mxfs_init_all_perag_data(mp);
		WRITE_ONCE(mxfs_dbg_mp, mp);
	}

	root = igrab(VFS_I(mp->m_rootip));
	if (!root) {
		error = -ENOENT;
		goto out_unmount;
	}
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		error = -ENOMEM;
		goto out_unmount;
	}

	return 0;

 out_filestream_unmount:
	if (mp->m_mxfs_dlm) {
		void *v5dlm = mp->m_mxfs_dlm;

		mp->m_mxfs_dlm = NULL;	/* sess9: no-op any queued withdraw */
		cancel_work_sync(&mp->m_mxfs_withdraw_work);
		mxfs_defer_reap_destroy(mp);
		mxfs_v5_dlm_shutdown(v5dlm);
	}
	xfs_filestream_unmount(mp);
 out_free_rtsb:
	xfs_rtmount_freesb(mp);
 out_free_sb:
	xfs_freesb(mp);
 out_free_scrub_stats:
	xchk_mount_stats_free(mp);
 out_free_stats:
	free_percpu(mp->m_stats.xs_stats);
 out_destroy_inodegc:
	xfs_inodegc_free_percpu(mp);
 out_destroy_counters:
	xfs_destroy_percpu_counters(mp);
 out_destroy_workqueues:
	xfs_destroy_mount_workqueues(mp);
 out_shutdown_devices:
	xfs_shutdown_devices(mp);
	return error;

 out_unmount:
	if (mp->m_mxfs_dlm) {
		void *v5dlm = mp->m_mxfs_dlm;

		mp->m_mxfs_dlm = NULL;	/* sess9: no-op any queued withdraw */
		cancel_work_sync(&mp->m_mxfs_withdraw_work);
		mxfs_defer_reap_destroy(mp);
		mxfs_v5_dlm_shutdown(v5dlm);
		/* v0.5.0: work INIT'd by mxfs_dlm_cache_init (ran before
		 * this label is reachable); drain while m_log is valid. */
		cancel_work_sync(&mp->m_mxfs_foreign_replay_work);
		/* sess151: same lifecycle — see the unmount-path comment. */
		cancel_work_sync(&mp->m_mxfs_dlm_stuck_work);
	}
	xfs_filestream_unmount(mp);
	xfs_unmountfs(mp);
	goto out_free_rtsb;
}

static int
xfs_fs_get_tree(
	struct fs_context	*fc)
{
	return get_tree_bdev(fc, xfs_fs_fill_super);
}

static int
xfs_remount_rw(
	struct xfs_mount	*mp)
{
	struct xfs_sb		*sbp = &mp->m_sb;
	int error;

	if (mp->m_logdev_targp && mp->m_logdev_targp != mp->m_ddev_targp &&
	    xfs_readonly_buftarg(mp->m_logdev_targp)) {
		xfs_warn(mp,
			"ro->rw transition prohibited by read-only logdev");
		return -EACCES;
	}

	if (mp->m_rtdev_targp && xfs_readonly_buftarg(mp->m_rtdev_targp)) {
		xfs_warn(mp,
			"ro->rw transition prohibited by read-only rtdev");
		return -EACCES;
	}

	if (xfs_has_norecovery(mp)) {
		xfs_warn(mp,
			"ro->rw transition prohibited on norecovery mount");
		return -EINVAL;
	}

	if (xfs_sb_is_v5(sbp) &&
	    xfs_sb_has_ro_compat_feature(sbp, XFS_SB_FEAT_RO_COMPAT_UNKNOWN)) {
		xfs_warn(mp,
	"ro->rw transition prohibited on unknown (0x%x) ro-compat filesystem",
			(sbp->sb_features_ro_compat &
				XFS_SB_FEAT_RO_COMPAT_UNKNOWN));
		return -EINVAL;
	}

	xfs_clear_readonly(mp);

	/*
	 * If this is the first remount to writeable state we might have some
	 * superblock changes to update.
	 */
	if (mp->m_update_sb) {
		error = xfs_sync_sb(mp, false);
		if (error) {
			xfs_warn(mp, "failed to write sb changes");
			return error;
		}
		mp->m_update_sb = false;
	}

	/*
	 * Fill out the reserve pool if it is empty. Use the stashed value if
	 * it is non-zero, otherwise go with the default.
	 */
	xfs_restore_resvblks(mp);
	xfs_log_work_queue(mp);
	xfs_blockgc_start(mp);

	/* Create the per-AG metadata reservation pool .*/
	error = xfs_fs_reserve_ag_blocks(mp);
	if (error && error != -ENOSPC)
		return error;

	/* Re-enable the background inode inactivation worker. */
	xfs_inodegc_start(mp);

	/* Restart zone reclaim */
	xfs_zone_gc_start(mp);

	return 0;
}

static int
xfs_remount_ro(
	struct xfs_mount	*mp)
{
	struct xfs_icwalk	icw = {
		.icw_flags	= XFS_ICWALK_FLAG_SYNC,
	};
	int			error;

	/* Flush all the dirty data to disk. */
	error = sync_filesystem(mp->m_super);
	if (error)
		return error;

	/*
	 * Cancel background eofb scanning so it cannot race with the final
	 * log force+buftarg wait and deadlock the remount.
	 */
	xfs_blockgc_stop(mp);

	/*
	 * Clear out all remaining COW staging extents and speculative post-EOF
	 * preallocations so that we don't leave inodes requiring inactivation
	 * cleanups during reclaim on a read-only mount.  We must process every
	 * cached inode, so this requires a synchronous cache scan.
	 */
	error = xfs_blockgc_free_space(mp, &icw);
	if (error) {
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		return error;
	}

	/*
	 * Stop the inodegc background worker.  xfs_fs_reconfigure already
	 * flushed all pending inodegc work when it sync'd the filesystem.
	 * The VFS holds s_umount, so we know that inodes cannot enter
	 * xfs_fs_destroy_inode during a remount operation.  In readonly mode
	 * we send inodes straight to reclaim, so no inodes will be queued.
	 */
	xfs_inodegc_stop(mp);

	/* Stop zone reclaim */
	xfs_zone_gc_stop(mp);

	/* Free the per-AG metadata reservation pool. */
	xfs_fs_unreserve_ag_blocks(mp);

	/*
	 * Before we sync the metadata, we need to free up the reserve block
	 * pool so that the used block count in the superblock on disk is
	 * correct at the end of the remount. Stash the current* reserve pool
	 * size so that if we get remounted rw, we can return it to the same
	 * size.
	 */
	xfs_save_resvblks(mp);

	xfs_log_clean(mp);
	xfs_set_readonly(mp);

	return 0;
}

/*
 * Logically we would return an error here to prevent users from believing
 * they might have changed mount options using remount which can't be changed.
 *
 * But unfortunately mount(8) adds all options from mtab and fstab to the mount
 * arguments in some cases so we can't blindly reject options, but have to
 * check for each specified option if it actually differs from the currently
 * set option and only reject it if that's the case.
 *
 * Until that is implemented we return success for every remount request, and
 * silently ignore all options that we can't actually change.
 */
static int
xfs_fs_reconfigure(
	struct fs_context *fc)
{
	struct xfs_mount	*mp = XFS_M(fc->root->d_sb);
	struct xfs_mount        *new_mp = fc->s_fs_info;
	int			flags = fc->sb_flags;
	int			error;

	new_mp->m_qflags &= ~XFS_QFLAGS_MNTOPTS;

	/* version 5 superblocks always support version counters. */
	if (xfs_has_crc(mp))
		fc->sb_flags |= SB_I_VERSION;

	error = xfs_fs_validate_params(new_mp);
	if (error)
		return error;

	xfs_errortag_copy(mp, new_mp);

	/* Validate new max_atomic_write option before making other changes */
	if (mp->m_awu_max_bytes != new_mp->m_awu_max_bytes) {
		error = xfs_set_max_atomic_write_opt(mp,
				new_mp->m_awu_max_bytes);
		if (error)
			return error;
	}

	/* inode32 -> inode64 */
	if (xfs_has_small_inums(mp) && !xfs_has_small_inums(new_mp)) {
		mp->m_features &= ~XFS_FEAT_SMALL_INUMS;
		mp->m_maxagi = xfs_set_inode_alloc(mp, mp->m_sb.sb_agcount);
	}

	/* inode64 -> inode32 */
	if (!xfs_has_small_inums(mp) && xfs_has_small_inums(new_mp)) {
		mp->m_features |= XFS_FEAT_SMALL_INUMS;
		mp->m_maxagi = xfs_set_inode_alloc(mp, mp->m_sb.sb_agcount);
	}

	/*
	 * Now that mp has been modified according to the remount options, we
	 * do a final option validation with xfs_finish_flags() just like it is
	 * just like it is done during mount. We cannot use
	 * done during mount. We cannot use xfs_finish_flags() on new_mp as it
	 * contains only the user given options.
	 */
	error = xfs_finish_flags(mp);
	if (error)
		return error;

	/* ro -> rw */
	if (xfs_is_readonly(mp) && !(flags & SB_RDONLY)) {
		error = xfs_remount_rw(mp);
		if (error)
			return error;
	}

	/* rw -> ro */
	if (!xfs_is_readonly(mp) && (flags & SB_RDONLY)) {
		error = xfs_remount_ro(mp);
		if (error)
			return error;
	}

	return 0;
}

static void
xfs_fs_free(
	struct fs_context	*fc)
{
	struct xfs_mount	*mp = fc->s_fs_info;

	/*
	 * mp is stored in the fs_context when it is initialized.
	 * mp is transferred to the superblock on a successful mount,
	 * but if an error occurs before the transfer we have to free
	 * it here.
	 */
	if (mp)
		xfs_mount_free(mp);
}

static const struct fs_context_operations xfs_context_ops = {
	.parse_param = xfs_fs_parse_param,
	.get_tree    = xfs_fs_get_tree,
	.reconfigure = xfs_fs_reconfigure,
	.free        = xfs_fs_free,
};

/*
 * WARNING: do not initialise any parameters in this function that depend on
 * mount option parsing having already been performed as this can be called from
 * fsopen() before any parameters have been set.
 */
static int
xfs_init_fs_context(
	struct fs_context	*fc)
{
	struct xfs_mount	*mp;
	int			i;

	mp = kzalloc(sizeof(struct xfs_mount), GFP_KERNEL);
	if (!mp)
		return -ENOMEM;
#ifdef DEBUG
	mp->m_errortag = kcalloc(XFS_ERRTAG_MAX, sizeof(*mp->m_errortag),
			GFP_KERNEL);
	if (!mp->m_errortag) {
		kfree(mp);
		return -ENOMEM;
	}
#endif

	spin_lock_init(&mp->m_sb_lock);
	for (i = 0; i < XG_TYPE_MAX; i++)
		xa_init(&mp->m_groups[i].xa);
	mutex_init(&mp->m_growlock);
	mutex_init(&mp->m_metafile_resv_lock);
	INIT_WORK(&mp->m_flush_inodes_work, xfs_flush_inodes_worker);
	INIT_DELAYED_WORK(&mp->m_reclaim_work, xfs_reclaim_worker);
	mp->m_kobj.kobject.kset = xfs_kset;
	/*
	 * We don't create the finobt per-ag space reservation until after log
	 * recovery, so we must set this to true so that an ifree transaction
	 * started during log recovery will not depend on space reservations
	 * for finobt expansion.
	 */
	mp->m_finobt_nores = true;

	/*
	 * These can be overridden by the mount option parsing.
	 */
	mp->m_logbufs = -1;
	mp->m_logbsize = -1;
	mp->m_allocsize_log = 16; /* 64k */

	xfs_hooks_init(&mp->m_dir_update_hooks);

	fc->s_fs_info = mp;
	fc->ops = &xfs_context_ops;

	return 0;
}

/*
 * ccloop c7ee71c6 sess22 — P199: NAME THE INODE THAT LEAKS AT UNMOUNT.
 *
 * PROVEN DEFECT (test9, after a 32/caw board run):
 *     WARNING at fs/super.c:649 generic_shutdown_super  (busy inodes at umount)
 *     kmem_cache_destroy mxfs_inode: Slab cache still has objects
 *         when called from xfs_destroy_caches+0xc2/0x140 [mxfs]
 *     Slab objects=18 used=1
 * i.e. exactly ONE mxfs_inode survives the super teardown, the VFS refuses to
 * destroy the cache, and the node's taint goes to G B W.  A leaked slab cache
 * is a use-after-free hazard for the next insmod, so this is not cosmetic.
 *
 * The warning fires INSIDE generic_shutdown_super and names nothing — no
 * inode number, no state.  Walking the ICI radix trees immediately BEFORE
 * kill_block_super() names the survivor and prints the DLM bookkeeping that
 * would explain a retained reference (a queued bast dwork and the
 * deferred-publish list both own an igrab ref).  Read-only; RCU only; runs
 * once per unmount, so it costs nothing on any hot path.
 */
static void
mxfs_report_residual_inodes(
	struct xfs_mount		*mp)
{
	struct xfs_perag		*pag = NULL;
	int				total = 0;
	int				held = 0;

	if (!mp)
		return;

	while ((pag = xfs_perag_next(mp, pag))) {
		struct xfs_inode	*batch[32];
		uint32_t		first_index = 0;
		int			nr_found, i;

		do {
			rcu_read_lock();
			nr_found = radix_tree_gang_lookup(&pag->pag_ici_root,
					(void **)batch, first_index, 32);
			for (i = 0; i < nr_found; i++) {
				struct xfs_inode *ip = batch[i];
				struct inode	 *vip;

				if (!ip)
					continue;
				first_index = XFS_INO_TO_AGINO(mp, ip->i_ino) + 1;
				vip = VFS_I(ip);
				total++;
				/*
				 * Only a HELD reference can keep an inode alive
				 * past the VFS eviction that follows, so print
				 * just those.  (icount==0 entries are simply
				 * awaiting reclaim and are normal here — this
				 * probe runs BEFORE generic_shutdown_super's
				 * shrink_dcache/evict_inodes, so a large
				 * icount==0 population proves nothing.  Measured
				 * on a healthy 32-node unmount: 770 icount==0,
				 * 216 icount==1, 32 icount==2, zero VFS warns.)
				 */
				if (atomic_read(&vip->i_count) == 0)
					continue;
				held++;
				if (held > 16)
					continue;
				pr_warn("mxfs: P199-UNMOUNT-RESIDUAL-INODE ino=%llu icount=%d mode=0%o nlink=%u dlm_mode=%u dlm_state=%u ex_h=%u pr_h=%u pin=%u bast_pending=%d unpublished=%d iflags=0x%lx pincount=%d in_ail=%d — still in the ICI radix tree at unmount; generic_shutdown_super will report it busy\n",
					(unsigned long long)ip->i_ino,
					atomic_read(&vip->i_count),
					vip->i_mode, vip->i_nlink,
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_ex_holders,
					ip->i_dlm_pr_holders,
					ip->i_dlm_pin_count,
					ip->i_dlm_bast_pending ? 1 : 0,
					ip->i_dlm_unpublished ? 1 : 0,
					ip->i_flags,
					atomic_read(&ip->i_pincount),
					(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
						&ip->i_itemp->ili_item.li_flags)) ? 1 : 0);
			}
			rcu_read_unlock();
		} while (nr_found == 32);
	}
	if (held)
		pr_warn("mxfs: P199-UNMOUNT-RESIDUAL-TOTAL in_tree=%d still_referenced=%d (printed at most 16) — if the VFS then warns at fs/super.c generic_shutdown_super, the leak is among these\n",
			total, held);
}

static void
xfs_kill_sb(
	struct super_block		*sb)
{
	mxfs_report_residual_inodes(XFS_M(sb));
	kill_block_super(sb);
	xfs_mount_free(XFS_M(sb));
}

static struct file_system_type xfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "mxfs",
	.init_fs_context	= xfs_init_fs_context,
	.parameters		= xfs_fs_parameters,
	.kill_sb		= xfs_kill_sb,
	.fs_flags		= FS_REQUIRES_DEV | FS_ALLOW_IDMAP | FS_MGTIME |
				  FS_LBS,
};
MODULE_ALIAS_FS("mxfs");

STATIC int __init
xfs_init_caches(void)
{
	int		error;

	xfs_buf_cache = kmem_cache_create("mxfs_buf", sizeof(struct xfs_buf), 0,
					 SLAB_HWCACHE_ALIGN |
					 SLAB_RECLAIM_ACCOUNT,
					 NULL);
	if (!xfs_buf_cache)
		goto out;

	xfs_log_ticket_cache = kmem_cache_create("mxfs_log_ticket",
						sizeof(struct xlog_ticket),
						0, 0, NULL);
	if (!xfs_log_ticket_cache)
		goto out_destroy_buf_cache;

	error = xfs_btree_init_cur_caches();
	if (error)
		goto out_destroy_log_ticket_cache;

	error = rcbagbt_init_cur_cache();
	if (error)
		goto out_destroy_btree_cur_cache;

	error = xfs_defer_init_item_caches();
	if (error)
		goto out_destroy_rcbagbt_cur_cache;

	xfs_da_state_cache = kmem_cache_create("mxfs_da_state",
					      sizeof(struct xfs_da_state),
					      0, 0, NULL);
	if (!xfs_da_state_cache)
		goto out_destroy_defer_item_cache;

	xfs_ifork_cache = kmem_cache_create("mxfs_ifork",
					   sizeof(struct xfs_ifork),
					   0, 0, NULL);
	if (!xfs_ifork_cache)
		goto out_destroy_da_state_cache;

	xfs_trans_cache = kmem_cache_create("mxfs_trans",
					   sizeof(struct xfs_trans),
					   0, 0, NULL);
	if (!xfs_trans_cache)
		goto out_destroy_ifork_cache;


	/*
	 * The size of the cache-allocated buf log item is the maximum
	 * size possible under XFS.  This wastes a little bit of memory,
	 * but it is much faster.
	 */
	xfs_buf_item_cache = kmem_cache_create("mxfs_buf_item",
					      sizeof(struct xfs_buf_log_item),
					      0, 0, NULL);
	if (!xfs_buf_item_cache)
		goto out_destroy_trans_cache;

	xfs_efd_cache = kmem_cache_create("mxfs_efd_item",
			xfs_efd_log_item_sizeof(XFS_EFD_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_efd_cache)
		goto out_destroy_buf_item_cache;

	xfs_efi_cache = kmem_cache_create("mxfs_efi_item",
			xfs_efi_log_item_sizeof(XFS_EFI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_efi_cache)
		goto out_destroy_efd_cache;

	xfs_inode_cache = kmem_cache_create("mxfs_inode",
					   sizeof(struct xfs_inode), 0,
					   (SLAB_HWCACHE_ALIGN |
					    SLAB_RECLAIM_ACCOUNT |
					    SLAB_ACCOUNT),
					   xfs_fs_inode_init_once);
	if (!xfs_inode_cache)
		goto out_destroy_efi_cache;

	xfs_ili_cache = kmem_cache_create("mxfs_ili",
					 sizeof(struct xfs_inode_log_item), 0,
					 SLAB_RECLAIM_ACCOUNT,
					 NULL);
	if (!xfs_ili_cache)
		goto out_destroy_inode_cache;

	xfs_icreate_cache = kmem_cache_create("mxfs_icr",
					     sizeof(struct xfs_icreate_item),
					     0, 0, NULL);
	if (!xfs_icreate_cache)
		goto out_destroy_ili_cache;

	xfs_rud_cache = kmem_cache_create("mxfs_rud_item",
					 sizeof(struct xfs_rud_log_item),
					 0, 0, NULL);
	if (!xfs_rud_cache)
		goto out_destroy_icreate_cache;

	xfs_rui_cache = kmem_cache_create("mxfs_rui_item",
			xfs_rui_log_item_sizeof(XFS_RUI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_rui_cache)
		goto out_destroy_rud_cache;

	xfs_cud_cache = kmem_cache_create("mxfs_cud_item",
					 sizeof(struct xfs_cud_log_item),
					 0, 0, NULL);
	if (!xfs_cud_cache)
		goto out_destroy_rui_cache;

	xfs_cui_cache = kmem_cache_create("mxfs_cui_item",
			xfs_cui_log_item_sizeof(XFS_CUI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_cui_cache)
		goto out_destroy_cud_cache;

	xfs_bud_cache = kmem_cache_create("mxfs_bud_item",
					 sizeof(struct xfs_bud_log_item),
					 0, 0, NULL);
	if (!xfs_bud_cache)
		goto out_destroy_cui_cache;

	xfs_bui_cache = kmem_cache_create("mxfs_bui_item",
			xfs_bui_log_item_sizeof(XFS_BUI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_bui_cache)
		goto out_destroy_bud_cache;

	xfs_attrd_cache = kmem_cache_create("mxfs_attrd_item",
					    sizeof(struct xfs_attrd_log_item),
					    0, 0, NULL);
	if (!xfs_attrd_cache)
		goto out_destroy_bui_cache;

	xfs_attri_cache = kmem_cache_create("mxfs_attri_item",
					    sizeof(struct xfs_attri_log_item),
					    0, 0, NULL);
	if (!xfs_attri_cache)
		goto out_destroy_attrd_cache;

	xfs_iunlink_cache = kmem_cache_create("mxfs_iul_item",
					     sizeof(struct xfs_iunlink_item),
					     0, 0, NULL);
	if (!xfs_iunlink_cache)
		goto out_destroy_attri_cache;

	xfs_xmd_cache = kmem_cache_create("mxfs_xmd_item",
					 sizeof(struct xfs_xmd_log_item),
					 0, 0, NULL);
	if (!xfs_xmd_cache)
		goto out_destroy_iul_cache;

	xfs_xmi_cache = kmem_cache_create("mxfs_xmi_item",
					 sizeof(struct xfs_xmi_log_item),
					 0, 0, NULL);
	if (!xfs_xmi_cache)
		goto out_destroy_xmd_cache;

	xfs_parent_args_cache = kmem_cache_create("mxfs_parent_args",
					     sizeof(struct xfs_parent_args),
					     0, 0, NULL);
	if (!xfs_parent_args_cache)
		goto out_destroy_xmi_cache;

	return 0;

 out_destroy_xmi_cache:
	kmem_cache_destroy(xfs_xmi_cache);
 out_destroy_xmd_cache:
	kmem_cache_destroy(xfs_xmd_cache);
 out_destroy_iul_cache:
	kmem_cache_destroy(xfs_iunlink_cache);
 out_destroy_attri_cache:
	kmem_cache_destroy(xfs_attri_cache);
 out_destroy_attrd_cache:
	kmem_cache_destroy(xfs_attrd_cache);
 out_destroy_bui_cache:
	kmem_cache_destroy(xfs_bui_cache);
 out_destroy_bud_cache:
	kmem_cache_destroy(xfs_bud_cache);
 out_destroy_cui_cache:
	kmem_cache_destroy(xfs_cui_cache);
 out_destroy_cud_cache:
	kmem_cache_destroy(xfs_cud_cache);
 out_destroy_rui_cache:
	kmem_cache_destroy(xfs_rui_cache);
 out_destroy_rud_cache:
	kmem_cache_destroy(xfs_rud_cache);
 out_destroy_icreate_cache:
	kmem_cache_destroy(xfs_icreate_cache);
 out_destroy_ili_cache:
	kmem_cache_destroy(xfs_ili_cache);
 out_destroy_inode_cache:
	kmem_cache_destroy(xfs_inode_cache);
 out_destroy_efi_cache:
	kmem_cache_destroy(xfs_efi_cache);
 out_destroy_efd_cache:
	kmem_cache_destroy(xfs_efd_cache);
 out_destroy_buf_item_cache:
	kmem_cache_destroy(xfs_buf_item_cache);
 out_destroy_trans_cache:
	kmem_cache_destroy(xfs_trans_cache);
 out_destroy_ifork_cache:
	kmem_cache_destroy(xfs_ifork_cache);
 out_destroy_da_state_cache:
	kmem_cache_destroy(xfs_da_state_cache);
 out_destroy_defer_item_cache:
	xfs_defer_destroy_item_caches();
 out_destroy_rcbagbt_cur_cache:
	rcbagbt_destroy_cur_cache();
 out_destroy_btree_cur_cache:
	xfs_btree_destroy_cur_caches();
 out_destroy_log_ticket_cache:
	kmem_cache_destroy(xfs_log_ticket_cache);
 out_destroy_buf_cache:
	kmem_cache_destroy(xfs_buf_cache);
 out:
	return -ENOMEM;
}

STATIC void
xfs_destroy_caches(void)
{
	/*
	 * Make sure all delayed rcu free are flushed before we
	 * destroy caches.
	 */
	rcu_barrier();
	/*
	 * sess23 (D-UNMOUNT-BUSY-INODES): after the rcu_barrier every inode that
	 * was going to be freed has been.  Anything still on the live registry
	 * is the leak that makes the next kmem_cache_destroy(xfs_inode_cache)
	 * report "Slab cache still has objects".  Name it before we lose it.
	 */
	mxfs_report_leaked_inodes();
	kmem_cache_destroy(xfs_parent_args_cache);
	kmem_cache_destroy(xfs_xmd_cache);
	kmem_cache_destroy(xfs_xmi_cache);
	kmem_cache_destroy(xfs_iunlink_cache);
	kmem_cache_destroy(xfs_attri_cache);
	kmem_cache_destroy(xfs_attrd_cache);
	kmem_cache_destroy(xfs_bui_cache);
	kmem_cache_destroy(xfs_bud_cache);
	kmem_cache_destroy(xfs_cui_cache);
	kmem_cache_destroy(xfs_cud_cache);
	kmem_cache_destroy(xfs_rui_cache);
	kmem_cache_destroy(xfs_rud_cache);
	kmem_cache_destroy(xfs_icreate_cache);
	kmem_cache_destroy(xfs_ili_cache);
	kmem_cache_destroy(xfs_inode_cache);
	kmem_cache_destroy(xfs_efi_cache);
	kmem_cache_destroy(xfs_efd_cache);
	kmem_cache_destroy(xfs_buf_item_cache);
	kmem_cache_destroy(xfs_trans_cache);
	kmem_cache_destroy(xfs_ifork_cache);
	kmem_cache_destroy(xfs_da_state_cache);
	xfs_defer_destroy_item_caches();
	rcbagbt_destroy_cur_cache();
	xfs_btree_destroy_cur_caches();
	kmem_cache_destroy(xfs_log_ticket_cache);
	kmem_cache_destroy(xfs_buf_cache);
}

STATIC int __init
xfs_init_workqueues(void)
{
	/*
	 * The allocation workqueue can be used in memory reclaim situations
	 * (writepage path), and parallelism is only limited by the number of
	 * AGs in all the filesystems mounted. Hence use the default large
	 * max_active value for this workqueue.
	 */
	xfs_alloc_wq = alloc_workqueue("xfsalloc", XFS_WQFLAGS(WQ_MEM_RECLAIM | WQ_FREEZABLE | WQ_PERCPU),
			0);
	if (!xfs_alloc_wq)
		return -ENOMEM;

	xfs_discard_wq = alloc_workqueue("xfsdiscard", XFS_WQFLAGS(WQ_UNBOUND),
			0);
	if (!xfs_discard_wq)
		goto out_free_alloc_wq;

	return 0;
out_free_alloc_wq:
	destroy_workqueue(xfs_alloc_wq);
	return -ENOMEM;
}

STATIC void
xfs_destroy_workqueues(void)
{
	destroy_workqueue(xfs_discard_wq);
	destroy_workqueue(xfs_alloc_wq);
}

/* ─── v5 sess33: dynamic cache sizing module parameters ───────────────────
 *
 * mxfs auto-sizes per-mount caches from host RAM at module load.  Total
 * cache budget is `min(host_ram * cache_mem_pct / 100,
 * cache_mem_max_mb * 1MB)`.  That budget is split across the caches.
 * Each cache also has an explicit override module param — setting it
 * nonzero overrides the auto-sized default.
 *
 * Heuristic split (tuned for typical FS workloads):
 *   inode cache    70 %   (~768 B/entry  → biggest cache)
 *   dlm CAW locks  matches inode count   (~48 B/entry — 1:1 with cached inodes)
 *   dir cache      inode/8 entries        (~1 KB/entry)
 *   block cache    20 %                   (~4 KB/entry)
 *
 * Computed once at module init, reused by all mounts that don't
 * override via per-mount mount option.
 *
 * (Ported from mxfs.1 sess74; v5 only the dlm_lock cap is currently
 * wired through to live code via mxfs_v5_dlm_opts.max_dlm_lock_caw,
 * since v5's inode/dir/block caches are upstream XFS's slab caches.
 * The other caps are exposed for forward compatibility and parity with
 * the mxfs.1 module-param interface.)
 */
module_param_named(legacy_rw, mxfs_legacy_rw, uint, 0644);
MODULE_PARM_DESC(legacy_rw,
	"Allow RW mount of a legacy (pre-protogate) MXFS cluster format "
	"(UNSAFE: pre-gate kernels can join undetected for seconds; "
	"default 0 = refuse, run chk_mxfs --upgrade-protogate instead).");

static unsigned int mxfs_cache_mem_pct = 10;
module_param_named(cache_mem_pct, mxfs_cache_mem_pct, uint, 0644);
MODULE_PARM_DESC(cache_mem_pct,
	"Percentage of host RAM available as total cache budget (1-50, default 10).");

static unsigned int mxfs_cache_mem_max_mb = 16384;	/* 16 GB */
module_param_named(cache_mem_max_mb, mxfs_cache_mem_max_mb, uint, 0644);
MODULE_PARM_DESC(cache_mem_max_mb,
	"Hard cap on total cache budget, in MB (default 16384 = 16 GB).");

static unsigned int mxfs_inode_cache_max;
module_param_named(inode_cache_max, mxfs_inode_cache_max, uint, 0644);
MODULE_PARM_DESC(inode_cache_max,
	"Max cached inodes per mount (0 = auto from cache_mem_pct).");

static unsigned int mxfs_dlm_lock_max;
module_param_named(dlm_lock_max, mxfs_dlm_lock_max, uint, 0644);
MODULE_PARM_DESC(dlm_lock_max,
	"Max held CAW DLM locks per mount (0 = match inode_cache_max, "
	"capped at on-disk MXFS_CAW_MAX_SLOTS=65536).");

static unsigned int mxfs_dir_cache_max;
module_param_named(dir_cache_max, mxfs_dir_cache_max, uint, 0644);
MODULE_PARM_DESC(dir_cache_max,
	"Max cached directories per mount (0 = auto, ~ inode_cache_max / 8).");

static unsigned int mxfs_block_cache_max;
module_param_named(block_cache_max, mxfs_block_cache_max, uint, 0644);
MODULE_PARM_DESC(block_cache_max,
	"Max cached 4 KB blocks per mount (0 = auto from cache_mem_pct).");

module_param_named(dead_timeout_ms, mxfs_dead_timeout_ms, uint, 0644);
MODULE_PARM_DESC(dead_timeout_ms,
	"Dead-node detection window in ms (0 = 62 s default). Gates lock "
	"purge + foreign log-slice replay after a peer dies.  This is the "
	"DISKLOCK heartbeat threshold; the lease timeout is separate, fixed "
	"at 600 s, and deliberately does not track it.");
/* Deprecated alias — see the comment on mxfs_dead_timeout_ms.  It never
 * configured the lease despite the name; dead_timeout_ms wins if both set. */
module_param_named(lease_timeout_ms, mxfs_lease_timeout_ms, uint, 0644);
MODULE_PARM_DESC(lease_timeout_ms,
	"DEPRECATED alias for dead_timeout_ms.  Never configured the lease.");

unsigned int mxfs_open_tracking = 1;
module_param_named(open_tracking, mxfs_open_tracking, uint, 0644);
MODULE_PARM_DESC(open_tracking,
	"sess40 cross-node open-unlink protection: 1 (default) = publish an "
	"open-holder bit when releasing a still-open inode under BAST, and "
	"defer a peer-open unlinked inode's destructive inactivation; 0 = "
	"pre-sess40 behaviour (A/B control; a peer's unlink then destroys "
	"data under a live fd).");

unsigned int mxfs_inocl_fence = 1;
module_param_named(inocl_fence, mxfs_inocl_fence, uint, 0644);
MODULE_PARM_DESC(inocl_fence,
	"sess47 inode-cluster time-travel fence: 1 (default) = device flush "
	"before a cold inode-cluster read inside an unflushed write window "
	"(sibling of the sess6 AG-meta fence; closes the fossil "
	"di_next_unlinked producer, P53-IUNLINK-MISMATCH); 0 = report-only "
	"(A/B control).");

extern unsigned int mxfs_caw_probe_span_enable;
module_param_named(caw_probe_span_enable, mxfs_caw_probe_span_enable, uint, 0644);
MODULE_PARM_DESC(caw_probe_span_enable,
	"CAW slot-probe multi-slot read window: 0 (default) = per-slot reads "
	"only; 1 = re-enable the 16-slot span read, which is PROVEN to return "
	"data disagreeing with a per-slot read of the same LBA "
	"(P94-SPAN-DISAGREE) and is retained only as an A/B control.");

extern unsigned int mxfs_iunlink_slot_buckets;
module_param_named(iunlink_slot_buckets, mxfs_iunlink_slot_buckets, uint, 0644);
MODULE_PARM_DESC(iunlink_slot_buckets,
	"Multi-node AGI unlinked-list bucket choice: 1 (default) = this "
	"node's disklock slot (private per-node buckets — cross-node zombie "
	"adjacency structurally impossible); 0 = legacy agino%64 hashing "
	"(A/B control). MUST be uniform across the cluster; removals of "
	"entries inserted under the other setting stay correct via the "
	"per-inode recorded bucket.");

/*
 * Conservative per-entry size estimates (bytes).  Better to slightly
 * over-budget than to under-allocate and hit the cap mid-workload.
 */
#define MXFS_INODE_ENTRY_BYTES		768
#define MXFS_DIR_ENTRY_BYTES		1024
#define MXFS_BLOCK_ENTRY_BYTES		4160
#define MXFS_DLM_LOCK_ENTRY_BYTES	48

#define MXFS_CACHE_FLOOR_INODE		8192
#define MXFS_CACHE_FLOOR_DLM_LOCK	4096
#define MXFS_CACHE_FLOOR_DIR		1024
#define MXFS_CACHE_FLOOR_BLOCK		4096

#define MXFS_DLM_LOCK_HARD_CAP		65536	/* matches MXFS_CAW_MAX_SLOTS */

static void mxfs_compute_cache_caps(void)
{
	u64 ram_bytes;
	u64 max_bytes;
	u64 budget;

	if (mxfs_cache_mem_pct < 1)
		mxfs_cache_mem_pct = 1;
	if (mxfs_cache_mem_pct > 50)
		mxfs_cache_mem_pct = 50;

	ram_bytes = (u64)totalram_pages() << PAGE_SHIFT;
	max_bytes = (u64)mxfs_cache_mem_max_mb << 20;

	budget = (ram_bytes / 100) * mxfs_cache_mem_pct;
	if (budget > max_bytes)
		budget = max_bytes;

	if (mxfs_inode_cache_max > 0)
		mxfs_cache_caps.inode = (int)mxfs_inode_cache_max;
	else
		mxfs_cache_caps.inode = (int)((budget * 70 / 100) /
					      MXFS_INODE_ENTRY_BYTES);
	if (mxfs_cache_caps.inode < MXFS_CACHE_FLOOR_INODE)
		mxfs_cache_caps.inode = MXFS_CACHE_FLOOR_INODE;

	if (mxfs_dlm_lock_max > 0)
		mxfs_cache_caps.dlm_lock = (int)mxfs_dlm_lock_max;
	else
		mxfs_cache_caps.dlm_lock = mxfs_cache_caps.inode;
	if (mxfs_cache_caps.dlm_lock < MXFS_CACHE_FLOOR_DLM_LOCK)
		mxfs_cache_caps.dlm_lock = MXFS_CACHE_FLOOR_DLM_LOCK;
	if (mxfs_cache_caps.dlm_lock > MXFS_DLM_LOCK_HARD_CAP)
		mxfs_cache_caps.dlm_lock = MXFS_DLM_LOCK_HARD_CAP;

	if (mxfs_dir_cache_max > 0)
		mxfs_cache_caps.dir = (int)mxfs_dir_cache_max;
	else
		mxfs_cache_caps.dir = mxfs_cache_caps.inode / 8;
	if (mxfs_cache_caps.dir < MXFS_CACHE_FLOOR_DIR)
		mxfs_cache_caps.dir = MXFS_CACHE_FLOOR_DIR;

	if (mxfs_block_cache_max > 0)
		mxfs_cache_caps.block = (int)mxfs_block_cache_max;
	else
		mxfs_cache_caps.block = (int)((budget * 20 / 100) /
					      MXFS_BLOCK_ENTRY_BYTES);
	if (mxfs_cache_caps.block < MXFS_CACHE_FLOOR_BLOCK)
		mxfs_cache_caps.block = MXFS_CACHE_FLOOR_BLOCK;

	pr_info("mxfs: cache sizing: ram=%llu MB pct=%u%% max=%u MB budget=%llu MB\n",
		(unsigned long long)(ram_bytes >> 20),
		mxfs_cache_mem_pct, mxfs_cache_mem_max_mb,
		(unsigned long long)(budget >> 20));
	pr_info("mxfs: cache caps: inode=%d dlm_lock=%d dir=%d block=%d\n",
		mxfs_cache_caps.inode, mxfs_cache_caps.dlm_lock,
		mxfs_cache_caps.dir, mxfs_cache_caps.block);
	pr_info("mxfs: cache memory estimate: %llu MB "
		"(inode %d, dlm %d, dir %d, block %d)\n",
		(unsigned long long)(((u64)mxfs_cache_caps.inode * MXFS_INODE_ENTRY_BYTES +
		                      (u64)mxfs_cache_caps.dlm_lock * MXFS_DLM_LOCK_ENTRY_BYTES +
		                      (u64)mxfs_cache_caps.dir * MXFS_DIR_ENTRY_BYTES +
		                      (u64)mxfs_cache_caps.block * MXFS_BLOCK_ENTRY_BYTES) >> 20),
		mxfs_cache_caps.inode, mxfs_cache_caps.dlm_lock,
		mxfs_cache_caps.dir, mxfs_cache_caps.block);
}

/* dlm/net2.h is not included here (upstream-fork glue) — declare the
 * gate-2 smoke selftest hooks directly, mxfs_pal_sdev_cache_release
 * convention. */
void mxfs_net2_selftest_maybe_start(void);
void mxfs_net2_selftest_stop(void);

STATIC int __init
init_xfs_fs(void)
{
	int			error;

	xfs_check_ondisk_structs();

	error = xfs_dahash_test();
	if (error)
		return error;

	printk(KERN_INFO XFS_VERSION_STRING " with "
			 XFS_BUILD_OPTIONS " enabled\n");

	/* v0.5.0: insmod-time param echo — "after 31 checks" in a test log
	 * with this reading nonzero means the param was lost in plumbing,
	 * not in insmod (sess18: a silently-failed insmod on an
	 * already-loaded module swallows params). */
	if (mxfs_lease_timeout_ms && !mxfs_dead_timeout_ms)
		printk(KERN_WARNING "mxfs: lease_timeout_ms=%u is DEPRECATED and "
		       "has never configured the lease — it is the disklock "
		       "dead-detection threshold.  Use dead_timeout_ms.  The "
		       "lease timeout stays 600000 ms by design (sess43).\n",
		       mxfs_lease_timeout_ms);
	printk(KERN_INFO "mxfs: dead_timeout_ms=%u (0 = 62s default)\n",
	       mxfs_resolve_dead_timeout_ms());

	mxfs_compute_cache_caps();

	xfs_dir_startup();

	error = xfs_init_caches();
	if (error)
		goto out;

	error = xfs_init_workqueues();
	if (error)
		goto out_destroy_caches;

	error = xfs_mru_cache_init();
	if (error)
		goto out_destroy_wq;

	error = xfs_init_procfs();
	if (error)
		goto out_mru_cache_uninit;

	error = xfs_sysctl_register();
	if (error)
		goto out_cleanup_procfs;

	xfs_debugfs = xfs_debugfs_mkdir("mxfs", NULL);

	xfs_kset = kset_create_and_add("mxfs", NULL, fs_kobj);
	if (!xfs_kset) {
		error = -ENOMEM;
		goto out_debugfs_unregister;
	}

	xfsstats.xs_kobj.kobject.kset = xfs_kset;

	xfsstats.xs_stats = alloc_percpu(struct xfsstats);
	if (!xfsstats.xs_stats) {
		error = -ENOMEM;
		goto out_kset_unregister;
	}

	error = xfs_sysfs_init(&xfsstats.xs_kobj, &xfs_stats_ktype, NULL,
			       "stats");
	if (error)
		goto out_free_stats;

	error = xchk_global_stats_setup(xfs_debugfs);
	if (error)
		goto out_remove_stats_kobj;

#ifdef DEBUG
	xfs_dbg_kobj.kobject.kset = xfs_kset;
	error = xfs_sysfs_init(&xfs_dbg_kobj, &xfs_dbg_ktype, NULL, "debug");
	if (error)
		goto out_remove_scrub_stats;
#endif

	error = xfs_qm_init();
	if (error)
		goto out_remove_dbg_kobj;

	error = register_filesystem(&xfs_fs_type);
	if (error)
		goto out_qm_exit;
	mxfs_net2_selftest_maybe_start();
	mxfs_lru_sweep_start();	/* sess39: stranded-inode repatriation */
	return 0;

 out_qm_exit:
	xfs_qm_exit();
 out_remove_dbg_kobj:
#ifdef DEBUG
	xfs_sysfs_del(&xfs_dbg_kobj);
 out_remove_scrub_stats:
#endif
	xchk_global_stats_teardown();
 out_remove_stats_kobj:
	xfs_sysfs_del(&xfsstats.xs_kobj);
 out_free_stats:
	free_percpu(xfsstats.xs_stats);
 out_kset_unregister:
	kset_unregister(xfs_kset);
 out_debugfs_unregister:
	debugfs_remove(xfs_debugfs);
	xfs_sysctl_unregister();
 out_cleanup_procfs:
	xfs_cleanup_procfs();
 out_mru_cache_uninit:
	xfs_mru_cache_uninit();
 out_destroy_wq:
	xfs_destroy_workqueues();
 out_destroy_caches:
	xfs_destroy_caches();
 out:
	return error;
}

/* pal/pal.h is not included here (upstream-fork glue) — declare directly. */
void mxfs_pal_sdev_cache_release(void);

STATIC void __exit
exit_xfs_fs(void)
{
	mxfs_lru_sweep_stop();	/* sess39: before teardown — the sweep touches sb inodes */
	mxfs_net2_selftest_stop();
	xfs_qm_exit();
	unregister_filesystem(&xfs_fs_type);
	mxfs_pal_sdev_cache_release();
#ifdef DEBUG
	xfs_sysfs_del(&xfs_dbg_kobj);
#endif
	xchk_global_stats_teardown();
	xfs_sysfs_del(&xfsstats.xs_kobj);
	free_percpu(xfsstats.xs_stats);
	kset_unregister(xfs_kset);
	debugfs_remove(xfs_debugfs);
	xfs_sysctl_unregister();
	xfs_cleanup_procfs();
	xfs_mru_cache_uninit();
	xfs_destroy_workqueues();
	xfs_destroy_caches();
	xfs_uuid_table_free();
}

module_init(init_xfs_fs);
module_exit(exit_xfs_fs);

MODULE_AUTHOR("Steve");
MODULE_DESCRIPTION("MXFS — Multinode XFS with " XFS_BUILD_OPTIONS " enabled");
MODULE_LICENSE("GPL");
