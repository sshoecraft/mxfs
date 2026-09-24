// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */

#include "xfs_platform.h"
#include <linux/namei.h>
#include <linux/random.h>	/* sess482: affine fast-path audit sampling */
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_bit.h"		/* 0.88.0: XFS_FSB_TO_DADDR for the slice lifecycle claim */
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_iops.h"
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
#include "xfs_relmark_item.h"	/* sess403: clean-release marker item cache */
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
#include "xfs_health.h"		/* sess475: xfs_fs_mark_sick (SB summary seal) */
#include "scrub/stats.h"
#include "scrub/rcbag_btree.h"

#include <mxfs/mxfs_super.h>
#include <mxfs/mxfs_tauth.h>	/* sess421: MXFS_TAUTH_REGION_BYTES */
#include "../../dlm/v5_mount.h"
#include "../../dlm/disklock.h"	/* the authority object the write gate asks */
#include "../../dlm/hostid.h"	/* sess437: host/boot identity at module init */
#include "../../xfs/xfs_mxfs_dlm.h"
#include <linux/magic.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/inet.h>		/* in4_pton: peers= */
#include <linux/in.h>		/* ipv4_is_multicast et al.: peers= */
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
	Opt_peer, Opt_peers, Opt_cluster,
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
	fsparam_string("peer",		Opt_peer),
	fsparam_string("peers",		Opt_peers),
	fsparam_string("cluster",	Opt_cluster),
	{}
};

/*
 * peer=ADDR (repeatable) and peers=ADDR[/ADDR...]: IPv4 addresses to unicast
 * every discovery, lease and nudge datagram to (dlm/static_peers.h).  peer=
 * adds them to multicast discovery; peers= makes the list the whole cluster,
 * replacing multicast and dropping everyone else.  Both add to one list, so a
 * repeated option extends it rather than replacing it, and any peers= makes
 * the whole list exclusive.  Within one value addresses are separated by '/',
 * because the mount option string itself is split on ','.  Stored canonical
 * (dotted, as the socket layer reports a sender) so a receiver's admit check
 * is a string compare.  A multicast, broadcast or unspecified address is
 * refused: none of them names one node.  Duplicates collapse.
 */
static int
mxfs_parse_peers(
	struct xfs_mount	*mp,
	const char		*arg,
	bool			exclusive)
{
	struct mxfs_static_peers *p;
	const char		*opt = exclusive ? "peers=" : "peer=";
	char			*copy, *cur, *tok;
	uint32_t		given = 0;
	int			error = 0;

	/* Build on a copy of the list so far; a bad address leaves it as it was. */
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	copy = kstrdup(arg, GFP_KERNEL);
	if (!p || !copy) {
		error = -ENOMEM;
		goto out;
	}
	if (mp->m_mxfs_peers)
		*p = *mp->m_mxfs_peers;
	if (exclusive)
		p->exclusive = true;
	cur = copy;
	while ((tok = strsep(&cur, "/")) != NULL) {
		__be32		ip;
		const char	*end;
		char		canon[MXFS_PEER_ADDR_LEN];
		uint32_t	i;

		if (!*tok)
			continue;
		if (!in4_pton(tok, -1, (u8 *)&ip, '\0', &end) ||
		    ipv4_is_multicast(ip) || ipv4_is_lbcast(ip) ||
		    ipv4_is_zeronet(ip)) {
			xfs_warn(mp, "%s: '%s' is not a unicast IPv4 address",
				 opt, tok);
			error = -EINVAL;
			goto out;
		}
		given++;
		snprintf(canon, sizeof(canon), "%pI4", &ip);
		for (i = 0; i < p->count; i++)
			if (!strcmp(p->addr[i], canon))
				break;
		if (i < p->count)
			continue;
		if (p->count >= MXFS_MAX_NODES) {
			xfs_warn(mp, "%s: more than %d addresses in all",
				 opt, MXFS_MAX_NODES);
			error = -EINVAL;
			goto out;
		}
		strscpy(p->addr[p->count++], canon, MXFS_PEER_ADDR_LEN);
	}
	if (!given) {
		xfs_warn(mp, "%s: no address given", opt);
		error = -EINVAL;
		goto out;
	}
	kfree(mp->m_mxfs_peers);
	mp->m_mxfs_peers = p;
	p = NULL;
out:
	kfree(copy);
	kfree(p);
	return error;
}

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
	if (mp->m_mxfs_cluster_name)
		seq_show_option(m, "cluster", mp->m_mxfs_cluster_name);
	if (mp->m_mxfs_peers) {
		const struct mxfs_static_peers *sp = mp->m_mxfs_peers;
		uint32_t i;

		/* Show the mode in effect: one exclusive peers= list, or
		 * one additive peer= per address. */
		for (i = 0; i < sp->count; i++) {
			if (sp->exclusive)
				seq_printf(m, "%s%s", i ? "/" : ",peers=",
					   sp->addr[i]);
			else
				seq_printf(m, ",peer=%s", sp->addr[i]);
		}
	}

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

	/* 0.75.34 (D-0536): node-local order of the SB summary critical section. */
	mutex_init(&mp->m_mxfs_sb_summary_mutex);
	mp->m_mxfs_sb_cover_durable = false;

	/* sess43 deferred-publish: per-node unpublished-inode list. */
	INIT_LIST_HEAD(&mp->m_mxfs_unpub_list);
	atomic_set(&mp->m_mxfs_pubdrain_active, 0);
	spin_lock_init(&mp->m_mxfs_unpub_lock);

	/* sess324 (D-513): victim-domain quarantine map.  The map fields are
	 * kzalloc-zero (= nothing quarantined) which the lockless readers
	 * rely on; only the writer lock needs explicit init. */
	spin_lock_init(&mp->m_mxfs_quar_lock);
	/* 0.85.0: the obligation freeze (see xfs_mount.h) */
	spin_lock_init(&mp->m_mxfs_oblf_lock);
	init_waitqueue_head(&mp->m_mxfs_oblf_wq);
	/*
	 * sess383: the mount is ADMITTING from the moment the quarantine map
	 * exists, not merely from DLM registration.  The recovery barrier
	 * imports verdicts too, and labelling those "ADMITTED" in
	 * P240-QUAR-IMPORT misdescribes the one thing that line exists to tell
	 * an operator: whether the mount that saw this quarantine could still
	 * be refused.  Cleared exactly once, by mxfs_dlm_admission_commit().
	 */
	mp->m_mxfs_quar_admitting = true;
	/* v0.5.4 sess24: background dir-slot publisher (runs on
	 * m_mxfs_inode_bast_wq; flushed with it at put_super). */
	INIT_WORK(&mp->m_mxfs_publish_work, mxfs_dlm_publish_dirs_work);
	/* ccloop c7ee71c6 sess2: coalesced destage kick (see xfs_mount.h). */
	{
		extern void mxfs_destage_kick_fn(struct work_struct *);
		INIT_DELAYED_WORK(&mp->m_mxfs_destage_kick,
				  mxfs_destage_kick_fn);
	}

	/* sess227 F4: committed-never-submitted obligation registry. */
	mxfs_f4_registry_init(mp);

	/* sess256 step-5 F3: keyed inode-cluster write registry. */
	mxfs_icwr_registry_init(mp);

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

	/* sess227 F4: all buffers and workers are gone — emit the
	 * F4-REGISTRY-TOTAL conservation line and free orphaned records. */
	mxfs_f4_registry_destroy(mp);

	/* sess256 step-5 F3: same lifecycle for the keyed inode-cluster
	 * write registry (entries deliberately live until here). */
	mxfs_icwr_registry_destroy(mp);
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

	/*
	 * An incarnation revocation queued with an inode reference has not
	 * run, yet the inode is being evicted: that reference was dropped by
	 * someone else, and the worker's own release will then hit a freed
	 * inode (the iput BUG).  The stack below is the final iput — it
	 * names the path that dropped one reference too many.
	 */
	if (unlikely(atomic_read(&XFS_I(inode)->i_mxfs_revoke_refs) > 0)) {
		pr_warn("mxfs: P-REVOKE-EVICT-EARLY ino=%llu gen=%u revoke_refs=%d i_state=0x%lx — evicted while a queued revocation still owns a reference\n",
			(unsigned long long)XFS_I(inode)->i_ino,
			inode->i_generation,
			atomic_read(&XFS_I(inode)->i_mxfs_revoke_refs),
			mxfs_istate(inode));
		dump_stack();
	}

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
	kfree(mp->m_mxfs_peers);
	kfree(mp->m_mxfs_cluster_name);
#ifdef DEBUG
	kfree(mp->m_errortag);
#endif
	/* sess454 (D4): the mount's reference on the departure accounting
	 * object; buffers that still hold tokens keep theirs. */
	mxfs_depart_acct_put(mp->m_mxfs_acct);
	mp->m_mxfs_acct = NULL;
	/*
	 * The authority object goes last.  Every producer, workqueue, timer
	 * and I/O completion of this incarnation is gone by the time the mount
	 * is freed, so this is the first point at which no work can still need
	 * to ask whether it was allowed to write.
	 */
	mxfs_authority_put(mp->m_mxfs_auth);
	mp->m_mxfs_auth = NULL;
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
							   30, 10, 0);
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

/*
 * sess454/455 (0.61.0, D2/D3/D4): the departure I/O gate — see struct
 * mxfs_depart_acct (xfs_mount.h).
 *
 * The drain after the freeze waits for every admitted token and every
 * pending rejection, UNCAPPED, one loud round at a time.  Derived, not
 * chosen: every xfs_buf submission that precedes the freeze was WAITED FOR
 * by xfs_unmountfs (synchronous log quiesce, AIL push, buftarg drain — a
 * buffer with I/O in flight holds b_hold) and the final device flush has
 * just returned, so at the freeze the count is zero on every healthy path
 * and nothing is waited for at all.  A nonzero count is therefore itself
 * an accounting or lifetime violation (D4), and the sess455 ruling is
 * explicit that tearing the mount down under it — the mount, its
 * workqueues, the buffer — frees exactly what the late completion will
 * touch; keeping only the accounting object alive is not enough.  So we
 * wait, as upstream's xfs_buftarg_drain waits, and say so every round.
 * The one exception is a CORRUPT account (under/overflow or an orphan):
 * its count cannot be trusted and a freed buffer's completion can never
 * come, so after one bounded round the departure is abandoned DIRTY.
 */
#define MXFS_DEPARTURE_DRAIN_ROUND_MS	2000

/*
 * D4 injector (dbg_depart_late_token_ms): one extra token, taken at the
 * freeze and retired N ms later from system_wq.  It proves the drain
 * WAITS for an outstanding token (umount wall grows by N, one STALL line
 * per round) and that the departure then completes CLEAN — a real buffer
 * cannot be made to complete after the freeze on a healthy unmount, because
 * xfs_unmountfs waits for it first; this is an account-lifetime test, not
 * a post-teardown late-I/O test (no teardown happens while a token is
 * outstanding).  Pending injectors are kept on a list so module exit can
 * cancel or run each one safely.
 */
uint32_t mxfs_pal_dbg_depart_late_token_take(void);	/* pal/pal.h not included here */
/* pal/linux/lureset.c — the witnessed LOGICAL UNIT RESET's report channel.
 * pal/pal.h is not included in this upstream-fork glue file. */
int mxfs_pal_lu_reset_init(void);
void mxfs_pal_lu_reset_exit(void);
struct mxfs_depart_late_token {
	struct delayed_work	work;
	struct list_head	node;
	struct mxfs_depart_acct	*acct;
	unsigned int		ms;
};
static LIST_HEAD(mxfs_depart_late_list);
static DEFINE_SPINLOCK(mxfs_depart_late_lock);

static void
mxfs_depart_late_token_retire(
	struct mxfs_depart_late_token *lt,
	const char		*how)
{
	struct mxfs_depart_acct	*acct = lt->acct;
	int			now, stage;
	bool			after;

	spin_lock(&acct->lock);
	if (acct->inflight > 0)
		acct->inflight--;
	else
		acct->corrupt = true;
	now = acct->inflight;
	stage = acct->stage;
	after = acct->after_freeze;
	if (acct->inflight == 0 && acct->rejected_pending == 0)
		wake_up_all(&acct->wq);
	spin_unlock(&acct->lock);
	pr_err("mxfs: P-DBG-DEPART-LATE-TOKEN-RETIRED %s after %u ms: inflight_now=%d acct_refs=%u stage=%d after_freeze=%d\n",
	       how, lt->ms, now, refcount_read(&acct->ref), stage, after ? 1 : 0);
	mxfs_depart_acct_put(acct);	/* the token's reference */
	kfree(lt);
}

static void
mxfs_depart_late_token_fn(
	struct work_struct	*w)
{
	struct mxfs_depart_late_token *lt =
		container_of(to_delayed_work(w), struct mxfs_depart_late_token, work);

	spin_lock(&mxfs_depart_late_lock);
	list_del_init(&lt->node);
	spin_unlock(&mxfs_depart_late_lock);
	mxfs_depart_late_token_retire(lt, "by the delayed work");
}

/* Called with acct->lock held, at the freeze. */
static void
mxfs_depart_late_token_arm(
	struct mxfs_depart_acct	*acct)
{
	uint32_t		ms = mxfs_pal_dbg_depart_late_token_take();
	struct mxfs_depart_late_token *lt;

	if (!ms)
		return;
	lt = kzalloc(sizeof(*lt), GFP_ATOMIC);
	if (!lt) {
		pr_err("mxfs: P-DBG-DEPART-LATE-TOKEN alloc failed; injector NOT armed\n");
		return;
	}
	lt->acct = acct;
	lt->ms = ms;
	INIT_LIST_HEAD(&lt->node);
	INIT_DELAYED_WORK(&lt->work, mxfs_depart_late_token_fn);
	refcount_inc(&acct->ref);
	acct->inflight++;
	acct->submitted++;
	spin_lock(&mxfs_depart_late_lock);
	list_add_tail(&lt->node, &mxfs_depart_late_list);
	spin_unlock(&mxfs_depart_late_lock);
	pr_err("mxfs: P-DBG-DEPART-LATE-TOKEN armed: one extra token, retired in %u ms (inflight=%d) — the drain must WAIT for it and the departure must then complete clean\n",
	       ms, acct->inflight);
	if (!schedule_delayed_work(&lt->work, msecs_to_jiffies(ms))) {
		/* cannot happen for a fresh work item; unwind rather than hang */
		spin_lock(&mxfs_depart_late_lock);
		list_del_init(&lt->node);
		spin_unlock(&mxfs_depart_late_lock);
		acct->inflight--;
		refcount_dec(&acct->ref);
		kfree(lt);
		pr_err("mxfs: P-DBG-DEPART-LATE-TOKEN schedule failed; injector unwound\n");
	}
}

/*
 * Module exit: no pending late token may fire into unloaded text.  Each
 * item is unlinked under the lock, then cancelled; a cancelled item is
 * retired here, one that already started is finished by the work itself
 * (cancel_delayed_work_sync waited for it) and is not touched again.
 */
static void
mxfs_depart_late_token_exit(void)
{
	struct mxfs_depart_late_token *lt;

	for (;;) {
		spin_lock(&mxfs_depart_late_lock);
		lt = list_first_entry_or_null(&mxfs_depart_late_list,
					      struct mxfs_depart_late_token, node);
		if (lt)
			list_del_init(&lt->node);
		spin_unlock(&mxfs_depart_late_lock);
		if (!lt)
			break;
		if (cancel_delayed_work_sync(&lt->work))
			mxfs_depart_late_token_retire(lt, "at module exit");
	}
}

/*
 * FREEZE, then drain what was admitted before the transition (D2).  From
 * the moment stage reaches FROZEN under acct->lock, xfs_buf_submit_bio
 * rejects every submission attributable to this mount (-EIO through the
 * normal completion path, after_freeze recorded).  Waits uncapped for the
 * admitted tokens and the pending rejections (see the header comment);
 * returns false only for a CORRUPT account, which makes the departure
 * DIRTY.
 */
static bool
mxfs_departure_freeze_drain(
	struct xfs_mount	*mp,
	const char		*where)
{
	struct mxfs_depart_acct	*acct = mp->m_mxfs_acct;
	int			inflight, rp, rounds = 0;
	bool			corrupt;

	if (!acct)
		return true;
	spin_lock(&acct->lock);
	acct->stage = MXFS_DEPARTURE_FROZEN;
	mxfs_depart_late_token_arm(acct);
	inflight = acct->inflight;
	rp = acct->rejected_pending;
	corrupt = acct->corrupt;
	spin_unlock(&acct->lock);
	if (inflight == 0 && rp == 0)
		return !corrupt;
	xfs_notice(mp,
"MXFS: P304-RETIRE-DRAIN at=%s inflight=%d rejected_pending=%d corrupt=%d — tokens admitted before the freeze still outstanding; waiting for them",
		   where, inflight, rp, corrupt ? 1 : 0);
	for (;;) {
		wait_event_timeout(acct->wq,
				   READ_ONCE(acct->inflight) == 0 &&
				   READ_ONCE(acct->rejected_pending) == 0,
				   msecs_to_jiffies(MXFS_DEPARTURE_DRAIN_ROUND_MS));
		rounds++;
		spin_lock(&acct->lock);
		inflight = acct->inflight;
		rp = acct->rejected_pending;
		corrupt = acct->corrupt;
		if (inflight || rp)
			acct->stalls++;
		spin_unlock(&acct->lock);
		if (inflight == 0 && rp == 0) {
			xfs_notice(mp,
"MXFS: P304-RETIRE-DRAINED at=%s after %d round(s) of %d ms — every token retired; departure may proceed%s",
				   where, rounds, MXFS_DEPARTURE_DRAIN_ROUND_MS,
				   corrupt ? " (account CORRUPT: DIRTY regardless)" : "");
			return !corrupt;
		}
		if (corrupt) {
			xfs_alert(mp,
"MXFS: P304-RETIRE-DRAIN-ABANDONED at=%s inflight=%d rejected_pending=%d after %d round(s) — the accounting is CORRUPT (under/overflow or an orphaned buffer), the count cannot be trusted and a freed buffer's completion can never come; departure DIRTY (slot ACTIVE, PR key retained as fence target), the accounting object stays pinned",
				  where, inflight, rp, rounds);
			return false;
		}
		xfs_alert(mp,
"MXFS: P304-RETIRE-DRAIN-STALL at=%s inflight=%d rejected_pending=%d after %d round(s) of %d ms — buffer I/O admitted before the freeze has not completed although xfs_unmountfs returned (a D4 accounting/lifetime violation: investigate); still waiting, the mount is not torn down under it",
			  where, inflight, rp, rounds, MXFS_DEPARTURE_DRAIN_ROUND_MS);
	}
}

/*
 * sess452/454: the departure quiescence assertion, read under the
 * accounting lock AFTER the teardown that follows the freeze (D3: freesb,
 * workqueues, xfs_shutdown_devices), so anything they submitted shows up
 * as after_freeze.  Returns true only when no token is outstanding, no
 * dir-write token is outstanding, nothing was submitted after the freeze
 * and the accounting was never found corrupt.  One greppable line either
 * way; a false answer makes the departure DIRTY.
 */
static bool
mxfs_departure_quiesced(
	struct xfs_mount	*mp,
	const char		*where)
{
	struct mxfs_depart_acct	*acct = mp->m_mxfs_acct;
	int	dirwr = atomic_read(&mp->m_mxfs_dir_wr_inflight);
	int	inflight = 0, rp = 0, stage = MXFS_DEPARTURE_FROZEN;
	unsigned long submitted = 0, rejected = 0, stalls = 0, untokened = 0;
	unsigned long soft = 0, carried = 0;
	bool	after = false, corrupt = false, ok;

	if (acct) {
		spin_lock(&acct->lock);
		inflight = acct->inflight;
		rp = acct->rejected_pending;
		stage = acct->stage;
		after = acct->after_freeze;
		corrupt = acct->corrupt;
		submitted = acct->submitted;
		rejected = acct->rejected;
		stalls = acct->stalls;
		untokened = acct->untokened;
		soft = acct->soft;
		carried = acct->carried;
		spin_unlock(&acct->lock);
	}
	/*
	 * sess459 (review #5 STOP-SHIP, condition 8): an UNTOKENED terminal
	 * completion is provenance the gate could not establish — it blocks
	 * the release exactly like an outstanding token (fail closed).  The
	 * audited `soft` class (xfs_buf_ioend_fail_unsubmitted) is reported
	 * but does not block: it only ever occurs after a forced shutdown,
	 * which makes the departure DIRTY on its own.
	 */
	ok = inflight == 0 && rp == 0 && dirwr == 0 && !after && !corrupt &&
	     untokened == 0 && stage == MXFS_DEPARTURE_FROZEN;
	if (ok)
		xfs_notice(mp,
"MXFS: P304-RETIRE-QUIESCED at=%s buf_io_inflight=0 rejected_pending=0 dir_wr_inflight=0 io_after_freeze=0 corrupt=0 untokened=0 soft=%lu carried=%lu submitted=%lu drain_stalls=%lu — departure frozen, release stamp may proceed",
			   where, soft, carried, submitted, stalls);
	else
		xfs_alert(mp,
"MXFS: P304-RETIRE-NOT-QUIESCED at=%s stage=%d buf_io_inflight=%d rejected_pending=%d dir_wr_inflight=%d io_after_freeze=%d rejected=%lu corrupt=%d untokened=%lu soft=%lu carried=%lu — I/O still attributable to this mount at the release point, or a completion of unknown provenance; departure treated as DIRTY (slot ACTIVE, PR key retained as fence target)",
			  where, stage, inflight, rp, dirwr, after ? 1 : 0,
			  rejected, corrupt ? 1 : 0, untokened, soft, carried);
	return ok;
}

/*
 * sess475 (D-0133, design-consult placement ruling — ccmemory ccloop-c7ee71c6-
 * sess475-GPT-ruling-d0133-lock-inert-put-super-teardown-shape9-hardened).
 * The FINAL clustered SB summary write: taken here, while the DLM context
 * and our heartbeat are alive, because put_super tears the DLM down before
 * xfs_unmountfs and the in-quiesce lock of 0.64.28 could never be granted
 * (rc=-19 on 96/96 attempts, chain 116 s474e).
 *
 *   1. flush inodegc and stop blockgc (the last local producers of AG
 *      counter changes) BEFORE the critical section;
 *   2. take the dedicated summary EX lock (CAW grant epoch = ordering
 *      witness) and hold it across xfs_log_quiesce, whose clustered path
 *      (mxfs_sb_summary_cover) recounts from UNCACHED AG headers, covers
 *      the log (the whole-sector SB home write), flushes the device and
 *      re-reads the durable sector;
 *   3. unlock, then SEAL the mount: from here no transaction, SB log or
 *      SB-sector write may happen; the later xfs_log_clean quiesce only
 *      verifies that (mxfs_sb_summary_sealed_quiesce) and a violation —
 *      or a lock/recount failure here — makes the departure DIRTY
 *      (m_mxfs_sb_late_dirty: no unmount record, slot retained, peers
 *      recover the slice).  Never an unlocked whole-sector SB write.
 *
 * Read-only, shut-down and non-lazy mounts have nothing to write.
 */
static void
mxfs_sb_summary_final_sync(
	struct xfs_mount	*mp)
{
	extern int mxfs_sb_summary_lock(struct xfs_mount *, uint64_t *);
	extern void mxfs_sb_summary_unlock(struct xfs_mount *);
	extern int mxfs_sb_summary_master_self(struct xfs_mount *);
	extern int mxfs_dbg_sb_late_dirty_take(void);
	int		lk, error = 0;

	if (!mp->m_mxfs_dlm || !mp->m_mxfs_dlm_was_active ||
	    !xfs_has_lazysbcount(mp))
		return;
	if (xfs_is_shutdown(mp) || !xfs_log_writable(mp)) {
		/* nothing may be written; the later quiesce stays guarded */
		mp->m_mxfs_sb_summary_done = true;
		xfs_notice(mp,
	"MXFS: P-SB-SUMMARY-FINAL-SKIP slot=%u shutdown=%d writable=%d — no final SB summary write",
			   mp->m_mxfs_node_slot, xfs_is_shutdown(mp) ? 1 : 0,
			   xfs_log_writable(mp) ? 1 : 0);
		return;
	}

	xfs_inodegc_flush(mp);
	xfs_blockgc_stop(mp);

	/*
	 * 0.75.34 (D-0536): wait out a runtime cover of this node that is
	 * inside the section right now (it holds the cluster lock too); the
	 * next runtime cover sees m_mxfs_sb_summary_done and writes nothing.
	 */
	mutex_lock(&mp->m_mxfs_sb_summary_mutex);

	/*
	 * sess476 (D-0537): raise the holder mark BEFORE the granting CAS, so a
	 * peer's BAST that lands between the grant and the mark cannot take the
	 * no-inode orphan release (__mxfs_dlm_bast_notify refuses while the mark
	 * is set; refusing a BAST for a grant we do not hold yet is harmless —
	 * there is nothing to release).
	 */
	WRITE_ONCE(mp->m_mxfs_sb_lock_held, true);
	smp_wmb();
	lk = mxfs_sb_summary_lock(mp, &mp->m_mxfs_sb_grant_epoch);
	pr_info("mxfs: P-SB-SUMMARY-LOCK slot=%u rc=%d epoch=%llu master_self=%d at=put_super\n",
		mp->m_mxfs_node_slot, lk,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch,
		mxfs_sb_summary_master_self(mp));
	if (lk != 0)
		WRITE_ONCE(mp->m_mxfs_sb_lock_held, false);
	if (lk == 0) {
		/*
		 * sess492 (D-0487) directed arm: pin this node's AIL NOW — with
		 * the cluster-wide lock held and the quiesce still ahead — so
		 * the measurement is whether the pinned-AIL fail-stop can still
		 * reach a node that holds the lock, whether its quiesce then
		 * returns, and how long the peers wait.  One-shot, disarmed by
		 * default; the first unheld AG at or above the armed number.
		 */
		{
			extern int mxfs_dbg_sb_inject_unheld_take(void);
			extern int mxfs_inject_unheld_agmeta_dirty(
					struct xfs_mount *, unsigned int);
			int	ia = mxfs_dbg_sb_inject_unheld_take();

			if (ia >= 0) {
				unsigned int	a;
				int		irc = -EBUSY;

				for (a = ia; a < mp->m_sb.sb_agcount &&
				     irc == -EBUSY; a++)
					irc = mxfs_inject_unheld_agmeta_dirty(mp, a);
				pr_warn("mxfs: P487-INJECT-UNDER-LOCK slot=%u armed_agno=%d agno=%u rc=%d — unheld AG image committed while put_super holds the SB summary lock, before its quiesce\n",
					mp->m_mxfs_node_slot, ia,
					irc == -EBUSY ? 0 : a - 1, irc);
			}
		}
		error = xfs_log_quiesce(mp);
		WRITE_ONCE(mp->m_mxfs_sb_lock_held, false);
		mxfs_sb_summary_unlock(mp);
		pr_info("mxfs: P-SB-SUMMARY-UNLOCK slot=%u epoch=%llu held=1 at=put_super cover_rc=%d\n",
			mp->m_mxfs_node_slot,
			(unsigned long long)mp->m_mxfs_sb_grant_epoch, error);
	}
	mp->m_mxfs_sb_summary_done = true;
	mutex_unlock(&mp->m_mxfs_sb_summary_mutex);
	if (lk || error) {
		mp->m_mxfs_sb_late_dirty = true;
		xfs_fs_mark_sick(mp, XFS_SICK_FS_COUNTERS);
		xfs_alert(mp,
	"MXFS: P-SB-SUMMARY-FINAL-FAIL slot=%u lock_rc=%d cover_rc=%d — final SB summary sync did not complete under the lock; departure DIRTY (no unmount record, slot retained)",
			  mp->m_mxfs_node_slot, lk, error);
	}
	/* the seal: counted producers after this point are violations */
	smp_wmb();
	WRITE_ONCE(mp->m_mxfs_sb_sealed, true);
	pr_info("mxfs: P-SB-SEALED slot=%u epoch=%llu late_dirty=%d\n",
		mp->m_mxfs_node_slot,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch,
		mp->m_mxfs_sb_late_dirty ? 1 : 0);

	/*
	 * sess475 late-dirty invariant arm (tests/sess475_chain116_d0133_sb_seal.sh).
	 * sess476: the knob is taken at put_super ENTRY (mxfs_sb_late_dirty_prearm)
	 * and the root's DLM EX pre-warmed there, BEFORE the teardown bast-arm
	 * sweep closes the gate — chain 116 v3 wedged this xfs_ilock forever in
	 * mxfs_dlm_ilock_begin (P-DEMWAIT-REDRIVE ino=128 -> P6S-ARM-REFUSED
	 * "bast-arm gate closed (teardown)" every 3 s): a dead demote instance on
	 * the root cannot be re-driven once the gate is closed.  With the grant
	 * cached EX and no BAST deliverable, this acquire is local.
	 */
	if (unlikely(mp->m_mxfs_sb_late_dirty_armed)) {
		struct xfs_trans	*tp;
		struct xfs_inode	*rip = NULL;

		mp->m_mxfs_sb_late_dirty_armed = false;
		/*
		 * sess485: the mount's root reference was dropped by
		 * xfs_unmountfs_prepare, which now runs before this sync; take
		 * a reference by number for the injection and drop it after.
		 */
		if (xfs_iget(mp, NULL, mp->m_sb.sb_rootino, 0, 0, &rip))
			rip = NULL;
		xfs_alert(mp,
	"MXFS: P-DBG-SB-LATE-DIRTY slot=%u — INJECTED: logging the root inode core after the SB summary seal (root dlm_mode=%u)",
			  mp->m_mxfs_node_slot, rip ? rip->i_dlm_mode : 0);
		if (rip && !xfs_trans_alloc(mp, &M_RES(mp)->tr_ichange, 0, 0, 0, &tp)) {
			xfs_ilock(rip, XFS_ILOCK_EXCL);
			xfs_trans_ijoin(tp, rip, XFS_ILOCK_EXCL);
			xfs_trans_log_inode(tp, rip, XFS_ILOG_CORE);
			xfs_trans_commit(tp);
		}
		if (rip)
			xfs_irele(rip);
	}
}

/*
 * sess476: called at put_super entry, before the teardown bast-arm sweep.
 * Takes the one-shot dbg_sb_late_dirty knob and pre-warms the root inode's
 * DLM EX (a normal acquire + release; the grant stays cached) so the
 * post-seal injection above never has to acquire through a closed gate.
 */
static void
mxfs_sb_late_dirty_prearm(
	struct xfs_mount	*mp)
{
	extern int mxfs_dbg_sb_late_dirty_take(void);
	struct xfs_inode	*rip = mp->m_rootip;

	if (likely(!mxfs_dbg_sb_late_dirty_take()))
		return;
	if (!rip || !mp->m_mxfs_dlm) {
		xfs_alert(mp,
	"MXFS: P-DBG-SB-LATE-DIRTY-PREARM slot=%u — no root inode / DLM; injection dropped",
			  mp->m_mxfs_node_slot);
		return;
	}
	xfs_ilock(rip, XFS_ILOCK_EXCL);
	xfs_iunlock(rip, XFS_ILOCK_EXCL);
	mp->m_mxfs_sb_late_dirty_armed = true;
	xfs_alert(mp,
	"MXFS: P-DBG-SB-LATE-DIRTY-PREARM slot=%u root dlm_mode=%u — root EX pre-warmed before the teardown bast-arm sweep",
		  mp->m_mxfs_node_slot, rip->i_dlm_mode);
}

/* stage → QUIESCING (before xfs_unmountfs); no-op without accounting. */
static void
mxfs_departure_quiescing(
	struct xfs_mount	*mp)
{
	struct mxfs_depart_acct	*acct = mp->m_mxfs_acct;

	if (!acct)
		return;
	spin_lock(&acct->lock);
	if (acct->stage < MXFS_DEPARTURE_QUIESCING)
		acct->stage = MXFS_DEPARTURE_QUIESCING;
	spin_unlock(&acct->lock);
}

/*
 * sess460 (0.61.6, review #5 condition 3): the crash-cut park.  put_super
 * stops here for dbg_depart_crash_hold_ms at the cut named by the one-shot
 * dbg_depart_crash_cut, printing P-DBG-DEPART-CUT so tests/depart_crash_cuts.sh
 * can destroy the VM while the departure sits exactly between two durable
 * steps (before the release CAS / after it before its flush / after the flush
 * before the late unregister / after a successful unregister).  If nobody
 * crashes us the hold simply expires and the departure continues unchanged.
 */
static void
mxfs_depart_dbg_crash_cut(
	struct xfs_mount	*mp,
	int			cut,
	const char		*phase)
{
	extern uint32_t mxfs_pal_dbg_depart_crash_hold_ms(void);
	uint32_t	hold = mxfs_pal_dbg_depart_crash_hold_ms();

	xfs_alert(mp,
"MXFS: P-DBG-DEPART-CUT cut=%d phase=%s — parking put_super for %u ms (crash-cut arm: destroy the VM now)",
		  cut, phase, hold);
	msleep(hold);
	xfs_alert(mp,
"MXFS: P-DBG-DEPART-CUT cut=%d phase=%s — hold expired without a crash; continuing the departure",
		  cut, phase);
}

/*
 * THE AUTHORITY GATE, ASKED OF THE MOUNT.
 *
 * The five mutating producers used to read mp->m_mxfs_dlm themselves and
 * treat a NULL as "not a clustered mount, nothing to own".  That is true of
 * a mount that never had a DLM.  It is NOT true of a mount whose DLM was
 * detached by its own teardown: put_super clears the pointer before
 * xfs_unmountfs writes the log cover and the unmount record, and joins the
 * heartbeat thread immediately after, so from that line on the producers ask
 * a question that answers itself and the node writing is one that is no
 * longer proving liveness to anybody.
 *
 * This build only COUNTS that case; the answer it returns is byte-for-byte
 * the answer the five sites returned before, so the count measures the
 * reachable population rather than the effect of a change.
 */
/*
 * TEST-ONLY, AND WHAT EACH ONE IS FOR.
 *
 * dbg_auth_tail_blind restores the gate's PRE-FIX answer for exactly the case
 * the fix changed: a mutating submission on a clustered mount whose DLM has
 * been detached is admitted without consulting the lease, because the absence
 * of the reference used to be read as "not a clustered mount".  It exists so
 * the before and the after can be measured on ONE build, where nothing else
 * differs — two builds would leave every other difference between them as an
 * alternative explanation.  It changes no other path: a mount with a live DLM
 * is gated exactly as it is with the knob clear.
 *
 * dbg_unmount_tail_delay_ms parks put_super for that long immediately after
 * the DLM is detached and the heartbeat thread joined, so the authority lease
 * runs out BEFORE xfs_unmountfs writes the log cover and the unmount record.
 * That ordering is the one this is all about and no workload produces it on
 * demand: the tail is normally ~1 s and the lease is 30 s.  One-shot.
 */
/*
 * dbg_admission_refuse makes xfs_fs_fill_super take the out_unmount goto
 * immediately after a SUCCESSFUL admission commit.  That is the one unwind in
 * the mount path that calls xfs_unmountfs, and it calls it with the DLM
 * already detached — so whatever log recovery and unlinked-inode processing
 * left behind is pushed to the shared LUN by a mount that was refused.  The
 * production trigger is an FSWIDE quarantine that only the registration-time
 * scan discovers, which exists for about half a second and cannot be aimed at
 * from outside; nothing downstream of the goto is changed by the knob, so the
 * unwind under measurement is the production unwind.  One-shot.
 *
 * dbg_mount_unwind_park_ms parks that unwind between the DLM shutdown (which
 * joins the heartbeat thread) and xfs_unmountfs, so the authority lease runs
 * out BEFORE the unwind's metadata writes are submitted.  It is the
 * mount-unwind twin of dbg_unmount_tail_delay_ms and it exists for the same
 * reason: the tail is ~1 s, the lease is 30 s, and no workload produces that
 * ordering on demand.  One-shot.
 */
int mxfs_dbg_auth_tail_blind;
int mxfs_dbg_unmount_tail_delay_ms;
int mxfs_dbg_admission_refuse;
int mxfs_dbg_mount_unwind_park_ms;
atomic64_t mxfs_auth_tail_blind_n = ATOMIC64_INIT(0);

/*
 * TEST ONLY — THE POST-ADMISSION PARK, and it is deliberately not another
 * pre-gate delay.
 *
 * Every knob that already lives beside this one parks a caller BEFORE the
 * authority gate, so the gate then sees an expired lease and refuses.  That
 * schedule proves the gate refuses; it says nothing about the schedule the
 * gate cannot see, which is an operation that PASSED the gate and had not yet
 * reached the layer below it when a successor fenced this node and began
 * replaying its journal slice.  If such an operation can still change what the
 * successor recovered, no second check anywhere near the gate helps — another
 * check only moves the pause point — and the disposition has to be an ordering
 * mechanism or storage-side exclusion instead.
 *
 * So: name a site, give it a hold in ms, and the FIRST submission of that
 * class to be admitted parks between the gate's "yes" and the caller's
 * submission.  One class at a time, because the four sites are the four
 * classes of submission and grading them together would make an unordered
 * write indistinguishable from a late completion of an ordered one.
 *
 * The site names are the ones the gate's own call sites pass, and they are
 * read from those call sites rather than invented here: "log" (the iclog
 * write, xfs/xfs_log.c:3021), "data" (buffered writeback's ioend,
 * pal/linux/xfs_aops.c:1175), "dio" and "dio-zoned" (pal/linux/xfs_file.c:1275
 * and :949), and "meta" (metadata buffers, pal/linux/xfs_buf.c:9794).  All are
 * reached from
 * process or workqueue context and the park sleeps, which is why the selector
 * is a name and not a blanket delay.
 *
 * One-shot: the hold is cleared by the submission that takes it, so a lap
 * parks exactly one operation and a knob left armed by an aborted lap cannot
 * silently park a later one.
 */
char *mxfs_dbg_admit_park_site;
int mxfs_dbg_admit_park_ms;

atomic64_t mxfs_auth_admit_detached_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_refuse_detached_n = ATOMIC64_INIT(0);
atomic64_t mxfs_auth_noauth_n = ATOMIC64_INIT(0);

/*
 * INSTRUMENT ONLY — it changes no decision.
 *
 * The metadata arm of the authority gate (pal/linux/xfs_buf.c) asks
 * bp->b_mount->m_mxfs_dlm rather than the mount's authority object, and takes
 * no branch at all when that pointer is NULL.  put_super detaches the DLM
 * before xfs_unmountfs writes the log cover, the superblock count and the
 * unmount record, so for the whole teardown tail that arm cannot see the lease
 * it is subject to.  This counts the submissions that reach it in exactly that
 * state — clustered mount, DLM detached — so a lap can say whether the
 * ordering is reached at all before anything is changed to close it.
 */
atomic64_t mxfs_auth_meta_detached_n = ATOMIC64_INIT(0);

/*
 * Does the armed site selector name THIS site?
 *
 * Trailing whitespace is ignored because a charp module parameter written
 * from a shell keeps the newline: `echo log > .../dbg_admit_park_site` stores
 * "log\n", and a plain strcmp would then match nothing while the knob read
 * back as armed.  An all-whitespace value is treated as unarmed for the same
 * reason — that is what clearing the knob with an empty echo actually leaves
 * behind.
 */
static bool
mxfs_admit_park_site_armed(
	const char		*site)
{
	const char		*want = READ_ONCE(mxfs_dbg_admit_park_site);
	size_t			n;

	if (!want || !site)
		return false;
	n = strlen(want);
	while (n && (want[n - 1] == '\n' || want[n - 1] == '\r' ||
		     want[n - 1] == ' ' || want[n - 1] == '\t'))
		n--;
	if (!n)
		return false;
	return strlen(site) == n && !strncmp(site, want, n);
}

bool
mxfs_mount_write_admitted(
	struct xfs_mount	*mp,
	const char		*site)
{
	struct mxfs_authority	*auth;
	bool			ok;

	/*
	 * NOT CLUSTERED IS A PROPERTY OF THE MOUNT, decided once before
	 * anything clustered could be submitted.  It is deliberately not "the
	 * DLM pointer is NULL": that is also true of a clustered mount partway
	 * through its own teardown and of one whose DLM init is still running.
	 */
	if (!mp || !READ_ONCE(mp->m_mxfs_clustered))
		return true;

	auth = READ_ONCE(mp->m_mxfs_auth);
	if (unlikely(!auth)) {
		atomic64_inc(&mxfs_auth_noauth_n);
		pr_err_ratelimited(
		    "mxfs: P291-AUTH-ABSENT site=%s comm=%s — a clustered mount reached the authority gate with no authority object, so which incarnation this write belongs to cannot be established; REFUSED\n",
		    site, current->comm);
		return false;
	}

	if (unlikely(mxfs_dbg_auth_tail_blind && !READ_ONCE(mp->m_mxfs_dlm))) {
		atomic64_inc(&mxfs_auth_tail_blind_n);
		pr_err_ratelimited(
		    "mxfs: P291-AUTH-TAIL-BLIND site=%s comm=%s — TEST: the pre-fix gate is in force, so this submission is admitted because the DLM reference is absent and WITHOUT asking whether this incarnation still holds authority\n",
		    site, current->comm);
		return true;
	}

	ok = mxfs_authority_ok(auth);

	/*
	 * The teardown tail, traced.  These are submissions made after
	 * put_super detached the DLM — the log cover, the unmount record,
	 * inode reclaim — and they are legitimate precisely while the lease is
	 * still live.  Before the authority object outlived the DLM pointer
	 * they were admitted without any lease being consulted at all.
	 */
	if (unlikely(!READ_ONCE(mp->m_mxfs_dlm))) {
		if (ok) {
			atomic64_inc(&mxfs_auth_admit_detached_n);
			pr_notice_ratelimited(
			    "mxfs: P291-AUTH-TAIL-ADMIT site=%s comm=%s — this mount's DLM is already detached; the submission is admitted because the incarnation's authority lease is still live, and it is the lease that said so\n",
			    site, current->comm);
		} else {
			atomic64_inc(&mxfs_auth_refuse_detached_n);
		}
	}

	/*
	 * TEST: hold an ADMITTED submission below the gate.  The decision is
	 * already made and is not revisited on the way out — that is the
	 * point.  Whatever happens to this node's authority while the caller
	 * sleeps here, the operation it is about to submit was admitted by the
	 * incarnation that held authority when it asked.
	 */
	if (unlikely(ok && READ_ONCE(mxfs_dbg_admit_park_ms) > 0 &&
		     mxfs_admit_park_site_armed(site))) {
		int	hold = READ_ONCE(mxfs_dbg_admit_park_ms);

		WRITE_ONCE(mxfs_dbg_admit_park_ms, 0);
		xfs_alert(mp,
"MXFS: P292-ADMIT-PARK site=%s comm=%s ms=%d — TEST: this submission PASSED the authority gate and is parked between the gate and the layer below it; it was admitted by the incarnation holding authority now, and it will be submitted by whatever this node has become when the hold ends",
			  site, current->comm, hold);
		msleep(hold);
		xfs_alert(mp,
"MXFS: P292-ADMIT-PARK-END site=%s comm=%s — TEST: the admitted submission resumes and is handed below the gate",
			  site, current->comm);
	}
	return ok;
}

static void
xfs_fs_put_super(
	struct super_block	*sb)
{
	struct xfs_mount	*mp = XFS_M(sb);
	uint64_t		pr_late_key = 0;
	bool			pr_quarantined = false;	/* sess454 (D8) */
	bool			slot_released = false;
	bool			unmount_prepared = false;	/* sess485 */
	int			crash_cut = 0;		/* sess460 */
	struct mxfs_v5_dlm_slot_release dl_late = {0};

	xfs_notice(mp, "Unmounting Filesystem %pU", &mp->m_sb.sb_uuid);

	/*
	 * sess485: open the pre-publication half of the unmount accounting.
	 * From here until mxfs_dlm_ag_force_release_all every AG-metadata and
	 * inode-cluster write is the unmount's own metadata work done under
	 * live grants; after it, any such write is the defect.
	 */
	if (mp->m_mxfs_acct) {
		spin_lock(&mp->m_mxfs_acct->lock);
		mp->m_mxfs_acct->put_super_entered = true;
		spin_unlock(&mp->m_mxfs_acct->lock);
	}

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
	/* sess476: late-dirty arm pre-warm — must precede the gate closure */
	mxfs_sb_late_dirty_prearm(mp);

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
				    (mxfs_istate(vinode) & (I_FREEING | I_CLEAR))) {
					pr_warn("mxfs: P6S-SWEEP-BADREF ino=%llu i_count=%d i_state=0x%lx — NOT releasing\n",
						(unsigned long long)sip->i_ino,
						cnt, mxfs_istate(vinode));
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

		/*
		 * sess180 D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE Arm A:
		 * a forced shutdown queues the withdraw asynchronously
		 * (mxfs_dlm_shutdown_withdraw), and an umount that follows
		 * immediately used to cancel that work below BEFORE it ran —
		 * ctx->withdrawn stayed false, the teardown computed
		 * depart_clean=true, and the heartbeat slot was released as
		 * "clean teardown" over a DIRTY journal slice.  The remount
		 * then pass-2 adopted the slice and skipped its images:
		 * fsync-acknowledged data silently lost (measured, test32
		 * loop, 0.11.464).  The teardown verdict must not depend on
		 * workqueue timing: if the FS is shut down, persist the
		 * WITHDRAWN state synchronously and idempotently NOW, while
		 * the v5 ctx is fully alive.  The stamp CASes from the read
		 * image and refuses foreign-owned slots, so a survivor's
		 * recovery guard landing first still wins; on stamp failure
		 * the slot simply stays ACTIVE — fail closed either way,
		 * never CONSUMABLE with a dirty slice.
		 */
		if (xfs_is_shutdown(mp))
			mxfs_v5_dlm_shutdown_withdraw(v5dlm);

		/*
		 * sess485 (D-0483) — THE ORDER OF THIS BLOCK IS THE FIX.
		 *
		 * Until 0.69.2 the AG grants were published (force_release_all)
		 * as the FIRST act of this block, and the unmount's own metadata
		 * work — deferred inode inactivation (AGI, inobt, finobt), the
		 * final SB summary sync's log quiesce, and xfs_unmountfs's AIL
		 * push and inode flush — ran AFTER it: first with a DLM that
		 * re-acquired grants nobody drained again, then with no DLM at
		 * all (__mxfs_ag_dlm_lock answers "granted" to a NULL DLM), while
		 * a peer that had taken the published AG was modifying the same
		 * AGI beneath us.  Mount does the opposite — the DLM is alive
		 * before xfs_mountfs — and unmount must mirror it.
		 *
		 * The release cannot simply move down: the heartbeat thread is
		 * joined in mxfs_v5_dlm_shutdown_defer_release below, before
		 * xfs_unmountfs, so grants held across xfs_unmountfs would be
		 * held by a node no longer proving liveness — a fenceable write
		 * instead of an unserialised one.  So the WORK moves up: stop
		 * every producer, inactivate and quiesce under live grants and a
		 * beating heartbeat, make it durable, and only then publish.
		 * What xfs_unmountfs has left to do after that is the log
		 * covering and the unmount record, which touch no AG metadata —
		 * and the P483-AGFREE-WINDOW counters printed after it are the
		 * proof, because anything that still crosses is counted there.
		 */

		/*
		 * sess171: retire the selftest trigger BEFORE the ctx is
		 * NULLed/freed.  debugfs_remove waits out any in-flight
		 * write handler (debugfs proxy), so a mid-run selftest —
		 * which dereferences the ctx for seconds — completes and
		 * releases its grants before teardown proceeds, and no new
		 * run can arm.  m_debugfs itself is only removed in
		 * xfs_mount_free, far too late for this file.  sess485: it
		 * is also a grant consumer, so it retires before the quiesce.
		 */
		debugfs_remove(mp->m_mxfs_pwtest_dentry);
		mp->m_mxfs_pwtest_dentry = NULL;
		debugfs_remove(mp->m_mxfs_samenode_dentry);
		mp->m_mxfs_samenode_dentry = NULL;
		/*
		 * sess185: settle any in-flight foreign-slice replay while
		 * the v5 ctx is still alive.  The old order (NULL the ctx,
		 * v5_shutdown frees it, only THEN cancel this work) made a
		 * running replay lose its publication — recovery_complete
		 * bailed on ctx=NULL (measured, test32 repro) — and left a
		 * use-after-free window for an instance that read the ctx
		 * pointer just before the NULL.  Cancel BEFORE the NULL so
		 * a running replay finishes and publishes; cancel AGAIN
		 * right after the NULL, before v5_shutdown frees the ctx,
		 * to join any instance queued in between that captured a
		 * non-NULL ctx.  After that, every new instance sees the
		 * NULL and bails at the top of its loop; the late cancel
		 * below (after v5_shutdown, heartbeat gone) joins those
		 * stragglers before mp->m_log goes away.  sess485: a replay
		 * is an AG-metadata producer, so it is settled before the
		 * quiesce and the release, not after.
		 */
		cancel_work_sync(&mp->m_mxfs_foreign_replay_work);
		/*
		 * sess475 (D-0133 placement ruling): every producer that can
		 * still log must be stopped BEFORE the locked final SB summary
		 * sync — the reap worker re-drives inactivation (transactions)
		 * and the destage kick pushes the AIL — and the sync itself must
		 * run while the DLM is alive (the lock needs the ctx; the
		 * heartbeat keeps beating for any peer waiting on it).  After
		 * it the mount is SEALED (see xfs_mount.h m_mxfs_sb_sealed).
		 * sess485: the same ruling now also puts all of this BEFORE the
		 * grants are published, which the sess475 placement — sync after
		 * release — had not required of itself.
		 */
		mxfs_defer_reap_destroy(mp);
		cancel_delayed_work_sync(&mp->m_mxfs_destage_kick);
		/*
		 * sess485: the unmount's metadata work, under live grants.  The
		 * prepare half of xfs_unmountfs performs, in upstream's words,
		 * "all on-disk metadata updates required to inactivate inodes
		 * that the VFS evicted earlier in the unmount process", returns
		 * the AG reservations, tears down quotas and the realtime
		 * inodes, drops the root and metadir references, and then
		 * DISABLES inode inactivation so nothing can queue a transaction
		 * behind us.  The SB summary sync (whose seal follows) and the
		 * explicit force/push/wait after it — covering every case the
		 * sync declines: read-only, non-lazy, DLM never active — then
		 * leave no dirty AG-metadata or inode-cluster buffer to be
		 * written after the release.  A shut-down log has nothing to
		 * push.  The finish half (inode reclaim of what is by then all
		 * clean, log covering, unmount record) runs where xfs_unmountfs
		 * always ran, after the DLM teardown.
		 */
		xfs_unmountfs_prepare(mp);
		unmount_prepared = true;
		/*
		 * 0.70.1 (D-SB-SUMMARY-LOCK-HELD-ACROSS-UNBOUNDED-LOG-QUIESCE-
		 * FLEET-CONVOY-0487): the explicit force / whole-AIL push / buffer
		 * wait now runs BEFORE the final SB summary sync, not after it.
		 * The sync takes the cluster-wide SB summary EX lock — whose BAST
		 * is refused while held — and runs its own log quiesce under it;
		 * on 2026-09-04 one node whose AIL could not drain (a committed
		 * image for a grant it no longer held, refused by xfsaild) sat in
		 * that quiesce holding the lock while 26 peers waited behind it
		 * for the whole budget.  Every wait that can depend on a grant
		 * this node no longer holds therefore happens here, before the
		 * lock is taken: a node whose AIL is pinned stalls alone, and
		 * with the refused-item fail-stop it shuts down here and never
		 * takes the lock (the sync skips itself on a shut-down mount).
		 * The quiesce under the lock then finds an AIL that only the
		 * sync's own counter transaction can have repopulated, which is
		 * local work.  Producers are stopped and inactivation is off by
		 * now, so nothing can be logged between this push and the seal
		 * except that transaction; the cases the sync declines (read-
		 * only, non-lazy, DLM never active) are covered by this same
		 * push, exactly as they were when it ran after the sync.
		 */
		if (!xfs_is_shutdown(mp)) {
			xfs_log_force(mp, XFS_LOG_SYNC);
			xfs_ail_push_all_sync(mp->m_ail);
			xfs_buftarg_wait(mp->m_ddev_targp);
		}
		mxfs_sb_summary_final_sync(mp);

		/* ICLUSTER (ccloop 72513a13 sess3): drop this mount's
		 * cluster-lock objects.  Must run while inodes are already
		 * evicted (refs all zero) and BEFORE the v5 ctx goes away;
		 * held disk grants are swept by caw release_all inside
		 * v5_shutdown.  Stale objects surviving into a later mount
		 * at the same mp address would false-hit the (mp,base)
		 * hash with a stale disk_mode — this call is load-bearing
		 * once mxfs.icluster_dlm=1.  sess485: it now follows the
		 * inactivation flush above, which is the last consumer of
		 * per-inode cluster locks; before, the flush ran after the
		 * purge. */
		mxfs_iclus_purge_all(mp);
		/*
		 * sess485: the release itself now runs the full per-AG drain
		 * pipeline (alloc buflist, inode clusters, AG metadata, device
		 * flush) before each unlock — architectural invariant 1 — and
		 * reports how many AGs the drains still found dirty; after the
		 * quiesce above that count is expected to be zero.
		 */
		mxfs_dlm_ag_force_release_all(mp);
		/*
		 * sess483: from this line on, every AG grant this node held has
		 * been published as free and a peer may legitimately take it.
		 * sess485: nothing below may touch AG metadata or inode
		 * clusters any more.  The buffer submit path counts any that
		 * does, the acquire path counts grants handed out by a DLM that
		 * no longer exists, and both totals are printed once below —
		 * the same instrument that found the defect verifies the fix.
		 */
		if (mp->m_mxfs_acct) {
			spin_lock(&mp->m_mxfs_acct->lock);
			mp->m_mxfs_acct->ag_grants_published = true;
			mp->m_mxfs_acct->nulldlm_at_agfree =
				atomic64_read(&mxfs_dlm_stat_ag_nulldlm);
			spin_unlock(&mp->m_mxfs_acct->lock);
		}
		/*
		 * sess9 (ccloop a864): settle the shutdown-withdraw work
		 * BEFORE freeing the ctx.  NULL the pointer first so a
		 * withdraw queued in the window no-ops instead of using the
		 * ctx v5_shutdown is about to free.
		 */
		mp->m_mxfs_dlm = NULL;
		cancel_work_sync(&mp->m_mxfs_withdraw_work);
		cancel_work_sync(&mp->m_mxfs_foreign_replay_work);
		/*
		 * v0.11.74: keep our PR registration alive across
		 * xfs_unmountfs.  Unregistering inside v5 shutdown fenced
		 * our OWN unmount log record on WE-RO targets whenever a
		 * peer still held the reservation (EBADE -> log-error
		 * shutdown on every clean non-holder umount, unmount record
		 * lost, dirty slice recovered on next mount).  The key is
		 * unregistered below, after the final log write.
		 */
		pr_late_key = mxfs_v5_dlm_detach_pr_key(v5dlm, &pr_quarantined);
		if (pr_quarantined)
			xfs_alert(mp,
"MXFS: P304-DEPARTURE-QUARANTINED — a PR probe/settle thread is parked in a SCSI command; departure treated as DIRTY (slot retained, PR key 0x%llx retained as fence target), the DLM context is leaked with the module pinned",
				  (unsigned long long)pr_late_key);
		/*
		 * sess192 (dirty-slice Arm C): on a clean departure the
		 * heartbeat slot is NOT zeroed inside shutdown any more —
		 * it is handed out through dl_late and cleared below, only
		 * after xfs_unmountfs has made the unmount record durable.
		 * A crash between here and there leaves the slot ACTIVE
		 * over the dirty log, so peers fence and recover us instead
		 * of a later claim consuming the slice.
		 */
		mxfs_v5_dlm_shutdown_defer_release(v5dlm, &dl_late);
		/*
		 * TEST: let the lease run out inside the teardown tail.  The
		 * heartbeat thread was joined on the line above, so from here
		 * authority can only run down; parking longer than the lease
		 * puts the log cover and the unmount record on the far side of
		 * its deadline, which is the ordering this gate exists for and
		 * which a normal ~1 s tail never reaches.  One-shot.
		 */
		if (unlikely(mxfs_dbg_unmount_tail_delay_ms > 0)) {
			int hold = mxfs_dbg_unmount_tail_delay_ms;

			mxfs_dbg_unmount_tail_delay_ms = 0;
			xfs_alert(mp,
"MXFS: P291-AUTH-TAIL-PARK ms=%d — TEST: parking the unmount tail past the authority lease; the log cover and the unmount record below are written by a node that has stopped proving liveness",
				  hold);
			msleep(hold);
			xfs_alert(mp,
"MXFS: P291-AUTH-TAIL-PARK-END — TEST: the unmount tail resumes");
		}
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
		/* D-0487: same lifecycle; the push that queues it needs
		 * m_mxfs_dlm, which is gone by here. */
		cancel_work_sync(&mp->m_mxfs_ailpin_work);
	}
	/* ccloop c7ee71c6 sess2: stop the destage kick while mp->m_log is
	 * still valid (same teardown-ordering family as foreign_replay). */
	cancel_delayed_work_sync(&mp->m_mxfs_destage_kick);

	/*
	 * sess452 (0.59.2, STOP-SHIP #2 blocker 5): the departure state
	 * machine, asserted mechanically.  QUIESCING: xfs_unmountfs drains
	 * the log, the AIL, inodegc and the buffer cache.  FROZEN (below,
	 * after the final device flush): no buffer I/O may be submitted by
	 * this mount any more — xfs_buf_submit_bio records a violation —
	 * and the release stamp is written only when the in-flight buffer
	 * count reads zero.
	 */
	mxfs_departure_quiescing(mp);
	xfs_filestream_unmount(mp);
	/* sess485: the clustered path ran the prepare half before publishing
	 * its grants; only the log teardown is left.  See xfs_unmountfs_prepare. */
	if (unmount_prepared)
		xfs_unmountfs_finish(mp);
	else
		xfs_unmountfs(mp);

	/*
	 * sess483: the size of the unmount AG-release window, reported once per
	 * unmount whatever the outcome.  nodlm_wr is the sharp number — an
	 * AG-metadata buffer this mount WROTE after publishing the AG as free
	 * AND after its DLM was destroyed, so no exclusion of any kind was
	 * available: an image landing on the platter for an allocation group
	 * another node may already own and may already have modified.  nodlm_rd
	 * is the same window in the other direction, a stale read that poisons
	 * whatever is built on it.  The dlm_* pair is the earlier half of the
	 * window, where the DLM still existed and the access may have re-
	 * acquired the grant it needed — those are not proof of an unserialised
	 * access, but whatever they dirtied is destaged only by the AIL push
	 * inside xfs_unmountfs, after the re-taken grants have been swept.
	 * nulldlm_acquires counts AG acquires told "granted" by a DLM that had
	 * already been destroyed (this mount's own share of a module-wide
	 * counter, differenced against the value sampled at publication); the
	 * first thirty-two name their callers.  All five are expected to be
	 * zero and none of them has ever been measured.
	 */
	if (mp->m_mxfs_acct) {
		unsigned long	agw, agr, ndw, ndr, icw, icr, indw, indr;
		unsigned long	anyio, anynd, prew, preic, agl, igc;
		long long	nulld;

		spin_lock(&mp->m_mxfs_acct->lock);
		prew = mp->m_mxfs_acct->agmeta_pre_agfree_wr;
		preic = mp->m_mxfs_acct->iclus_pre_agfree_wr;
		agl = mp->m_mxfs_acct->aglock_after_agfree;
		igc = mp->m_mxfs_acct->inodegc_after_stop;
		agw  = mp->m_mxfs_acct->agmeta_after_agfree_wr;
		agr  = mp->m_mxfs_acct->agmeta_after_agfree_rd;
		ndw  = mp->m_mxfs_acct->agmeta_nodlm_wr;
		ndr  = mp->m_mxfs_acct->agmeta_nodlm_rd;
		icw  = mp->m_mxfs_acct->iclus_after_agfree_wr;
		icr  = mp->m_mxfs_acct->iclus_after_agfree_rd;
		indw = mp->m_mxfs_acct->iclus_nodlm_wr;
		indr = mp->m_mxfs_acct->iclus_nodlm_rd;
		anyio = mp->m_mxfs_acct->anyio_after_agfree;
		anynd = mp->m_mxfs_acct->anyio_nodlm;
		nulld = atomic64_read(&mxfs_dlm_stat_ag_nulldlm) -
			mp->m_mxfs_acct->nulldlm_at_agfree;
		spin_unlock(&mp->m_mxfs_acct->lock);
		/*
		 * sess485: pre_wr / pre_iclus_wr are the writes the unmount made
		 * BEFORE publishing its grants — the hoisted work.  They are the
		 * positive control for the zeros that follow them: on a workload
		 * that leaves inactivation or dirty AG metadata for unmount they
		 * must be nonzero, and every after-publication counter zero.
		 */
		if (ndw || ndr || indw || indr || nulld)
			xfs_alert(mp,
"MXFS: P483-AGFREE-WINDOW nodlm_wr=%lu nodlm_rd=%lu iclus_nodlm_wr=%lu iclus_nodlm_rd=%lu dlm_wr=%lu dlm_rd=%lu iclus_dlm_wr=%lu iclus_dlm_rd=%lu nulldlm_acquires=%lld anyio=%lu anyio_nodlm=%lu pre_wr=%lu pre_iclus_wr=%lu aglock_after=%lu inodegc_after_stop=%lu — this mount touched allocation-group metadata and/or inode clusters after publishing its AG grants as free and after its DLM was gone; the nodlm counts had no exclusion available at all",
				  ndw, ndr, indw, indr, agw, agr, icw, icr,
				  nulld, anyio, anynd, prew, preic, agl, igc);
		else if (agw || agr || icw || icr || agl || igc)
			xfs_alert(mp,
"MXFS: P483-AGFREE-WINDOW nodlm_wr=0 nodlm_rd=0 iclus_nodlm_wr=0 iclus_nodlm_rd=0 dlm_wr=%lu dlm_rd=%lu iclus_dlm_wr=%lu iclus_dlm_rd=%lu nulldlm_acquires=0 anyio=%lu anyio_nodlm=%lu pre_wr=%lu pre_iclus_wr=%lu aglock_after=%lu inodegc_after_stop=%lu — metadata was touched, an AG grant re-taken, or an inode queued for inactivation after the grants were published; whatever that dirtied was destaged after the re-taken grants were swept, which is the defect the sess485 reordering removes",
				  agw, agr, icw, icr, anyio, anynd, prew, preic,
				  agl, igc);
		else
			xfs_notice(mp,
"MXFS: P483-AGFREE-WINDOW nodlm_wr=0 nodlm_rd=0 iclus_nodlm_wr=0 iclus_nodlm_rd=0 dlm_wr=0 dlm_rd=0 iclus_dlm_wr=0 iclus_dlm_rd=0 nulldlm_acquires=0 anyio=%lu anyio_nodlm=%lu pre_wr=%lu pre_iclus_wr=%lu aglock_after=0 inodegc_after_stop=0 — no AG-metadata or inode-cluster access, no AG acquire and no inactivation queued after the AG grants were published; pre_wr is the positive control (the unmount's metadata work, done under live grants), and a zero here is only a measurement while it is nonzero",
				   anyio, anynd, prew, preic);
	}

	/*
	 * sess192 (dirty-slice Arm C): the unmount record is on stable
	 * storage — xlog_unmount_write forces its iclog with PREFLUSH|FUA —
	 * or the log shut down trying (any unmount-record I/O error reaches
	 * xlog_force_shutdown, which sets the mp shutdown state we test
	 * here).  Only now may the heartbeat slot become consumable; on
	 * failure it stays ACTIVE and peers recover the slice.  The slot
	 * write happens while our PR registration is still alive (the late
	 * unregister below), so it cannot bounce EBADE on WE-RO targets.
	 */
	/*
	 * sess433 (D-379(B) / D-0355, sess432 design-consult ruling): the departure
	 * is CLEAN only if the log is not shut down AND the whole stack's
	 * final flush completes — the slot release must not precede the last
	 * operation that can dirty the departure.  A failed flush means the
	 * platter state of this incarnation's writes is uncertain, which is
	 * the same disposition as a dirty log: slot stays ACTIVE, key stays
	 * registered, peers fence and recover.
	 */
	/*
	 * sess451: the late phase — release stamp, PR unregister, re-stamp or
	 * self-complete, finish — is serialized host-wide against a same-boot
	 * remount's REGISTER + P305 settlement (mxfs_v5_dlm_departure_lock in
	 * v5_mount.h).  Held until release_finish below.
	 */
	{
		int flush_rc = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
		bool quiesced, drained;

		if (flush_rc)
			xfs_alert(mp,
"MXFS: P277-FINAL-FLUSH-FAILED rc=%d before slot release — departure treated as DIRTY (slot retained, PR key retained as fence target)",
				  flush_rc);
		/*
		 * sess452/454/455 (D2/D3): FREEZE under the accounting lock
		 * — from here every xfs_buf submission attributable to this
		 * mount is rejected — then WAIT for the tokens admitted
		 * before the transition (uncapped: see
		 * mxfs_departure_freeze_drain), THEN run the rest of the
		 * teardown (sb buffers, stats, workqueues,
		 * xfs_shutdown_devices' raw flush): anything those paths
		 * submit is rejected and recorded, so the quiescence
		 * assertion below sees it.  The heartbeat thread was joined
		 * in mxfs_v5_dlm_shutdown_defer_release, the CAW producers
		 * in mxfs_dlm_caw_stop, the mount workqueues here; the token
		 * count covers every xfs_buf bio this mount ever submitted.
		 * bt_bdev stays valid through xfs_mount_free, so the release
		 * CAS (through the cloned disklock handle) and the late
		 * unregister below still have their device.
		 *
		 * sess455 (ruling item 7): the host-wide departure mutex —
		 * which every local PR OUT also takes — is taken only AFTER
		 * the workqueues are destroyed, so no worker they flush can
		 * ever wait on it; a same-boot remount cannot begin before
		 * this put_super returns (the superblock and the exclusive
		 * bdev holder are still ours), so the flush/freeze/drain
		 * need no serialisation.
		 */
		/*
		 * sess459: departure-gate fault injectors (dbg_depart_inject,
		 * one-shot).  Arms 3/5/6 need an account that still admits
		 * tokens (pre-freeze); 1/4 act on the frozen account after
		 * the drain; 2 submits after the teardown so that the FINAL
		 * assertion, not the drain, is what blocks the release.
		 */
		{
			extern int mxfs_pal_dbg_depart_inject_take(void);
			extern int mxfs_pal_dbg_depart_crash_cut_take(void);
			int dbg = mxfs_pal_dbg_depart_inject_take();

			crash_cut = mxfs_pal_dbg_depart_crash_cut_take();
			if (dbg == 3 || dbg == 5 || dbg == 6 || dbg == 7)
				mxfs_depart_dbg_inject(mp, dbg, "pre-freeze");
			drained = mxfs_departure_freeze_drain(mp, "put_super");
			if (dbg == 1 || dbg == 4)
				mxfs_depart_dbg_inject(mp, dbg, "post-freeze");

			xfs_rtmount_freesb(mp);
			xfs_freesb(mp);
			xchk_mount_stats_free(mp);
			free_percpu(mp->m_stats.xs_stats);
			xfs_inodegc_free_percpu(mp);
			xfs_destroy_percpu_counters(mp);
			xfs_destroy_mount_workqueues(mp);
			xfs_shutdown_devices(mp);
			if (dbg == 2)
				mxfs_depart_dbg_inject(mp, dbg, "post-teardown");
		}

		mxfs_v5_dlm_departure_lock();		/* held to _unlock below */
		quiesced = mxfs_departure_quiesced(mp, "put_super") && drained;
		if (crash_cut == 1)
			mxfs_depart_dbg_crash_cut(mp, 1, "before-release-cas");
		/*
		 * sess475 (D-0133): a seal violation or a failed locked final
		 * SB summary sync withheld the unmount record — the slice is
		 * dirty, so the departure must be too (slot ACTIVE, key kept).
		 */
		if (mp->m_mxfs_sb_late_dirty)
			xfs_alert(mp,
	"MXFS: P-SB-SEAL-DIRTY-DEPARTURE slot=%u — SB summary seal violated or final sync failed; departure treated as DIRTY",
				  mp->m_mxfs_node_slot);
		slot_released = mxfs_v5_dlm_slot_release_commit(&dl_late,
					!xfs_is_shutdown(mp) && flush_rc == 0 &&
					quiesced && !pr_quarantined &&
					!mp->m_mxfs_sb_late_dirty);
		/*
		 * "Released" must mean DURABLY released before the key that
		 * fences this incarnation is retired: the CAS release is a
		 * synchronous target-side COMPARE AND WRITE with no FUA, so
		 * flush behind it.  A failed flush does not undo a CAS that
		 * may already be visible — it makes the release UNCERTAIN,
		 * and the safe disposition for uncertain is the DIRTY one:
		 * keep the key registered (P302 below) so the peers expire
		 * the RETIRE_PENDING record and fence it, whichever image
		 * the platter finally holds.
		 */
		if (slot_released) {
			if (crash_cut == 2)
				mxfs_depart_dbg_crash_cut(mp, 2, "after-cas-before-flush");
			flush_rc = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
			if (flush_rc) {
				xfs_alert(mp,
"MXFS: P277-RELEASE-FLUSH-FAILED rc=%d after slot release — the release CAS may or may not be durable (uncertain, not undone); PR key retained as the fence target so the peers settle the record either way",
					  flush_rc);
				slot_released = false;
			}
		}
	}

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
	/*
	 * sess377 (D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377): the unregister
	 * now VERIFIES itself with PR IN / READ KEYS and only returns 0 when
	 * the key is provably gone from every nexus.  A nonzero result is not
	 * a cosmetic warning — it means this initiator can still write to the
	 * shared LUN after MXFS has finished unmounting, so the departure is
	 * incomplete and the cluster must fence the key.  Say exactly that,
	 * once, in a greppable form.
	 */
	/*
	 * sess433 (D-379(B) / D-0355): a DIRTY or FAILED departure keeps its
	 * key.  The predecessor incarnation's slot stays ACTIVE over a dirty
	 * slice; the only proof of exclusion a replayer accepts is a verified
	 * PREEMPT AND ABORT of a PRESENT key.  Retiring the key here — as every
	 * build before this one did unconditionally — converted a fenceable
	 * state into KEY_ABSENT_UNPROVEN and made the slice unrecoverable by
	 * anyone, including this host's own next mount.
	 *
	 * 0.89.18: the operator's single_node_exclusive assertion used to be a
	 * second way out of that state and is not any more, which makes keeping
	 * the key here the ONLY thing standing between a dirty departure and an
	 * unrecoverable slice.
	 */
	if (pr_late_key && !slot_released) {
		xfs_alert(mp,
"MXFS: P302-PR-KEY-RETAINED-FENCE-TARGET key 0x%llx kept registered: departure was not durably clean (log_shutdown=%d). Peers fence this key with PREEMPT AND ABORT to recover the slice, and a same-host remount needs that fence - there is no operator override, since single_node_exclusive no longer certifies. See D-0355.",
			  (unsigned long long)pr_late_key,
			  xfs_is_shutdown(mp) ? 1 : 0);
	} else if (pr_late_key) {
		int prret;

		if (crash_cut == 3)
			mxfs_depart_dbg_crash_cut(mp, 3, "after-flush-before-unregister");
		prret = mxfs_pal_scsi_pr_unregister_bdev(
				mp->m_ddev_targp->bt_bdev, pr_late_key);
		if (prret == -EOPNOTSUPP) {
			/* No PR on this target at all — nothing was ever
			 * registered, so nothing leaked.  sess450: then nobody
			 * needs a READ KEYS to prove it: complete our own
			 * RETIRE_PENDING release. */
			int crc = mxfs_v5_dlm_slot_retire_complete(&dl_late);

			if (crc == -EPERM)
				xfs_alert(mp,
"MXFS: P304-RETIRE-SELF-WITHHELD: no PR on target but this mount was admitted under a fence capability; released slot left RETIRE_PENDING for a node with PR evidence (see P304-RETIRE-SELF-REFUSED-CLUSTERED).");
			else if (crc && crc != -ENOENT)
				xfs_alert(mp,
"MXFS: P304-RETIRE-SELF-FAILED rc=%d: released slot left RETIRE_PENDING (no PR on target); a peer or the next mount settles it.",
					  crc);
		} else if (prret) {
			int rrc;

			xfs_alert(mp,
"MXFS: P301-DEPARTURE-INCOMPLETE PR key 0x%llx was NOT retired (rc=%d). This node's initiator can still write to the shared LUN even though the filesystem is unmounted; the cluster must fence this key. See D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377.",
				  (unsigned long long)pr_late_key, prret);
			/*
			 * sess449 (D-0356 / D-377 phase (v)): slot=RELEASED +
			 * key=PRESENT is unfenceable — nothing names the
			 * incarnation the key belongs to.  Hand the retirement
			 * to the peers' fencing path: CAS our released record
			 * back to WITHDRAWN with the key (P303).  The disklock
			 * ctx was kept alive across the unregister for exactly
			 * this; it is destroyed by _release_finish below.
			 *
			 * sess450: the released record is RETIRE_PENDING, so
			 * even when this re-stamp never lands (crash, lost
			 * LUN — modelled by dbg_retire_skip_restamp) the peers'
			 * monitor expires it to WITHDRAWN after the grace and
			 * fences the key itself (P304-RETIRE-EXPIRED-WITHDRAWN).
			 */
			if (mxfs_pal_dbg_retire_skip_restamp_take())
				rrc = 0;
			else
				rrc = mxfs_v5_dlm_slot_restamp_unretired(&dl_late);
			if (rrc)
				xfs_alert(mp,
"MXFS: P303-DEPARTURE-INDETERMINATE key 0x%llx: the released slot could not be re-stamped for fencing (rc=%d). Peers expire the RETIRE_PENDING record after the retirement grace and fence the key; operator remedy meanwhile: PREEMPT AND ABORT this key from a live peer (sg_persist --out --preempt-abort). See D-0356.",
					  (unsigned long long)pr_late_key, rrc);
		}
		/* prret == 0: the key is provably gone, but a de-registered
		 * initiator cannot write a WE-RO LUN — the peers' READ KEYS
		 * (or the next mount's) completes the RETIRE_PENDING record. */
		if (prret == 0 && crash_cut == 5)
			mxfs_depart_dbg_crash_cut(mp, 5, "after-unregister-before-finish");
	} else if (slot_released) {
		/* sess450: no PR key was ever registered by this mount —
		 * complete our own retirement. */
		int crc = mxfs_v5_dlm_slot_retire_complete(&dl_late);

		if (crc == -EPERM)
			xfs_alert(mp,
"MXFS: P304-RETIRE-SELF-WITHHELD: no PR key was registered yet this mount was admitted under a fence capability; released slot left RETIRE_PENDING for a node with PR evidence (see P304-RETIRE-SELF-REFUSED-CLUSTERED).");
		else if (crc && crc != -ENOENT)
			xfs_alert(mp,
"MXFS: P304-RETIRE-SELF-FAILED rc=%d: released slot left RETIRE_PENDING (no PR key); a peer or the next mount settles it.",
				  crc);
	}
	mxfs_v5_dlm_slot_release_finish(&dl_late);
	mxfs_v5_dlm_departure_unlock();		/* sess451 */

	/*
	 * THE TEARDOWN TAIL, REPORTED ONCE PER UNMOUNT.
	 *
	 * Everything this mount submitted after its DLM was detached, split by
	 * what the authority lease said about it.  tail_admit is the permitted
	 * tail — the log cover, the unmount record, inode reclaim — admitted
	 * because the lease was still live, and it is the POSITIVE CONTROL: a
	 * zero there on a clean unmount means the instrument never fired, not
	 * that nothing was submitted.  tail_refuse is the same tail after the
	 * lease closed, which is a dirty departure and the correct one.
	 * no_authority must always be zero; it counts a clustered mount that
	 * could not say which incarnation a write belonged to.
	 *
	 * Before the authority object outlived the DLM pointer, every one of
	 * these submissions was admitted with no lease consulted at all,
	 * because the gate read mp->m_mxfs_dlm and a detached pointer answered
	 * "not a clustered mount".
	 */
	if (mp->m_mxfs_clustered) {
		long long	adm = atomic64_read(&mxfs_auth_admit_detached_n);
		long long	ref = atomic64_read(&mxfs_auth_refuse_detached_n);
		long long	noa = atomic64_read(&mxfs_auth_noauth_n);
		long long	bld = atomic64_read(&mxfs_auth_tail_blind_n);
		long long	mta = atomic64_read(&mxfs_auth_meta_detached_n);

		/*
		 * The metadata arm is counted separately because it is decided
		 * somewhere else.  tail_admit and tail_refuse are submissions
		 * that reached the authority object and were DECIDED by the
		 * lease; meta_detached counts metadata writes that reached
		 * their own gate while this mount's DLM was already detached,
		 * where that gate asks the detached pointer and so admits
		 * without consulting the lease at all.  A non-zero value is
		 * the ordering being reached, not a verdict on it.
		 */
		xfs_notice(mp,
"MXFS: P291-AUTH-META meta_detached=%lld (module-wide total since load) — metadata writes that reached the metadata authority arm after this mount's DLM was detached",
			   mta);

		if (bld)
			xfs_alert(mp,
"MXFS: P291-AUTH-TAIL tail_admit=%lld tail_refuse=%lld no_authority=%lld tail_blind=%lld (module-wide totals since load) — TEST: the pre-fix gate was in force for the tail, so tail_blind submissions went to the LUN without the authority lease being consulted at all",
				  adm, ref, noa, bld);
		else if (noa)
			xfs_alert(mp,
"MXFS: P291-AUTH-TAIL tail_admit=%lld tail_refuse=%lld no_authority=%lld tail_blind=0 (module-wide totals since load) — a clustered mount reached the authority gate with no authority object; which incarnation those writes belonged to could not be established",
				  adm, ref, noa);
		else
			xfs_notice(mp,
"MXFS: P291-AUTH-TAIL tail_admit=%lld tail_refuse=%lld no_authority=0 tail_blind=0 (module-wide totals since load) — submissions made after a mount's DLM was detached, each one decided by that incarnation's own authority lease rather than by the presence of a pointer",
				   adm, ref);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
/*
 * THE COMPLETION HALF OF LAZYTIME, ON THE KERNELS THAT HAVE NOWHERE ELSE TO PUT
 * IT.  xfs_vn_update_time defers a timestamp on a lazytime mount: it marks the
 * inode I_DIRTY_TIME and returns success without logging anything.  Something
 * has to come back later and write it, and which hook the VFS calls for that
 * moved in 6.19 — inode_operations->sync_lazytime replaced
 * super_operations->dirty_inode.  This fork carries the newer one, so below
 * 6.19 the deferral had no completion path at all: not at writeback, not at the
 * last iput, not at sync, not at unmount.  An accepted timestamp update was
 * simply lost.
 *
 * The guards are upstream's and both matter: a non-lazytime mount logs its
 * timestamps inline and has nothing deferred, and only an I_DIRTY_SYNC raised
 * over an inode that was carrying a deferred timestamp means "now write it".
 *
 * HOW THE VFS SAYS SO ON THIS KERNEL.  Since 5.12, __mark_inode_dirty clears
 * I_DIRTY_TIME from i_state BEFORE calling ->dirty_inode and hands it over in
 * the flags instead ("Inode timestamp update will piggback on this dirtying",
 * fs/fs-writeback.c), so the callback sees flags == I_DIRTY_SYNC|I_DIRTY_TIME
 * and an i_state that no longer has the bit.  The pre-5.12 test — flags equal
 * to I_DIRTY_SYNC alone and I_DIRTY_TIME still in i_state — is false on every
 * call here, and a guard written that way turned this hook back into the
 * nothing it replaced.
 */
STATIC void
xfs_fs_dirty_inode(
	struct inode		*inode,
	int			flags)
{
	if (!(inode->i_sb->s_flags & SB_LAZYTIME))
		return;
	if (flags != (I_DIRTY_SYNC | I_DIRTY_TIME))
		return;
	xfs_vn_sync_lazytime(inode);
}
#endif

static const struct super_operations xfs_super_operations = {
	.alloc_inode		= xfs_fs_alloc_inode,
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
	.dirty_inode		= xfs_fs_dirty_inode,
#endif
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
	case Opt_peer:
		return mxfs_parse_peers(parsing_mp, param->string, false);
	case Opt_peers:
		return mxfs_parse_peers(parsing_mp, param->string, true);
	case Opt_cluster:
		if (!mxfs_cluster_name_valid(param->string)) {
			xfs_warn(parsing_mp,
	"cluster=: a name is 1-%d characters of A-Z a-z 0-9 . _ -",
				 MXFS_CLUSTER_NAME_LEN - 1);
			return -EINVAL;
		}
		kfree(parsing_mp->m_mxfs_cluster_name);
		parsing_mp->m_mxfs_cluster_name = kstrdup(param->string,
							   GFP_KERNEL);
		if (!parsing_mp->m_mxfs_cluster_name)
			return -ENOMEM;
		return 0;
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
 * sess447 (D-FOREIGN-REPLAY-UNGATED-IMAGES, design-consult ruling "scoped
 * coherence-only default flip", 0.54.0): foreign_replay_token_enforce now
 * DEFAULTS TO 1 — an ordinary node death under the old default 0 ended in
 * POLICY-REFUSED + AG quarantine + survivor EIO (measured sess438).  The
 * token gate is sound only inside an admitted DURABILITY DOMAIN, so every
 * clustered (envelope) RW mount is validated here, at mount time and on a
 * ro->rw remount, before any recovery write.  The truth table (no silent
 * fallback to blanket refusal, no downgrade — every invalid row refuses):
 *
 *   fua_disable=1, target_cache_protected=0  -> REFUSED (tenure-boundary
 *       flushes are no-ops; a target write-cache loss can persist the
 *       release CAS while dropping the home writes it certified — F2)
 *   fua_disable=1, target_cache_protected=1  -> ADMITTED, coherence-only
 *       domain (node/host death covered; target power loss declared out
 *       of scope by the operator)
 *   fua_disable=0                            -> REFUSED in this release:
 *       the crash-durable domain is NOT yet qualified (sess197 step 7
 *       durable ordering at every peer-claimable release, epoch-mint
 *       durability, the stable-media oracle) — see
 *       D-CRASH-DURABLE-DOMAIN-UNQUALIFIED-0516
 *   icluster_dlm=1                           -> REFUSED (cluster-routed
 *       inode tenures release without a clean-release certificate)
 *   foreign_replay_token_enforce=0           -> REFUSED (the unsafe
 *       shadow-only legacy; A/B control on a non-clustered mount only)
 *   release_proof_enforce=0                  -> REFUSED (release evidence
 *       untrustworthy for the token gate)
 * Read-only mounts are not gated (they take no tenure and replay nothing
 * under the token gate's authority).
 */
/*
 * sess448 (design-consult ruling ccloop-c7ee71c6-sess448-GPT-ruling-iclus-relmark-
 * certificate-and-sequencing): the ICLUSTER clean-release certificate
 * (ic->auth_lineage + marker before the cluster unlock CAS) is LANDED but
 * not yet rig-verified; production readiness is a property of the BUILD.
 * 0 = the validator keeps refusing icluster_dlm=1.  A LAB build passes
 * KCFLAGS=-DMXFS_ICLUS_RELMARK_READY=1 to exercise the marker path on the
 * rig (announced in P-DOMAIN-ADMITTED); no runtime bypass exists.  Flip
 * the default to 1 only in a reviewed change carrying the ruling's
 * evidence list (positive laps, 9-point fault injection, counters).
 */
#ifndef MXFS_ICLUS_RELMARK_READY
#define MXFS_ICLUS_RELMARK_READY	0
#endif
#if MXFS_ICLUS_RELMARK_READY
/* srcversion hashes SOURCE, so a -D build is otherwise indistinguishable
 * from production: name it in modinfo (tests gate on this field). */
MODULE_INFO(mxfs_iclus_relmark_lab, "1");
#endif

/*
 * Transport admission.  From 0.55.0 to 0.72.x a clustered RW mount whose
 * selected DLM transport was TCP was refused here (-EPERM, P-DOMAIN-REFUSED
 * "transport is not CAW"): the TCP transport minted no durable authority
 * epochs, so under token enforcement every dead peer's slice would have been
 * refused and its AGs quarantined, and admitting such a mount was a silent
 * fallback into an unqualified recovery domain.  0.73.0 lifts that arm.
 * The TCP authority ledger (steps 1-5, 0.30.0-0.71.0) now mints per-grant
 * authority epochs and a sealed fence-time manifest gives foreign replay
 * its authority source on TCP; on the 2-node TCP cluster a dirty death is
 * fenced, replayed and published with every fsync-acknowledged file readable
 * from the survivor (tests/tcp_death_replay.sh, sess502-504).  Both
 * transports are therefore admitted; the lab-only compile flag that used to
 * lift the refusal is gone, so a production build and a lab build behave
 * the same.  The transport is still only known once the DLM is initialised,
 * so this arm keeps its place right after mxfs_v5_dlm_init and on the ro->rw
 * reconfigure: a mount that reaches it with NO DLM transport selected at all
 * is refused, since nothing downstream can fence or replay for it.
 */
static int
mxfs_transport_domain_admit(
	struct xfs_mount	*mp)
{
	if (!mp->m_mxfs_has_envelope || xfs_is_readonly(mp) || !mp->m_mxfs_dlm)
		return 0;
	if (mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm) ||
	    mxfs_v5_dlm_transport_tcp(mp->m_mxfs_dlm))
		return 0;
	xfs_alert(mp,
	"MXFS P-DOMAIN-REFUSED clustered RW mount REFUSED: no DLM transport is selected (neither CAW nor TCP), so no dead peer could be fenced or replayed");
	return -EPERM;
}

static int
mxfs_durability_domain_admit(
	struct xfs_mount	*mp)
{
	const char		*why = NULL;

	if (!mp->m_mxfs_has_envelope || xfs_is_readonly(mp))
		return 0;
	if (mxfs_icluster_dlm && !MXFS_ICLUS_RELMARK_READY)
		why = "icluster_dlm=1 (cluster-routed inode tenures' clean-release certificate is not yet qualified in this build); load the module with icluster_dlm=0";
	else if (!READ_ONCE(mxfs_foreign_replay_token_enforce))
		why = "foreign_replay_token_enforce=0 (blanket refusal of every dead peer's slice: POLICY-REFUSED + AG quarantine on an ordinary death); leave it at its default 1";
	else if (!mxfs_release_proof_enforce)
		why = "release_proof_enforce=0 (a failed completion proof would not block the release CAS); leave it at its default 1";
	else if (READ_ONCE(mxfs_fua_disable) && !READ_ONCE(mxfs_target_cache_protected))
		why = "fua_disable=1 with target_cache_protected=0: tenure-boundary flushes are no-ops, so a target write-cache loss can persist a release while dropping the writes it certified; declare mxfs.target_cache_protected=1 (target power loss out of durability scope — coherence-only domain)";
	else if (!READ_ONCE(mxfs_fua_disable))
		why = "fua_disable=0: the crash-durable domain is not yet qualified in this release (durable ordering at every peer-claimable release + stable-media oracle outstanding, D-0516); run the coherence-only domain (fua_disable=1 target_cache_protected=1) on a cache-protected target";
	if (why) {
		xfs_alert(mp,
	"MXFS P-DOMAIN-REFUSED clustered RW mount REFUSED: %s (foreign_replay_token_enforce=%d release_proof_enforce=%d fua_disable=%d target_cache_protected=%d icluster_dlm=%d)",
			  why, READ_ONCE(mxfs_foreign_replay_token_enforce),
			  mxfs_release_proof_enforce, READ_ONCE(mxfs_fua_disable),
			  READ_ONCE(mxfs_target_cache_protected), mxfs_icluster_dlm);
		return -EPERM;
	}
	return 0;
}

/*
 * sess461 (chain 86 domain_admission_matrix R8): the ADMITTED verdict is
 * announced only once EVERY admission arm has passed — the durability
 * domain above AND the transport arm, which can only run after the DLM
 * has selected its transport.  Printing it from the durability helper
 * announced a mount as admitted two seconds before the transport arm
 * refused it (P-DOMAIN-ADMITTED then P-DOMAIN-REFUSED for one attempt),
 * which is a false verdict for anyone reading the log.
 */
static void
mxfs_domain_admitted_announce(
	struct xfs_mount	*mp)
{
	if (!mp->m_mxfs_has_envelope || xfs_is_readonly(mp))
		return;
	xfs_notice(mp,
	"MXFS P-DOMAIN-ADMITTED clustered RW mount in the COHERENCE-ONLY durability domain (fua_disable=1 target_cache_protected=1): node/host death is recovered under token enforcement; target power loss / volatile target-cache loss is declared out of scope (foreign_replay_token_enforce=%d release_proof_enforce=%d icluster_dlm=%d%s transport=%s)",
		   READ_ONCE(mxfs_foreign_replay_token_enforce),
		   mxfs_release_proof_enforce, mxfs_icluster_dlm,
		   mxfs_icluster_dlm ? " ICLUS-RELMARK-LAB-BUILD" : "",
		   mp->m_mxfs_dlm && mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm) ?
			"CAW" : "TCP");
}

/*
 * Fix 3c (sess180 ruling, D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE):
 * operator assertion that no other initiator can write this host's MXFS
 * block devices (single-host deployment / exclusive LUN masking).  It USED to
 * let a single-node mount certify SINGLE_NODE_EXCLUSIVE for a dead slot whose
 * exclusion SCSI PR could not prove, so that slot's dirty journal slice was
 * replayed instead of blocked.
 *
 * 0.89.18: it no longer authorises any recovery.  The assertion is about which
 * INITIATORS may write; a dead slot belongs to a previous INCARNATION whose
 * already-accepted writes the target may still be finishing, and replaying
 * against those is silent corruption.  Kind 17 is revoked, nothing mints it,
 * and setting this parameter will not unblock a recovery.  It is still read
 * and still recorded as write-time provenance, so a deployment that sets it is
 * described rather than silently ignored (module param defined with the others
 * below).
 */
static unsigned int mxfs_single_node_exclusive;
static unsigned int mxfs_fence_capability_override;

/*
 * sess482: sampled verification of the dentry-revalidation AFFINE fast path.
 *
 * That exit blesses a cached (parent, name) -> inode binding as valid, with no
 * coordinated lookup and no check of the parent's hold epoch, whenever the
 * CHILD inode lives in this node's own affine allocation group.  The premise it
 * states is about the child ("under node-affine allocation we own it"); the
 * claim it needs is about the PARENT ("this name still resolves here").  Those
 * are different properties: allocation locality gives a node authority over an
 * inode, not over a directory entry that any node may rewrite.
 *
 * Two successive probes tried to measure the gap by comparing dentry->d_time
 * against the parent's epoch, and neither could: the population reaching that
 * exit is, by construction, the population that never reaches the one site in
 * the tree where d_time is written.  A percentage knob is the honest instrument
 * instead -- take a sampled fraction of blessings down the coordinated path
 * that already computes the correct verdict, and compare.  It answers the
 * question directly ("would the coordinated lookup have agreed?") and needs no
 * new machinery.
 *
 * It is a sampled INTERLOCK, not a passive observer: an audited blessing that
 * turns out to be wrong is also refused, so the miss count is the number of bad
 * bindings CAUGHT, and is a lower bound on the number that would have been
 * served without it.  A zero is meaningful only alongside the audit count --
 * which is why the count is reported and not just the misses.
 *
 * 0 (the default) leaves every path byte-identical to shipping behaviour.
 */
static unsigned int mxfs_affine_audit_pct;
/* 0.75.35 (D-482 verification): parent inode whose zero-I/O dentry
 * blessings are printed (P-DREVAL-EPOCH-FAST); 0 = off. */
unsigned long long mxfs_dbg_dreval_trace_ino;	/* also read by xfs_vn_lookup */
module_param_named(dbg_dreval_trace_ino, mxfs_dbg_dreval_trace_ino, ullong, 0644);
MODULE_PARM_DESC(dbg_dreval_trace_ino, "DEBUG: print every fast-path dentry blessing (epoch or affine) and every stale-flag rejection under this parent inode (0=off)");
static atomic64_t mxfs_affine_audit_n = ATOMIC64_INIT(0);	/* sampled     */
static atomic64_t mxfs_affine_audit_ok = ATOMIC64_INIT(0);	/* blessing OK */
static atomic64_t mxfs_affine_audit_gone = ATOMIC64_INIT(0);	/* name gone   */
static atomic64_t mxfs_affine_audit_rebind = ATOMIC64_INIT(0);	/* other ino   */
static atomic64_t mxfs_affine_audit_incarn = ATOMIC64_INIT(0);	/* stale incarn*/
static atomic64_t mxfs_affine_audit_operr = ATOMIC64_INIT(0);	/* NOT a miss  */

/*
 * 0.75.37: the audit counters are the record, and until now they were
 * readable only through the summary line printed every 10,000 audits — a
 * two-node harness that audits a few hundred lookups had no denominator at
 * all.  Read-only, one line, the same fields as the summary.
 */
static int mxfs_affine_audit_stats_get(char *buf, const struct kernel_param *kp)
{
	return scnprintf(buf, PAGE_SIZE,
			 "n=%lld ok=%lld gone=%lld rebind=%lld incarn=%lld operr=%lld\n",
			 (long long)atomic64_read(&mxfs_affine_audit_n),
			 (long long)atomic64_read(&mxfs_affine_audit_ok),
			 (long long)atomic64_read(&mxfs_affine_audit_gone),
			 (long long)atomic64_read(&mxfs_affine_audit_rebind),
			 (long long)atomic64_read(&mxfs_affine_audit_incarn),
			 (long long)atomic64_read(&mxfs_affine_audit_operr));
}
static const struct kernel_param_ops mxfs_affine_audit_stats_ops = {
	.get = mxfs_affine_audit_stats_get,
};
module_param_cb(affine_audit_stats, &mxfs_affine_audit_stats_ops, NULL, 0444);
MODULE_PARM_DESC(affine_audit_stats, "read-only: affine fast-path audit counters n/ok/gone/rebind/incarn/operr");

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
	/* sess482: this revalidation was diverted off the affine fast path so
	 * the coordinated verdict can be compared against the blessing that
	 * exit would have given.  See mxfs_affine_audit_pct. */
	bool			affine_audited = false;

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

	/*
	 * 0.72.2 (D-SURVIVOR-SINGLE-NODE-BYPASS-SERVES-STALE-VIEW-AFTER-PEER-
	 * DEATH-0904): a mount that never had a peer may bless every cached
	 * dentry — nobody else could have created, unlinked or renamed a name.
	 * The SOLE SURVIVOR of a peer's death may not: a negative dentry it
	 * cached before the dead peer created that name, or a positive one for
	 * a name the peer unlinked, is exactly what the coordinated validation
	 * below exists to catch, and with no peer left nothing else will ever
	 * drop it.  The survivor therefore keeps taking the multi-node path;
	 * its hold-epoch fast paths still make an unchanged directory cost
	 * zero I/O.
	 */
	if (!dp->i_mount->m_mxfs_dlm ||
	    (mxfs_v5_dlm_is_single_node(dp->i_mount->m_mxfs_dlm) &&
	     !mxfs_v5_dlm_sole_survivor(dp->i_mount->m_mxfs_dlm))) {
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
		 * sess86 Part A (Gemini design-consult): respect a stale flag already set
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
		/* sess318: MXFS_IF_INCARN_STALE added — the poison site sets
		 * only the iflag (i_dlm_stale comes later, at lookup retire),
		 * so a poisoned child's dentry was still blessed here in the
		 * poison→first-relookup window. */
		if (ip->i_dlm_stale ||
		    xfs_iflags_test(ip, XFS_ISTALE_CAW) ||
		    xfs_iflags_test(ip, MXFS_IF_INCARN_STALE)) {
			/*
			 * Force re-resolution through xfs_lookup, which re-reads the
			 * current dir block + evicts a genuinely-reused inode.  The
			 * stuck-XFS_ISTALE_CAW false-positive loop (sess91) is broken
			 * in xfs_lookup AFTER the fresh dir lookup (so rename/unlink
			 * content stays visible), NOT here — clearing the flag here
			 * removed the dir-content re-read trigger and regressed
			 * rename_visibility.
			 */
			/* 0.75.44: uncapped under the traced parent (harness
			 * evidence, see P-VNLOOKUP); ratelimited for the wide knobs. */
			if (unlikely(READ_ONCE(mxfs_dbg_dreval_trace_ino) == dp->i_ino))
				pr_info("mxfs: P-DREVAL-STALEFLAG ino=%llu istale_caw=%d dlm_stale=%d stale_src=%u incarn_stale=%d dp=%llu name=%.*s\n",
					(unsigned long long)ip->i_ino,
					!!xfs_iflags_test(ip, XFS_ISTALE_CAW),
					ip->i_dlm_stale, ip->i_dlm_stale_src,
					!!xfs_iflags_test(ip, MXFS_IF_INCARN_STALE),
					(unsigned long long)dp->i_ino,
					dentry->d_name.len, dentry->d_name.name);
			else if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				pr_warn_ratelimited(
					"mxfs: P-DREVAL-STALEFLAG ino=%llu istale_caw=%d dlm_stale=%d stale_src=%u incarn_stale=%d dp=%llu name=%.*s\n",
					(unsigned long long)ip->i_ino,
					!!xfs_iflags_test(ip, XFS_ISTALE_CAW),
					ip->i_dlm_stale, ip->i_dlm_stale_src,
					!!xfs_iflags_test(ip, MXFS_IF_INCARN_STALE),
					(unsigned long long)dp->i_ino,
					dentry->d_name.len, dentry->d_name.name);
			dput(parent);
			return 0;
		}
		/*
		 * v0.5.1 DLM hold-epoch fast path (proven by instrument, sess19 ccloop:
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
			/* 0.75.35 (D-482 verification): name every zero-I/O
			 * blessing under the traced parent, so a harness can
			 * prove a dentry WAS fast-path valid before a grant
			 * loss and is NOT after it. */
			if (unlikely(READ_ONCE(mxfs_dbg_dreval_trace_ino) == dp->i_ino))
				pr_info("mxfs: P-DREVAL-EPOCH-FAST dp=%llu name=%.*s d_time=%lu epoch=%lu positive=1\n",
					(unsigned long long)dp->i_ino,
					dentry->d_name.len, dentry->d_name.name,
					dentry->d_time, READ_ONCE(dp->i_dlm_epoch));
			dput(parent);
			return 1;
		}
		/*
		 * sess126 FIX (proven by instrument + design-consult Gemini): EXCLUDE DIRECTORY
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
			/*
			 * sess481: THE PROBE ABOVE WAS VACUOUS AND ITS 229,444
			 * HITS MEANT NOTHING.  Measured on 0.64.37 over one
			 * 32-node crash_consistency row: 229,444 of 229,444
			 * P165 lines carried d_time=0 -- 100.0% -- with
			 * dp_epoch=1 on 99.2% of them.
			 *
			 * The reason is structural.  d_time is stamped in
			 * exactly ONE place (the `ret == 1` tail of the
			 * coordinated validation below), and this affine
			 * fast-path RETURNS BEFORE REACHING IT.  A dentry that
			 * takes this exit is therefore never stamped, keeps
			 * d_time == 0, and can never equal an epoch that starts
			 * at 1 (xfs_mxfs_dlm.c:38672 sets i_dlm_epoch = 1 for
			 * precisely that reason).  So the sess10 premise --
			 * "a fresh binding validated this epoch never
			 * mismatches, a resurrected/stale one always does" --
			 * is false for the population this exit samples: a
			 * fresh binding here is never validated, so it always
			 * mismatches too.  The test could not separate the two
			 * cases it was written to separate, and it emitted 8%
			 * of the entire kernel log saying so.
			 *
			 * A dentry with d_time != 0 DID pass coordinated
			 * validation at some epoch.  Seeing one blessed under a
			 * DIFFERENT epoch is the actual resurrection signature,
			 * and that is what is printed now.  The fresh
			 * population is counted rather than printed, because
			 * dropping it silently would remove the denominator and
			 * make a future zero unreadable.
			 */
			if (dentry->d_time &&
			    dentry->d_time != READ_ONCE(dp->i_dlm_epoch)) {
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
			} else if (!dentry->d_time) {
				static atomic_t p165fresh = ATOMIC_INIT(0);
				int p165_fn = atomic_inc_return(&p165fresh);

				/* the denominator, at 1/100000 the volume */
				if ((p165_fn % 100000) == 0)
					pr_warn("mxfs: P165-AFFINE-FRESH n=%d — affine fast-path blessings of never-validated dentries (d_time=0); these are NOT evidence of staleness, see the comment above\n",
						p165_fn);
			}
			/*
			 * sess482: NEITHER probe above can decide this exit, and
			 * no refinement of them can, because both interrogate
			 * d_time.  d_time is written in exactly one place -- the
			 * ret==1 tail of the coordinated validation below -- and
			 * this exit returns before reaching it.  Of the three
			 * conjuncts that select this exit, m_maxagi and the
			 * inode's AG (fixed with the inode number, which is fixed
			 * for a positive dentry's life) and m_mxfs_node_slot
			 * (assigned once, at fill_super) are all invariant; only
			 * the child's in-core S_IFMT can change.  So an affine
			 * regular-file dentry is blessed here on every lookup for
			 * its whole life and is never once validated.  d_time
			 * stays 0 -- measured 229,444 of 229,444 across a 32-node
			 * row -- and a test on d_time is therefore silent on
			 * exactly the population that carries the risk.  A zero
			 * from such a test is not evidence of absence; it is the
			 * test declining to sample.
			 *
			 * What the exit actually needs checking is whether the
			 * binding it blesses is still real, and the coordinated
			 * path below already decides precisely that.  So send a
			 * sampled fraction down it and compare verdicts.
			 */
			if (READ_ONCE(mxfs_affine_audit_pct)) {
				unsigned int pct = READ_ONCE(mxfs_affine_audit_pct);

				if (pct > 100)
					pct = 100;
				if ((get_random_u32() % 100U) < pct)
					affine_audited = true;
			}
			/* 0.75.37 (D-AFFINE verification): name every arrival
			 * at this exit under the traced parent, blessed or
			 * diverted, so a harness can tell "served stale here"
			 * from "never reached this exit at all". */
			if (unlikely(READ_ONCE(mxfs_dbg_dreval_trace_ino) == dp->i_ino))
				pr_info("mxfs: P-DREVAL-AFFINE-FAST dp=%llu name=%.*s ino=%llu d_time=%lu epoch=%lu dp_mode=%d audited=%d\n",
					(unsigned long long)dp->i_ino,
					dentry->d_name.len, dentry->d_name.name,
					(unsigned long long)ip->i_ino,
					dentry->d_time,
					(unsigned long)READ_ONCE(dp->i_dlm_epoch),
					READ_ONCE(dp->i_dlm_mode),
					affine_audited ? 1 : 0);
			if (!affine_audited) {
				dput(parent);
				return 1;
			}
			/* fall through to the coordinated validation */
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
			if (unlikely(READ_ONCE(mxfs_dbg_dreval_trace_ino) == dp->i_ino))
				pr_info("mxfs: P-DREVAL-EPOCH-FAST dp=%llu name=%.*s d_time=%lu epoch=%lu positive=0\n",
					(unsigned long long)dp->i_ino,
					dentry->d_name.len, dentry->d_name.name,
					dentry->d_time, READ_ONCE(dp->i_dlm_epoch));
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
	 * sess133 PROVEN ROOT FIX (instrumented, live /proc/pid/stack +
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
		 * sess86 Part C (Gemini design-consult): reused-inode (SAME number, SAME
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
			 * sess126 ROOT FIX (instrument step 2b, proven by P-IRESURRECT):
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
	 * sess71 INSTR (instrumented): Face A = inode-number REUSE type confusion.
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
		 * sess89 (instrumented): convert sess71's detect-only TYPEMISS into a
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
	 * sess482: this revalidation was diverted off the affine fast path.
	 * The blessing that exit would have given is unconditionally VALID, so
	 * the coordinated verdict now in hand is a direct measurement of
	 * whether that blessing was right.
	 *
	 * An operational failure of the lookup itself (-EIO, -ENOMEM, a lock
	 * that could not be taken) is NOT a wrong blessing and is counted
	 * apart: the coordinated path maps every error to INVALID because that
	 * is the safe answer for the VFS, but only -ENOENT means the name is
	 * genuinely gone.  Reporting the two together would manufacture
	 * corruption out of transport noise.
	 *
	 * Counters, not log lines, are the record: a miss rate is only
	 * readable against the number of audits taken, and the per-event
	 * warning is ratelimited precisely when a real fault would produce
	 * the most of it.
	 */
	if (affine_audited && ip) {
		long long n = atomic64_inc_return(&mxfs_affine_audit_n);
		const char *kind = NULL;

		if (error == -ENOENT) {
			atomic64_inc(&mxfs_affine_audit_gone);
			kind = "GONE";		/* a peer unlinked the name    */
		} else if (error) {
			atomic64_inc(&mxfs_affine_audit_operr);
		} else if (actual_ino != ip->i_ino) {
			atomic64_inc(&mxfs_affine_audit_rebind);
			kind = "REBIND";	/* the name is someone else's  */
		} else if (ret == 0) {
			atomic64_inc(&mxfs_affine_audit_incarn);
			kind = "INCARN";	/* same number, dead incarnation */
		} else {
			atomic64_inc(&mxfs_affine_audit_ok);
		}

		if (kind)
			pr_warn_ratelimited(
				"mxfs: P165-AFFINE-AUDIT-MISS kind=%s name=%.*s ino=%llu dp=%llu actual_ino=%llu error=%d ret=%d — the affine fast path would have blessed this binding\n",
				kind, dentry->d_name.len, dentry->d_name.name,
				(unsigned long long)ip->i_ino,
				(unsigned long long)dp->i_ino,
				(unsigned long long)actual_ino,
				error, ret);

		if ((n % 10000) == 0)
			pr_warn("mxfs: P165-AFFINE-AUDIT n=%lld ok=%lld gone=%lld rebind=%lld incarn=%lld operr=%lld pct=%u\n",
				n,
				(long long)atomic64_read(&mxfs_affine_audit_ok),
				(long long)atomic64_read(&mxfs_affine_audit_gone),
				(long long)atomic64_read(&mxfs_affine_audit_rebind),
				(long long)atomic64_read(&mxfs_affine_audit_incarn),
				(long long)atomic64_read(&mxfs_affine_audit_operr),
				READ_ONCE(mxfs_affine_audit_pct));
	}

	/*
	 * v0.5.1: coordinated validation passed — stamp the pre-lookup
	 * hold-epoch so the next cached lookup under an unbounced grant
	 * takes the zero-I/O fast path above.
	 *
	 * sess482: not for an audited affine dentry.  Stamping it would let it
	 * take the epoch fast path from then on, removing it from the very
	 * population being sampled — the audit would drain its own denominator
	 * and the miss rate would fall for a reason that has nothing to do with
	 * the filesystem.  Leaving it unstamped is also what happens today,
	 * since this exit is one it never reaches when the knob is off.
	 */
	if (ret == 1 && !affine_audited)
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
	struct mxfs_v5_dlm_slot_release dl_late = {0};
	/* sess454 (D3): the failed-mount unwind's late release runs after
	 * the shared teardown chain below, under the departure lock. */
	bool			late_release = false, late_drained = true;
	int			late_flush_rc = 0;

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
				/*
				 * The cluster name must agree before anything
				 * clustered starts: a node configured for another
				 * cluster hears none of this one's peers and would
				 * otherwise run alone against the shared disk.
				 * Either side naming a cluster the other does not
				 * is a mismatch.
				 */
				{
					bool named = msup->flags &
						     MXFS_FORMAT_F_CLUSTER_NAME;
					char disk[MXFS_CLUSTER_NAME_LEN];
					const char *want = mp->m_mxfs_cluster_name;

					memcpy(disk, msup->cluster_name, sizeof(disk));
					disk[sizeof(disk) - 1] = '\0';
					if (named && !want)
						xfs_alert(mp,
	"MXFS: this filesystem belongs to cluster '%s'; mount it with -o cluster=%s",
							  disk, disk);
					else if (!named && want)
						xfs_alert(mp,
	"MXFS: mounted with cluster=%s but this filesystem has no cluster name (set one with mxfs_admin -c)",
							  want);
					else if (named && strcmp(disk, want))
						xfs_alert(mp,
	"MXFS: this filesystem belongs to cluster '%s', not '%s'; refusing mount",
							  disk, want);
					if (named != !!want ||
					    (named && strcmp(disk, want))) {
						kfree(msup);
						error = -EINVAL;
						goto out_free_scrub_stats;
					}
				}
				mp->m_ddev_targp->bt_sector_offset = off;
				mp->m_mxfs_has_envelope = true;
				mp->m_mxfs_journal_offset = msup->journal_offset;
				mp->m_mxfs_disklock_offset = msup->disklock_offset;
				/* sess404: recovery manifest region
				 * (docs/recovery-manifest.md).  Gen 7 requires
				 * it; the gate below already refuses a super
				 * whose cluster_proto_gen != MXFS_PROTO_GEN, and
				 * mkfs writes the flag with gen 7, so a gated
				 * gen-7 super without it is a format fault. */
				if (msup->flags & MXFS_FORMAT_F_RMAN) {
					mp->m_mxfs_rman_offset = msup->rman_offset;
					mp->m_mxfs_rman_size = msup->rman_size;
					if (msup->rman_size != MXFS_RMAN_REGION_BYTES ||
					    msup->rman_offset + msup->rman_size >
					    msup->xfs_data_offset) {
						xfs_warn(mp,
		"MXFS: envelope recovery-manifest region malformed (offset=%llu size=%llu xfs_data_offset=%llu expected size %llu) — refusing mount",
							 (unsigned long long)msup->rman_offset,
							 (unsigned long long)msup->rman_size,
							 (unsigned long long)msup->xfs_data_offset,
							 (unsigned long long)MXFS_RMAN_REGION_BYTES);
						kfree(msup);
						error = -EINVAL;
						goto out_free_scrub_stats;
					}
				} else {
					mp->m_mxfs_rman_offset = 0;
					mp->m_mxfs_rman_size = 0;
				}
				/* sess421: TCP authority ledger region
				 * (docs/tcp-authority-ledger.md).  Gen 8
				 * requires it; validated like the manifests. */
				if (msup->flags & MXFS_FORMAT_F_TAUTH) {
					mp->m_mxfs_tauth_offset = msup->tauth_offset;
					mp->m_mxfs_tauth_size = msup->tauth_size;
					/* sess427 (D-0348 step 2): the region is
					 * mkfs-sized; the envelope must hold at least
					 * the minimum geometry and a whole number of
					 * pages.  The exact page count is validated
					 * against this size by the store when the
					 * ledger opens (tauth_store.c). */
					if (msup->tauth_size < MXFS_TAUTH_REGION_BYTES ||
					    msup->tauth_size % MXFS_TAUTH_PAGE_BYTES ||
					    msup->tauth_offset + msup->tauth_size >
					    msup->xfs_data_offset) {
						xfs_warn(mp,
		"MXFS: envelope authority-ledger region malformed (offset=%llu size=%llu xfs_data_offset=%llu minimum size %llu) — refusing mount",
							 (unsigned long long)msup->tauth_offset,
							 (unsigned long long)msup->tauth_size,
							 (unsigned long long)msup->xfs_data_offset,
							 (unsigned long long)MXFS_TAUTH_REGION_BYTES);
						kfree(msup);
						error = -EINVAL;
						goto out_free_scrub_stats;
					}
				} else {
					mp->m_mxfs_tauth_offset = 0;
					mp->m_mxfs_tauth_size = 0;
				}
				/* sess438: the PR registrant ledger region
				 * (docs/whole-cluster-restart.md item 2).  Gen 12
				 * requires it: without a ledger a 64-bit per-boot
				 * key has no durable owner record. */
				if (msup->flags & MXFS_FORMAT_F_PRKEY64) {
					mp->m_mxfs_prkey_offset = msup->prkey_offset;
					mp->m_mxfs_prkey_size = msup->prkey_size;
					if (msup->prkey_size < MXFS_PRLEDGER_ENTRY_BYTES ||
					    msup->prkey_size % MXFS_PRLEDGER_ENTRY_BYTES ||
					    msup->prkey_offset + msup->prkey_size >
					    msup->xfs_data_offset) {
						xfs_warn(mp,
		"MXFS: envelope PR registrant ledger region malformed (offset=%llu size=%llu xfs_data_offset=%llu) — refusing mount",
							 (unsigned long long)msup->prkey_offset,
							 (unsigned long long)msup->prkey_size,
							 (unsigned long long)msup->xfs_data_offset);
						kfree(msup);
						error = -EINVAL;
						goto out_free_scrub_stats;
					}
				} else {
					mp->m_mxfs_prkey_offset = 0;
					mp->m_mxfs_prkey_size = 0;
				}
				/* sess439: the whole-cluster bootstrap record region
				 * (docs/whole-cluster-restart.md §5).  Gen 13
				 * requires it. */
				if (msup->flags & MXFS_FORMAT_F_BOOTSTRAP) {
					mp->m_mxfs_bootstrap_offset = msup->bootstrap_offset;
					mp->m_mxfs_bootstrap_size = msup->bootstrap_size;
					if (msup->bootstrap_size < MXFS_BOOTSTRAP_REC_BYTES ||
					    msup->bootstrap_offset % 512 ||
					    msup->bootstrap_offset + msup->bootstrap_size >
					    msup->xfs_data_offset) {
						xfs_warn(mp,
		"MXFS: envelope bootstrap record region malformed (offset=%llu size=%llu xfs_data_offset=%llu) — refusing mount",
							 (unsigned long long)msup->bootstrap_offset,
							 (unsigned long long)msup->bootstrap_size,
							 (unsigned long long)msup->xfs_data_offset);
						kfree(msup);
						error = -EINVAL;
						goto out_free_scrub_stats;
					}
				} else {
					mp->m_mxfs_bootstrap_offset = 0;
					mp->m_mxfs_bootstrap_size = 0;
				}
				/* 0.88.0: the slice lifecycle region (D-SLICE-
				 * CLAIM-TIME-INIT-UNTRUSTED-ZERO-531): one 512 B
				 * record per log slice; gen 20 requires it.  A
				 * volume without it mounts with today's behaviour
				 * and says so at the claim (P-SLIFE-LEGACY). */
				if (msup->flags & MXFS_FORMAT_F_SLIFE) {
					mp->m_mxfs_slife_offset = msup->slife_offset;
					mp->m_mxfs_slife_size = msup->slife_size;
					if (msup->slife_size <
					    (uint64_t)msup->xfs_log_node_count *
						MXFS_SLIFE_RECORD_SIZE ||
					    msup->slife_offset % 512 ||
					    msup->slife_offset + msup->slife_size >
					    msup->xfs_data_offset) {
						xfs_warn(mp,
	"MXFS: envelope slice lifecycle region malformed (offset=%llu size=%llu slices=%u xfs_data_offset=%llu) — refusing mount",
							 (unsigned long long)msup->slife_offset,
							 (unsigned long long)msup->slife_size,
							 msup->xfs_log_node_count,
							 (unsigned long long)msup->xfs_data_offset);
						kfree(msup);
						error = -EINVAL;
						goto out_free_scrub_stats;
					}
				} else {
					mp->m_mxfs_slife_offset = 0;
					mp->m_mxfs_slife_size = 0;
				}
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
				/* sess466: directory-sharding envelope gate
				 * (docs/dir-sharding.md); the sb incompat bit
				 * and clustered mode are the other two. */
				mp->m_mxfs_dirshard_env =
					(msup->flags & MXFS_FORMAT_F_DIRSHARD_VALUE) != 0;
				xfs_notice(mp,
					"MXFS envelope v%u: XFS data at offset %llu (%llu sectors) proto_gen=%u dirshard=%s cluster=%s",
					msup->version,
					(unsigned long long)msup->xfs_data_offset,
					(unsigned long long)off,
					mp->m_mxfs_cluster_proto_gen,
					mp->m_mxfs_dirshard_env ? "formatted" : "off",
					mp->m_mxfs_cluster_name ?: "(none)");
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
#if !defined(MXFS_HAVE_IOMAP_ITER_PRIVATE) || !defined(MXFS_DIO_IOEND_BIOSET)
		/*
		 * A zoned write carries its allocation context to the iomap
		 * callbacks in iomap_iter->private and allocates its bios from
		 * iomap_ioend_bioset through iomap_dio_ops->bio_set.  This
		 * kernel's iomap lacks one of them (6.8 exports no ioend set,
		 * RHEL 9 has neither), so no zoned write could reach its
		 * reservation: refused here, before anything runs.
		 */
		xfs_alert(mp,
	"zoned realtime devices need an iomap with a private context and a dio bio_set, which this kernel does not have");
		error = -EOPNOTSUPP;
		goto out_filestream_unmount;
#endif
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
		/* B1 (D-MIXED-VERSION-UNGATED-REPLAY): every admitted branch
		 * of the C7 chain above — gated exact-match or the explicit
		 * legacy_rw opt-in — falls through to here; every refusal
		 * jumped out.  Recovery entry points in xfs_log.c assert
		 * this before applying any log image. */
		mp->m_mxfs_proto_admitted = true;
		/* sess447 (D-FOREIGN-REPLAY-UNGATED-IMAGES default-on, design-consult
		 * ruling): the durability-domain admission for a clustered RW
		 * mount.  Refuses before any recovery write. */
		error = mxfs_durability_domain_admit(mp);
		if (error)
			goto out_filestream_unmount;
		/*
		 * v5 sess33: pick max_dlm_lock_caw from the per-mount override
		 * (set via mount option, future work) or fall back to the
		 * module-wide auto-sized mxfs_cache_caps.dlm_lock computed at
		 * module load.
		 */
		int max_dlm_caw = mp->m_mxfs_max_dlm_lock_caw > 0 ?
				  mp->m_mxfs_max_dlm_lock_caw :
				  mxfs_cache_caps.dlm_lock;
		/*
		 * THIS INCARNATION'S AUTHORITY, INSTALLED BEFORE THE DLM EXISTS.
		 *
		 * The gate that decides whether a mutating submission may reach
		 * the shared LUN asks this object, and it has to exist from the
		 * first instant a clustered mutation is possible — which is
		 * before mxfs_v5_dlm_init returns, not after.  The mount owns it
		 * and keeps its reference until xfs_mount_free, long after the
		 * DLM, the disklock and the heartbeat are gone, because the work
		 * it governs is still being submitted then.  m_mxfs_clustered is
		 * set in the same breath and never cleared: "this mount must hold
		 * authority to write" is a property of the incarnation, and a
		 * pointer that teardown clears cannot express it.
		 */
		mp->m_mxfs_auth = mxfs_authority_alloc();
		if (!mp->m_mxfs_auth) {
			error = -ENOMEM;
			goto out_filestream_unmount;
		}
		mp->m_mxfs_clustered = true;
		struct mxfs_v5_dlm_opts dlm_opts = {
			.authority = mp->m_mxfs_auth,
			.transport = MXFS_V5_TRANSPORT_CAW,
			.disklock_offset = mp->m_mxfs_disklock_offset,
			.journal_offset = mp->m_mxfs_journal_offset,
			.rman_offset = mp->m_mxfs_rman_offset,
			.rman_size = mp->m_mxfs_rman_size,
			.tauth_offset = mp->m_mxfs_tauth_offset,
			.tauth_size = mp->m_mxfs_tauth_size,
			.prkey_offset = mp->m_mxfs_prkey_offset,
			.prkey_size = mp->m_mxfs_prkey_size,
			.bootstrap_offset = mp->m_mxfs_bootstrap_offset,
			.bootstrap_size = mp->m_mxfs_bootstrap_size,
			.slife_offset = mp->m_mxfs_slife_offset,
			.slife_size = mp->m_mxfs_slife_size,
			.max_nodes = mp->m_mxfs_max_nodes,
			.peers = mp->m_mxfs_peers,
			.bdev = mp->m_ddev_targp->bt_bdev,
			.max_dlm_lock_caw = max_dlm_caw,
			.lease_timeout_ms = mxfs_resolve_dead_timeout_ms(),
			/* sess65: the log-slice divisor, read from the
			 * envelope above.  The durable recovery descriptor
			 * records which slice a recovery covers. */
			.log_node_count = mp->m_mxfs_log_node_count,
			/* Fix 3c: operator-asserted exclusive bdev access.  It
			 * gated SINGLE_NODE_EXCLUSIVE fence certificates until
			 * 0.89.18 revoked that kind; it is now write-time
			 * provenance about how a tenure was configured and
			 * authorises nothing. */
			.single_node_exclusive = mxfs_single_node_exclusive != 0,
			/* 0.74.0: the fence gate re-read the assertion live so
			 * an operator could answer a RECOVERY_BLOCKED slot
			 * without a remount.  That gate is gone; the live
			 * pointer stays so the value reported is the current
			 * one rather than the one sampled at mount. */
			.single_node_exclusive_live = &mxfs_single_node_exclusive,
			.fence_capability_override = mxfs_fence_capability_override != 0,
		};
		memcpy(dlm_opts.volume_uuid, &mp->m_sb.sb_uuid, 16);
		/* sess6 (46efd8b6): flush epoch starts at 1 so a buffer stamp
		 * of 0 unambiguously means "never written by this node". */
		atomic64_set(&mp->m_mxfs_flush_epoch, 1);
		/*
		 * sess454 (0.61.0, D2/D4): the departure accounting object
		 * exists for the whole life of a clustered mount — every
		 * xfs_buf submission from here on takes a token in it — and
		 * the mount's reference is dropped in xfs_mount_free; buffers
		 * holding tokens keep it alive past that.
		 */
		mp->m_mxfs_acct = mxfs_depart_acct_alloc();
		if (!mp->m_mxfs_acct) {
			xfs_alert(mp, "MXFS: departure accounting allocation failed — aborting mount of cluster (envelope) volume");
			error = -ENOMEM;
			goto out_filestream_unmount;
		}
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
			/*
			 * 0.88.0 (D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531):
			 * the heartbeat slot just claimed is the exclusive lease
			 * on the identically numbered log slice.  Before this
			 * incarnation mounts that log, the slice's lifecycle
			 * record must say READY; if mkfs left it INIT_REQUIRED
			 * (its zero of the log region is a userspace write the
			 * target does not promise to persist) or a previous
			 * claimant died ZEROING, this claimant zeroes the whole
			 * payload through the FUA path, proves it by reading it
			 * back, and persists READY — only then may a journal
			 * write land.  A slice already READY holds whatever this
			 * incarnation's earlier owners wrote and is mounted as
			 * before (own-crash replay, adopted-slice gating).  A
			 * record that is missing, invalid or another volume's
			 * on a volume that carries the region refuses the mount:
			 * nothing may guess a slice is safe to zero.
			 */
			if (mp->m_mxfs_node_slot >= 0 && mxfs_has_log_slices(mp)) {
				uint32_t	slice, before = 0, after = 0, zms = 0;
				uint64_t	poff, plen;
				int		lrc;

				lrc = mxfs_log_slice_of_slot(mp,
						(uint32_t)mp->m_mxfs_node_slot,
						&slice);
				if (lrc) {
					xfs_alert(mp,
	"MXFS: P-SLIFE-NOSLICE slot=%d rc=%d — the claimed slot has no log slice; refusing mount",
						  mp->m_mxfs_node_slot, lrc);
					error = lrc;
					goto out_filestream_unmount;
				}
				/*
				 * The slice's absolute byte range, from the
				 * superblock's own fields.  XFS_FSB_TO_DADDR is
				 * NOT usable here: it shifts by m_blkbb_log,
				 * which xfs_sb_mount_common sets inside
				 * xfs_mountfs — after this point — so it read
				 * as 0 and the first lap (s61a) zeroed 64 MiB
				 * of the data area at logstart-in-blocks
				 * (3782775296) instead of the slice
				 * (27071496192), leaving the plant untouched.
				 * The image tool (tools/slice_image.py geom)
				 * computes exactly this: xfs_data_offset +
				 * (agno * agblocks + agbno) << blocklog.
				 */
				{
					uint64_t	ls = mp->m_sb.sb_logstart;
					uint64_t	agno = ls >> mp->m_sb.sb_agblklog;
					uint64_t	agbno = ls &
						((1ULL << mp->m_sb.sb_agblklog) - 1);
					uint64_t	log_off =
						(agno * mp->m_sb.sb_agblocks + agbno)
							<< mp->m_sb.sb_blocklog;
					uint64_t	log_len =
						(uint64_t)mp->m_sb.sb_logblocks
							<< mp->m_sb.sb_blocklog;

					plen = BBTOB(mp->m_mxfs_log_slice_bblks);
					poff = BBTOB(mp->m_ddev_targp->bt_sector_offset) +
					       log_off + (uint64_t)slice * plen;
					if ((uint64_t)slice * plen + plen > log_len) {
						xfs_alert(mp,
		"MXFS: P-SLIFE-GEOM slot=%d slice=%u slice_bytes=%llu log_bytes=%llu — the slice does not lie inside the internal log; refusing mount",
							  mp->m_mxfs_node_slot, slice,
							  (unsigned long long)plen,
							  (unsigned long long)log_len);
						error = -EFSCORRUPTED;
						goto out_filestream_unmount;
					}
				}
				lrc = mxfs_v5_dlm_slice_lifecycle_claim(
						mp->m_mxfs_dlm, slice, poff, plen,
						&before, &after, &zms);
				if (lrc == -ENODEV) {
					xfs_warn(mp,
	"MXFS: P-SLIFE-LEGACY slot=%d slice=%u — this volume carries no slice lifecycle region (formatted before 0.88.0): the slice payload is trusted as mkfs left it, unverified; re-mkfs to get the claim-time zero",
						 mp->m_mxfs_node_slot, slice);
				} else if (lrc) {
					xfs_alert(mp,
	"MXFS: P-SLIFE-REFUSED slot=%d slice=%u rc=%d before=%s after=%s — the slice lifecycle could not be brought to READY; refusing mount (nothing is journaled into an unverified payload)",
						  mp->m_mxfs_node_slot, slice, lrc,
						  mxfs_v5_dlm_slice_lifecycle_name(before),
						  mxfs_v5_dlm_slice_lifecycle_name(after));
					error = lrc;
					goto out_filestream_unmount;
				} else {
					xfs_notice(mp,
	"MXFS: P-SLIFE slot=%d slice=%u before=%s after=%s zeroed_bytes=%llu zero_ms=%u — slice lifecycle at claim",
						   mp->m_mxfs_node_slot, slice,
						   mxfs_v5_dlm_slice_lifecycle_name(before),
						   mxfs_v5_dlm_slice_lifecycle_name(after),
						   before == MXFS_SLIFE_READY ? 0ULL :
						   (unsigned long long)plen, zms);
				}
			}
			/*
			 * sess389 (D-RSYNC-LAP-PACE-AG-SHARING-388, design-consult ruling):
			 * a node's home AG is node_slot % agcount (xfs_ialloc.c).
			 * A slot >= agcount therefore SHARES its home AG with slot
			 * (slot % agcount): both nodes' dirops ping-pong the AG EX
			 * grant (measured 25 AGs / 32 nodes: the 14 shared-AG nodes
			 * were exactly the rsync_paired lap-2+ failures, 34-60s+
			 * vs 14-27s exclusive).  Correctness is unaffected; pace is
			 * not promised.  Say so at join, loudly, with the partner.
			 */
			if (mp->m_mxfs_node_slot >= 0 && mp->m_sb.sb_agcount > 0 &&
			    (xfs_agnumber_t)mp->m_mxfs_node_slot >=
						mp->m_sb.sb_agcount)
				xfs_warn(mp, "MXFS P-AGCOUNT-COLLISION: node slot %d >= agcount %u — home AG %u is SHARED with slot %u; pace degrades under contention (sizing rule: agcount >= active nodes, 2x for the perf class; grow the device or reformat)",
					 mp->m_mxfs_node_slot, mp->m_sb.sb_agcount,
					 (unsigned)(mp->m_mxfs_node_slot %
						    mp->m_sb.sb_agcount),
					 (unsigned)(mp->m_mxfs_node_slot %
						    mp->m_sb.sb_agcount));
			/* sess32: pass-2 fresh HB claim => the log slice we
			 * inherit may be an already-recovered incarnation's;
			 * xfs_log_mount gates image re-application on this. */
			mp->m_mxfs_slice_adopted =
				mxfs_v5_dlm_slice_adopted(mp->m_mxfs_dlm);
			/* sess441 (§6.5 shape B): the whole-cluster bootstrap
			 * owner adopted a certified victim's slice as its own
			 * log — full replay, authority-evaluated. */
			mp->m_mxfs_bootstrap_adopted =
				mxfs_v5_dlm_bootstrap_adopted(mp->m_mxfs_dlm);
			/* sess9 (ccloop a864): armed by xfs_do_force_shutdown
			 * to withdraw this node from the cluster DLM (fence
			 * acquires + stop heartbeat).  INIT here, immediately
			 * after the ctx exists, so any shutdown from this
			 * point on can queue it. */
			mxfs_defer_reap_init(mp);
			INIT_WORK(&mp->m_mxfs_withdraw_work,
				  mxfs_dlm_withdraw_work_fn);
			/* sess448: the SELECTED transport is known only now;
			 * refuse an unqualified (non-CAW) domain before
			 * xfs_mountfs runs any recovery.  out_filestream_unmount
			 * shuts the DLM down again. */
			error = mxfs_transport_domain_admit(mp);
			if (error)
				goto out_filestream_unmount;
			mxfs_domain_admitted_announce(mp);
		}
	} else {
		/* B1: no envelope means no cluster protocol to admit —
		 * plain-XFS recovery is trivially admitted. */
		mp->m_mxfs_proto_admitted = true;
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
		/*
		 * sess383: the recovery barrier's FSWIDE gates ran inside
		 * xfs_mountfs, BEFORE the registration-time outcome scan and
		 * before the settle could drive a refusal.  Close the
		 * admission transaction here, where every synchronous import
		 * of this mount phase has already happened.
		 */
		error = mxfs_dlm_admission_commit(mp);
		if (!error && unlikely(mxfs_dbg_admission_refuse)) {
			mxfs_dbg_admission_refuse = 0;	/* one shot */
			xfs_alert(mp,
"MXFS: P291-ADMISSION-REFUSE-INJECTED — TEST: the admission commit succeeded and is being discarded, so this mount takes the unwind that calls xfs_unmountfs with the DLM already detached");
			error = -EIO;
		}
		if (error)
			goto out_unmount;
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
	if (late_release) {
		/*
		 * sess454/455 (D3): the unwind's release point, AFTER the sb
		 * buffers, workqueues and the raw device flush above — the
		 * gate rejected anything they submitted after the freeze and
		 * the assertion sees it.  Same predicate as put_super minus
		 * the late PR phase (this path unregistered inside shutdown).
		 * The departure mutex is taken here, after the workqueues
		 * are gone (ruling item 7).
		 */
		bool q;

		mxfs_v5_dlm_departure_lock();			/* sess451 */
		q = mxfs_departure_quiesced(mp, "mount-unwind") && late_drained;
		mxfs_v5_dlm_slot_release_commit(&dl_late,
					!xfs_is_shutdown(mp) &&
					late_flush_rc == 0 && q);
		mxfs_v5_dlm_slot_release_finish(&dl_late);	/* sess449 */
		mxfs_v5_dlm_departure_unlock();
	}
	return error;

 out_unmount:
	if (mp->m_mxfs_dlm) {
		void *v5dlm = mp->m_mxfs_dlm;

		mp->m_mxfs_dlm = NULL;	/* sess9: no-op any queued withdraw */
		cancel_work_sync(&mp->m_mxfs_withdraw_work);
		mxfs_defer_reap_destroy(mp);
		/*
		 * sess192 (dirty-slice Arm C): same ordering hazard as
		 * put_super — the log may already carry this mount's writes
		 * (unlinked-inode processing at minimum), so the heartbeat
		 * slot must not become consumable before the unmount record
		 * below is durable.  Note the slot-zero commit runs after
		 * mxfs_scsipr_unregister (inside shutdown; this path has no
		 * late PR detach), so on a WE-RO target with a peer-held
		 * reservation the release write can bounce — that fails
		 * CLOSED (slot stays ACTIVE, peers fence and recover),
		 * which is the required disposition for a failed mount.
		 */
		mxfs_v5_dlm_shutdown_defer_release(v5dlm, &dl_late);
		/* v0.5.0: work INIT'd by mxfs_dlm_cache_init (ran before
		 * this label is reachable); drain while m_log is valid. */
		cancel_work_sync(&mp->m_mxfs_foreign_replay_work);
		/* sess151: same lifecycle — see the unmount-path comment. */
		cancel_work_sync(&mp->m_mxfs_dlm_stuck_work);
		/* D-0487: same lifecycle; the push that queues it needs
		 * m_mxfs_dlm, which is gone by here. */
		cancel_work_sync(&mp->m_mxfs_ailpin_work);
		/*
		 * TEST: let the lease run out inside the mount unwind.  The
		 * heartbeat thread was joined by the shutdown above, so from
		 * here authority can only run down; parking longer than the
		 * lease puts every write xfs_unmountfs makes below — the AIL
		 * push of whatever recovery and unlinked-inode processing
		 * left, the log cover, the unmount record — on the far side of
		 * its deadline.  One-shot.
		 */
		if (unlikely(mxfs_dbg_mount_unwind_park_ms > 0)) {
			int hold = mxfs_dbg_mount_unwind_park_ms;

			mxfs_dbg_mount_unwind_park_ms = 0;
			xfs_alert(mp,
"MXFS: P291-AUTH-UNWIND-PARK ms=%d — TEST: parking the mount unwind past the authority lease; xfs_unmountfs below is run by a node that has stopped proving liveness",
				  hold);
			msleep(hold);
			xfs_alert(mp,
"MXFS: P291-AUTH-UNWIND-PARK-END — TEST: the mount unwind resumes");
		}
	}
	mxfs_departure_quiescing(mp);
	xfs_filestream_unmount(mp);
	xfs_unmountfs(mp);
	late_release = true;
	/* sess452/454: same final flush + freeze + drain as put_super; the
	 * assertion and the release run at out_shutdown_devices (D3). */
	late_flush_rc = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	if (late_flush_rc)
		xfs_alert(mp,
"MXFS: P277-FINAL-FLUSH-FAILED rc=%d before slot release (mount unwind) — departure treated as DIRTY",
			  late_flush_rc);
	late_drained = mxfs_departure_freeze_drain(mp, "mount-unwind");
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
		/* sess419 D-0133: deferred non-counter SB update; cluster-refused */
		error = mxfs_sb_mutation_refuse(mp, "remount-rw sb update");
		if (error)
			return error;
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
		/* sess447: the same durability-domain admission a fresh RW
		 * mount gets — a ro->rw remount must not bypass it.  The
		 * helper skips read-only mounts, so evaluate it as if RW. */
		if (mp->m_mxfs_has_envelope) {
			clear_bit(XFS_OPSTATE_READONLY, &mp->m_opstate);
			error = mxfs_durability_domain_admit(mp);
			if (!error)	/* sess448: transport arm too */
				error = mxfs_transport_domain_admit(mp);
			if (!error)
				mxfs_domain_admitted_announce(mp);
			set_bit(XFS_OPSTATE_READONLY, &mp->m_opstate);
			if (error)
				return error;
		}
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

/*
 * 0.75.66 (D-0924 instrument): create the buffer cache with SLUB's
 * allocation/free tracking, so the slab shutdown at module unload prints,
 * for every object still allocated, the stack that allocated it and its age
 * ("INFO: Allocated in ... age=...").  The module's own live-buffer registry
 * read empty on every lap of the builds that carry it while the builds
 * before it leaked six objects per unload; this names the objects from
 * outside the module.  The kernel no longer lets the flag be switched
 * through sysfs (store_user is read-only since the runtime toggle was
 * removed), so it must be requested at cache creation.  Read at module init
 * only.  Debug-only: the tracked object grows and the cache stops merging.
 */
static int mxfs_buf_slab_track;
module_param_named(buf_slab_track, mxfs_buf_slab_track, int, 0444);
MODULE_PARM_DESC(buf_slab_track,
	"DEBUG: create the buffer slab cache with SLUB allocation/free tracking (1=on; read at load)");

/*
 * D-0924: an unload report is only evidence about THIS load if the cache was
 * this load's.  When kmem_cache_destroy finds objects remaining it leaves the
 * cache on the slab list with refcount 0, and the node kernel's
 * kmem_cache_create merges a same-shape request with any listed mergeable
 * cache (only a negative refcount is unmergeable), so the next load adopts the
 * zombie and its stranded objects and re-reports them at its own unload.
 * Three unloads of three builds in test1's 2026-09-08 boot reported the same
 * six mxfs_buf objects at the same slab offsets, and the build that "fixed"
 * the leak had merely grown struct xfs_buf so the size no longer merged.
 * Every cache is therefore created SLAB_NO_MERGE unless slab_merge=1 asks for
 * the old shape (the control arm of tests/d0924_zombie_cache_ab.sh).  Read at
 * module init only.
 */
static unsigned int mxfs_slab_merge;
module_param_named(slab_merge, mxfs_slab_merge, uint, 0444);
MODULE_PARM_DESC(slab_merge,
	"1 = let the slab allocator merge this module's caches with same-shape caches (an unload leak report may then be a previous load's); 0 = every cache is its own (default)");

struct kmem_cache *
mxfs_cache_create(
	const char		*name,
	unsigned int		size,
	unsigned int		align,
	slab_flags_t		flags,
	void			(*ctor)(void *))
{
	return kmem_cache_create(name, size, align,
				 flags | (mxfs_slab_merge ? 0 : SLAB_NO_MERGE),
				 ctor);
}

STATIC int __init
xfs_init_caches(void)
{
	int		error;

	xfs_buf_cache = mxfs_cache_create("mxfs_buf", sizeof(struct xfs_buf), 0,
					 SLAB_HWCACHE_ALIGN |
					 SLAB_RECLAIM_ACCOUNT |
					 (mxfs_buf_slab_track ? SLAB_STORE_USER : 0),
					 NULL);
	if (!xfs_buf_cache)
		goto out;

	xfs_log_ticket_cache = mxfs_cache_create("mxfs_log_ticket",
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

	xfs_da_state_cache = mxfs_cache_create("mxfs_da_state",
					      sizeof(struct xfs_da_state),
					      0, 0, NULL);
	if (!xfs_da_state_cache)
		goto out_destroy_defer_item_cache;

	xfs_ifork_cache = mxfs_cache_create("mxfs_ifork",
					   sizeof(struct xfs_ifork),
					   0, 0, NULL);
	if (!xfs_ifork_cache)
		goto out_destroy_da_state_cache;

	xfs_trans_cache = mxfs_cache_create("mxfs_trans",
					   sizeof(struct xfs_trans),
					   0, 0, NULL);
	if (!xfs_trans_cache)
		goto out_destroy_ifork_cache;


	/*
	 * The size of the cache-allocated buf log item is the maximum
	 * size possible under XFS.  This wastes a little bit of memory,
	 * but it is much faster.
	 */
	xfs_buf_item_cache = mxfs_cache_create("mxfs_buf_item",
					      sizeof(struct xfs_buf_log_item),
					      0, 0, NULL);
	if (!xfs_buf_item_cache)
		goto out_destroy_trans_cache;

	xfs_efd_cache = mxfs_cache_create("mxfs_efd_item",
			xfs_efd_log_item_sizeof(XFS_EFD_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_efd_cache)
		goto out_destroy_buf_item_cache;

	xfs_efi_cache = mxfs_cache_create("mxfs_efi_item",
			xfs_efi_log_item_sizeof(XFS_EFI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_efi_cache)
		goto out_destroy_efd_cache;

	xfs_inode_cache = mxfs_cache_create("mxfs_inode",
					   sizeof(struct xfs_inode), 0,
					   (SLAB_HWCACHE_ALIGN |
					    SLAB_RECLAIM_ACCOUNT |
					    SLAB_ACCOUNT),
					   xfs_fs_inode_init_once);
	if (!xfs_inode_cache)
		goto out_destroy_efi_cache;

	xfs_ili_cache = mxfs_cache_create("mxfs_ili",
					 sizeof(struct xfs_inode_log_item), 0,
					 SLAB_RECLAIM_ACCOUNT,
					 NULL);
	if (!xfs_ili_cache)
		goto out_destroy_inode_cache;

	xfs_icreate_cache = mxfs_cache_create("mxfs_icr",
					     sizeof(struct xfs_icreate_item),
					     0, 0, NULL);
	if (!xfs_icreate_cache)
		goto out_destroy_ili_cache;

	xfs_relmark_cache = mxfs_cache_create("mxfs_relmark_item",
					      sizeof(struct xfs_relmark_item),
					      0, 0, NULL);
	if (!xfs_relmark_cache)
		goto out_destroy_icreate_cache;

	xfs_rud_cache = mxfs_cache_create("mxfs_rud_item",
					 sizeof(struct xfs_rud_log_item),
					 0, 0, NULL);
	if (!xfs_rud_cache)
		goto out_destroy_relmark_cache;

	xfs_rui_cache = mxfs_cache_create("mxfs_rui_item",
			xfs_rui_log_item_sizeof(XFS_RUI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_rui_cache)
		goto out_destroy_rud_cache;

	xfs_cud_cache = mxfs_cache_create("mxfs_cud_item",
					 sizeof(struct xfs_cud_log_item),
					 0, 0, NULL);
	if (!xfs_cud_cache)
		goto out_destroy_rui_cache;

	xfs_cui_cache = mxfs_cache_create("mxfs_cui_item",
			xfs_cui_log_item_sizeof(XFS_CUI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_cui_cache)
		goto out_destroy_cud_cache;

	xfs_bud_cache = mxfs_cache_create("mxfs_bud_item",
					 sizeof(struct xfs_bud_log_item),
					 0, 0, NULL);
	if (!xfs_bud_cache)
		goto out_destroy_cui_cache;

	xfs_bui_cache = mxfs_cache_create("mxfs_bui_item",
			xfs_bui_log_item_sizeof(XFS_BUI_MAX_FAST_EXTENTS),
			0, 0, NULL);
	if (!xfs_bui_cache)
		goto out_destroy_bud_cache;

	xfs_attrd_cache = mxfs_cache_create("mxfs_attrd_item",
					    sizeof(struct xfs_attrd_log_item),
					    0, 0, NULL);
	if (!xfs_attrd_cache)
		goto out_destroy_bui_cache;

	xfs_attri_cache = mxfs_cache_create("mxfs_attri_item",
					    sizeof(struct xfs_attri_log_item),
					    0, 0, NULL);
	if (!xfs_attri_cache)
		goto out_destroy_attrd_cache;

	xfs_iunlink_cache = mxfs_cache_create("mxfs_iul_item",
					     sizeof(struct xfs_iunlink_item),
					     0, 0, NULL);
	if (!xfs_iunlink_cache)
		goto out_destroy_attri_cache;

	xfs_xmd_cache = mxfs_cache_create("mxfs_xmd_item",
					 sizeof(struct xfs_xmd_log_item),
					 0, 0, NULL);
	if (!xfs_xmd_cache)
		goto out_destroy_iul_cache;

	xfs_xmi_cache = mxfs_cache_create("mxfs_xmi_item",
					 sizeof(struct xfs_xmi_log_item),
					 0, 0, NULL);
	if (!xfs_xmi_cache)
		goto out_destroy_xmd_cache;

	xfs_parent_args_cache = mxfs_cache_create("mxfs_parent_args",
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
 out_destroy_relmark_cache:
	kmem_cache_destroy(xfs_relmark_cache);
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
	WRITE_ONCE(mxfs_buf_caches_destroying, true);
	rcu_barrier();
	/*
	 * sess23 (D-UNMOUNT-BUSY-INODES): after the rcu_barrier every inode that
	 * was going to be freed has been.  Anything still on the live registry
	 * is the leak that makes the next kmem_cache_destroy(xfs_inode_cache)
	 * report "Slab cache still has objects".  Name it before we lose it.
	 */
	mxfs_report_leaked_inodes();
	/* 0.75.64: the same for buffers (D-0924) — see mxfs_report_leaked_buffers. */
	mxfs_report_leaked_buffers("after-barrier");
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
	kmem_cache_destroy(xfs_relmark_cache);
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
	mxfs_report_leaked_buffers("before-buf-cache-destroy");
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
module_param_named(dbg_auth_tail_blind, mxfs_dbg_auth_tail_blind, int, 0644);
MODULE_PARM_DESC(dbg_auth_tail_blind,
	"DEBUG: admit a mutating submission on a clustered mount whose DLM is already detached WITHOUT consulting the authority lease — the pre-fix gate, for measuring the before and the after on one build (0=off)");

module_param_named(dbg_unmount_tail_delay_ms, mxfs_dbg_unmount_tail_delay_ms, int, 0644);
MODULE_PARM_DESC(dbg_unmount_tail_delay_ms,
	"DEBUG: park put_super for this long right after the DLM is detached and the heartbeat joined, so the authority lease expires before the log cover and the unmount record are written (one-shot, 0=off)");

module_param_named(dbg_admit_park_site, mxfs_dbg_admit_park_site, charp, 0644);
MODULE_PARM_DESC(dbg_admit_park_site,
	"DEBUG: which class of submission the post-admission park applies to — log, data, dio, dio-zoned or meta; trailing whitespace is ignored so a shell echo works, and an empty or all-whitespace value is unarmed");

module_param_named(dbg_admit_park_ms, mxfs_dbg_admit_park_ms, int, 0644);
MODULE_PARM_DESC(dbg_admit_park_ms,
	"DEBUG: park the first submission of dbg_admit_park_site for this long AFTER the authority gate has admitted it and BEFORE it is handed to the layer below, so a fence and a successor's replay can happen while an already-admitted operation is in flight (one-shot, 0=off)");

module_param_named(dbg_admission_refuse, mxfs_dbg_admission_refuse, int, 0644);
MODULE_PARM_DESC(dbg_admission_refuse,
	"DEBUG: discard a successful mount admission commit so the mount takes the unwind that calls xfs_unmountfs with the DLM already detached (one-shot, 0=off)");

module_param_named(dbg_mount_unwind_park_ms, mxfs_dbg_mount_unwind_park_ms, int, 0644);
MODULE_PARM_DESC(dbg_mount_unwind_park_ms,
	"DEBUG: park the mount unwind for this long after the DLM shutdown joins the heartbeat, so the authority lease expires before xfs_unmountfs writes anything (one-shot, 0=off)");

module_param_named(dbg_recov_inject_agino, mxfs_dbg_recov_inject_agino, int, 0644);
MODULE_PARM_DESC(dbg_recov_inject_agino,
	"DEBUG: substitute this agino into the di_next_unlinked of the next logged inode-buffer image, in the LOG COPY only, so the replay guard against a wild unlinked pointer can be exercised on a value this build never writes (one-shot, cleared only when it lands, 0=off)");

module_param_named(dbg_recov_inject_straddle, mxfs_dbg_recov_inject_straddle, int, 0644);
MODULE_PARM_DESC(dbg_recov_inject_straddle,
	"DEBUG: move the next logged inode-buffer image's daddr, in the LOG COPY only, so the cluster it names crosses an AG boundary and the replay guard against a straddling image can be exercised (one-shot, cleared only when it lands, 0=off)");

module_param_named(legacy_rw, mxfs_legacy_rw, uint, 0644);
MODULE_PARM_DESC(legacy_rw,
	"Allow RW mount of a legacy (pre-protogate) MXFS cluster format "
	"(UNSAFE: pre-gate kernels can join undetected for seconds; "
	"default 0 = refuse, run chk_mxfs --upgrade-protogate instead).");

/*
 * 0.75.34: the log worker's period.  Upstream exposes it as the sysctl
 * fs/xfs/xfssyncd_centisecs; this fork registers its table under fs/mxfs
 * and that directory is absent on the rig nodes, so the same variable is
 * reachable as a module parameter.  The D-0536 harness sets 100 (1 s) on
 * the peer so its clustered log cover runs many times inside the other
 * node's summary critical section.
 */
module_param_named(syncd_centisecs, xfs_params.syncd_timer.val, int, 0644);
MODULE_PARM_DESC(syncd_centisecs,
	"Log worker period in centiseconds (default 3000; the value upstream's "
	"fs/xfs/xfssyncd_centisecs sets)");

module_param_named(fence_capability_override, mxfs_fence_capability_override, uint, 0644);
MODULE_PARM_DESC(fence_capability_override,
	"Admit a clustered RW mount even when the admission-time fencing-capability "
	"check fails (default 0 = refuse).  Set 1 ONLY as an explicit operator "
	"statement that this rig cannot fence; the mount then has weaker than "
	"production recovery semantics and says so in the log.");
module_param_named(affine_audit_pct, mxfs_affine_audit_pct, uint, 0644);
MODULE_PARM_DESC(affine_audit_pct,
	"Percent of dentry-revalidation affine fast-path blessings to verify "
	"against the coordinated lookup (0 = off, the default; behaviour is "
	"then unchanged).  That exit blesses a cached name->inode binding with "
	"no coordinated lookup and no parent hold-epoch check, on the strength "
	"of the CHILD inode living in this node's own allocation group -- which "
	"establishes authority over the inode, not over a directory entry any "
	"node may rewrite.  A sampled blessing is sent down the coordinated "
	"path instead and the verdicts compared; a wrong one is reported as "
	"P165-AFFINE-AUDIT-MISS and refused.  Costs one coordinated directory "
	"lookup per sample, so it is a diagnostic setting, not a production one.");

module_param_named(single_node_exclusive, mxfs_single_node_exclusive, uint, 0644);
MODULE_PARM_DESC(single_node_exclusive,
	"Operator assertion that NO other initiator can write this host's MXFS "
	"block devices.  IT NO LONGER AUTHORISES RECOVERY.  Until 0.89.18 it let "
	"a single-node mount certify a dead slot SINGLE_NODE_EXCLUSIVE when SCSI "
	"PR could not prove exclusion, and replay that slot's dirty journal "
	"slice; that kind is revoked and nothing mints it.  The assertion is "
	"about which INITIATORS may write, while the dead slot belongs to a "
	"previous INCARNATION whose already-accepted writes the target may still "
	"be finishing - replaying against those is silent corruption, and no "
	"parameter value can observe that they are done.  Setting it will not "
	"unblock a recovery (default 0).");

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

/*
 * sess469 fix shape A verification knobs (TEST ONLY; docs/authority-
 * certificate.md).  1 = after a successful inactivation-certificate install,
 * revoke it and treat the install as refused (STALEGEN) — proves that a
 * refusal DEFERS the free with no dirty (P-INACT-CERT-REFUSED, no
 * P2G-LOGWHO for the ino, zombie reaped later).  2 = corrupt the saved
 * certificate identity before the INACT-EXREL revoke — proves the
 * revoke-mismatch path fails CLOSED (P-INACT-CERT-FOREIGN + shutdown).
 */
int mxfs_inact_cert_inject;
module_param_named(inact_cert_inject, mxfs_inact_cert_inject, int, 0644);
MODULE_PARM_DESC(inact_cert_inject,
		 "TEST ONLY: 1 = refuse every inactivation certificate (free must defer), 2 = corrupt the saved identity (revoke must fail closed FOREIGN), 3 = force the -EDEADLK retry with a poisoned grant result, 4 = advance the installed epoch past the grant result (exact revoke), 5 = a release-side actor moves the certificate before INACT-EXREL (LOST+GONE must fail closed), 6 = a DEFERRED certificate looks like another incarnation at evict (cls=2 must fail closed), 7 = the inactivation leaves the certificate ACTIVE (evict cls=3 must fail closed)");
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
	/* sess437 (docs/whole-cluster-restart.md build item 1): read the host
	 * and boot identities ONCE per module load; the P-HOSTID line is the
	 * evidence a mount later cites when it replaces its own predecessor's
	 * PR key.  Incomplete identity is not fatal here — it only keeps the
	 * fail-closed refusal in force. */
	(void)mxfs_host_identity_init();
	/* sess451: host-wide departure/re-registration lock (v5_mount.h). */
	if (mxfs_v5_dlm_global_init())
		printk(KERN_ERR "mxfs: departure lock alloc failed — same-boot "
		       "remount vs. late departure is UNSERIALIZED\n");

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

	/*
	 * The witnessed LOGICAL UNIT RESET's report channel lives under
	 * /proc/fs/mxfs, so it is created after that directory exists and
	 * removed before it goes.  A failure here is NOT fatal to the module:
	 * with no channel every witnessed reset refuses, which costs the
	 * absent-registration recovery route and nothing else.
	 */
	(void)mxfs_pal_lu_reset_init();

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
	mxfs_pal_lu_reset_exit();
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
	mxfs_v5_dlm_global_exit();	/* sess451: after the last put_super */
	mxfs_depart_late_token_exit();	/* sess454: D4 injector's delayed work */
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
	mxfs_pal_lu_reset_exit();
	xfs_cleanup_procfs();
	xfs_mru_cache_uninit();
	xfs_destroy_workqueues();
	xfs_destroy_caches();
	xfs_uuid_table_free();
}

module_init(init_xfs_fs);
module_exit(exit_xfs_fs);

MODULE_AUTHOR("Stephen P. Shoecraft");
MODULE_DESCRIPTION("MXFS — Multinode XFS with " XFS_BUILD_OPTIONS " enabled");
MODULE_LICENSE("GPL");
