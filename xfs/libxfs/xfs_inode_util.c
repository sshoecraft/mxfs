// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include <linux/iversion.h>
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_inode_util.h"
#include "xfs_trans.h"
#include "xfs_ialloc.h"
#include "xfs_health.h"
#include "../../dlm/v5_mount.h"	/* ccloop-4dd7 sess2: mxfs_v5_dlm_is_single_node (recycle heal) */
#include "xfs_bmap.h"
#include "xfs_mxfs_dlm.h"
#include "xfs_error.h"
#include "xfs_trace.h"
#include "xfs_ag.h"
#include "xfs_iunlink_item.h"
#include "xfs_inode_item.h"

uint16_t
xfs_flags2diflags(
	struct xfs_inode	*ip,
	unsigned int		xflags)
{
	/* can't set PREALLOC this way, just preserve it */
	uint16_t		di_flags =
		(ip->i_diflags & XFS_DIFLAG_PREALLOC);

	if (xflags & FS_XFLAG_IMMUTABLE)
		di_flags |= XFS_DIFLAG_IMMUTABLE;
	if (xflags & FS_XFLAG_APPEND)
		di_flags |= XFS_DIFLAG_APPEND;
	if (xflags & FS_XFLAG_SYNC)
		di_flags |= XFS_DIFLAG_SYNC;
	if (xflags & FS_XFLAG_NOATIME)
		di_flags |= XFS_DIFLAG_NOATIME;
	if (xflags & FS_XFLAG_NODUMP)
		di_flags |= XFS_DIFLAG_NODUMP;
	if (xflags & FS_XFLAG_NODEFRAG)
		di_flags |= XFS_DIFLAG_NODEFRAG;
	if (xflags & FS_XFLAG_FILESTREAM)
		di_flags |= XFS_DIFLAG_FILESTREAM;
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		if (xflags & FS_XFLAG_RTINHERIT)
			di_flags |= XFS_DIFLAG_RTINHERIT;
		if (xflags & FS_XFLAG_NOSYMLINKS)
			di_flags |= XFS_DIFLAG_NOSYMLINKS;
		if (xflags & FS_XFLAG_EXTSZINHERIT)
			di_flags |= XFS_DIFLAG_EXTSZINHERIT;
		if (xflags & FS_XFLAG_PROJINHERIT)
			di_flags |= XFS_DIFLAG_PROJINHERIT;
	} else if (S_ISREG(VFS_I(ip)->i_mode)) {
		if (xflags & FS_XFLAG_REALTIME)
			di_flags |= XFS_DIFLAG_REALTIME;
		if (xflags & FS_XFLAG_EXTSIZE)
			di_flags |= XFS_DIFLAG_EXTSIZE;
	}

	return di_flags;
}

uint64_t
xfs_flags2diflags2(
	struct xfs_inode	*ip,
	unsigned int		xflags)
{
	uint64_t		di_flags2 =
		(ip->i_diflags2 & (XFS_DIFLAG2_REFLINK |
				   XFS_DIFLAG2_BIGTIME |
				   XFS_DIFLAG2_NREXT64));

	if (xflags & FS_XFLAG_DAX)
		di_flags2 |= XFS_DIFLAG2_DAX;
	if (xflags & FS_XFLAG_COWEXTSIZE)
		di_flags2 |= XFS_DIFLAG2_COWEXTSIZE;

	return di_flags2;
}

uint32_t
xfs_ip2xflags(
	struct xfs_inode	*ip)
{
	uint32_t		flags = 0;

	if (ip->i_diflags & XFS_DIFLAG_ANY) {
		if (ip->i_diflags & XFS_DIFLAG_REALTIME)
			flags |= FS_XFLAG_REALTIME;
		if (ip->i_diflags & XFS_DIFLAG_PREALLOC)
			flags |= FS_XFLAG_PREALLOC;
		if (ip->i_diflags & XFS_DIFLAG_IMMUTABLE)
			flags |= FS_XFLAG_IMMUTABLE;
		if (ip->i_diflags & XFS_DIFLAG_APPEND)
			flags |= FS_XFLAG_APPEND;
		if (ip->i_diflags & XFS_DIFLAG_SYNC)
			flags |= FS_XFLAG_SYNC;
		if (ip->i_diflags & XFS_DIFLAG_NOATIME)
			flags |= FS_XFLAG_NOATIME;
		if (ip->i_diflags & XFS_DIFLAG_NODUMP)
			flags |= FS_XFLAG_NODUMP;
		if (ip->i_diflags & XFS_DIFLAG_RTINHERIT)
			flags |= FS_XFLAG_RTINHERIT;
		if (ip->i_diflags & XFS_DIFLAG_PROJINHERIT)
			flags |= FS_XFLAG_PROJINHERIT;
		if (ip->i_diflags & XFS_DIFLAG_NOSYMLINKS)
			flags |= FS_XFLAG_NOSYMLINKS;
		if (ip->i_diflags & XFS_DIFLAG_EXTSIZE)
			flags |= FS_XFLAG_EXTSIZE;
		if (ip->i_diflags & XFS_DIFLAG_EXTSZINHERIT)
			flags |= FS_XFLAG_EXTSZINHERIT;
		if (ip->i_diflags & XFS_DIFLAG_NODEFRAG)
			flags |= FS_XFLAG_NODEFRAG;
		if (ip->i_diflags & XFS_DIFLAG_FILESTREAM)
			flags |= FS_XFLAG_FILESTREAM;
	}

	if (ip->i_diflags2 & XFS_DIFLAG2_ANY) {
		if (ip->i_diflags2 & XFS_DIFLAG2_DAX)
			flags |= FS_XFLAG_DAX;
		if (ip->i_diflags2 & XFS_DIFLAG2_COWEXTSIZE)
			flags |= FS_XFLAG_COWEXTSIZE;
	}

	if (xfs_inode_has_attr_fork(ip))
		flags |= FS_XFLAG_HASATTR;
	return flags;
}

prid_t
xfs_get_initial_prid(struct xfs_inode *dp)
{
	if (dp->i_diflags & XFS_DIFLAG_PROJINHERIT)
		return dp->i_projid;

	/* Assign to the root project by default. */
	return 0;
}

/* Propagate di_flags from a parent inode to a child inode. */
static inline void
xfs_inode_inherit_flags(
	struct xfs_inode	*ip,
	const struct xfs_inode	*pip)
{
	unsigned int		di_flags = 0;
	xfs_failaddr_t		failaddr;
	umode_t			mode = VFS_I(ip)->i_mode;

	if (S_ISDIR(mode)) {
		if (pip->i_diflags & XFS_DIFLAG_RTINHERIT)
			di_flags |= XFS_DIFLAG_RTINHERIT;
		if (pip->i_diflags & XFS_DIFLAG_EXTSZINHERIT) {
			di_flags |= XFS_DIFLAG_EXTSZINHERIT;
			ip->i_extsize = pip->i_extsize;
		}
		if (pip->i_diflags & XFS_DIFLAG_PROJINHERIT)
			di_flags |= XFS_DIFLAG_PROJINHERIT;
	} else if (S_ISREG(mode)) {
		if ((pip->i_diflags & XFS_DIFLAG_RTINHERIT) &&
		    xfs_has_realtime(ip->i_mount))
			di_flags |= XFS_DIFLAG_REALTIME;
		if (pip->i_diflags & XFS_DIFLAG_EXTSZINHERIT) {
			di_flags |= XFS_DIFLAG_EXTSIZE;
			ip->i_extsize = pip->i_extsize;
		}
	}
	if ((pip->i_diflags & XFS_DIFLAG_NOATIME) &&
	    xfs_inherit_noatime)
		di_flags |= XFS_DIFLAG_NOATIME;
	if ((pip->i_diflags & XFS_DIFLAG_NODUMP) &&
	    xfs_inherit_nodump)
		di_flags |= XFS_DIFLAG_NODUMP;
	if ((pip->i_diflags & XFS_DIFLAG_SYNC) &&
	    xfs_inherit_sync)
		di_flags |= XFS_DIFLAG_SYNC;
	if ((pip->i_diflags & XFS_DIFLAG_NOSYMLINKS) &&
	    xfs_inherit_nosymlinks)
		di_flags |= XFS_DIFLAG_NOSYMLINKS;
	if ((pip->i_diflags & XFS_DIFLAG_NODEFRAG) &&
	    xfs_inherit_nodefrag)
		di_flags |= XFS_DIFLAG_NODEFRAG;
	if (pip->i_diflags & XFS_DIFLAG_FILESTREAM)
		di_flags |= XFS_DIFLAG_FILESTREAM;

	ip->i_diflags |= di_flags;

	/*
	 * Inode verifiers on older kernels only check that the extent size
	 * hint is an integer multiple of the rt extent size on realtime files.
	 * They did not check the hint alignment on a directory with both
	 * rtinherit and extszinherit flags set.  If the misaligned hint is
	 * propagated from a directory into a new realtime file, new file
	 * allocations will fail due to math errors in the rt allocator and/or
	 * trip the verifiers.  Validate the hint settings in the new file so
	 * that we don't let broken hints propagate.
	 */
	failaddr = xfs_inode_validate_extsize(ip->i_mount, ip->i_extsize,
			VFS_I(ip)->i_mode, ip->i_diflags);
	if (failaddr) {
		ip->i_diflags &= ~(XFS_DIFLAG_EXTSIZE |
				   XFS_DIFLAG_EXTSZINHERIT);
		ip->i_extsize = 0;
	}
}

/* Propagate di_flags2 from a parent inode to a child inode. */
static inline void
xfs_inode_inherit_flags2(
	struct xfs_inode	*ip,
	const struct xfs_inode	*pip)
{
	xfs_failaddr_t		failaddr;

	if (pip->i_diflags2 & XFS_DIFLAG2_COWEXTSIZE) {
		ip->i_diflags2 |= XFS_DIFLAG2_COWEXTSIZE;
		ip->i_cowextsize = pip->i_cowextsize;
	}
	if (pip->i_diflags2 & XFS_DIFLAG2_DAX)
		ip->i_diflags2 |= XFS_DIFLAG2_DAX;
	if (xfs_is_metadir_inode(pip))
		ip->i_diflags2 |= XFS_DIFLAG2_METADATA;

	/* Don't let invalid cowextsize hints propagate. */
	failaddr = xfs_inode_validate_cowextsize(ip->i_mount, ip->i_cowextsize,
			VFS_I(ip)->i_mode, ip->i_diflags, ip->i_diflags2);
	if (failaddr) {
		ip->i_diflags2 &= ~XFS_DIFLAG2_COWEXTSIZE;
		ip->i_cowextsize = 0;
	}
}

/*
 * If we need to create attributes immediately after allocating the inode,
 * initialise an empty attribute fork right now. We use the default fork offset
 * for attributes here as we don't know exactly what size or how many
 * attributes we might be adding. We can do this safely here because we know
 * the data fork is completely empty and this saves us from needing to run a
 * separate transaction to set the fork offset in the immediate future.
 *
 * If we have parent pointers and the caller hasn't told us that the file will
 * never be linked into a directory tree, we /must/ create the attr fork.
 */
static inline bool
xfs_icreate_want_attrfork(
	struct xfs_mount		*mp,
	const struct xfs_icreate_args	*args)
{
	if (args->flags & XFS_ICREATE_INIT_XATTRS)
		return true;

	if (!(args->flags & XFS_ICREATE_UNLINKABLE) && xfs_has_parent(mp))
		return true;

	return false;
}

/* Initialise an inode's attributes. */
void
xfs_inode_init(
	struct xfs_trans	*tp,
	const struct xfs_icreate_args *args,
	struct xfs_inode	*ip)
{
	struct xfs_inode	*pip = args->pip;
	struct inode		*dir = pip ? VFS_I(pip) : NULL;
	struct xfs_mount	*mp = tp->t_mountp;
	struct inode		*inode = VFS_I(ip);
	unsigned int		flags;
	int			times = XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG |
					XFS_ICHGTIME_ACCESS;

	if (args->flags & XFS_ICREATE_TMPFILE)
		mxfs_set_nlink(ip, 0);
	else if (S_ISDIR(args->mode))
		mxfs_set_nlink(ip, 2);
	else
		mxfs_set_nlink(ip, 1);
	inode->i_rdev = args->rdev;

	if (!args->idmap || pip == NULL) {
		/* creating a tree root, sb rooted, or detached file */
		inode->i_uid = GLOBAL_ROOT_UID;
		inode->i_gid = GLOBAL_ROOT_GID;
		ip->i_projid = 0;
		inode->i_mode = args->mode;
	} else {
		/* creating a child in the directory tree */
		if (dir && !(dir->i_mode & S_ISGID) && xfs_has_grpid(mp)) {
			inode_fsuid_set(inode, args->idmap);
			inode->i_gid = dir->i_gid;
			inode->i_mode = args->mode;
		} else {
			inode_init_owner(args->idmap, inode, dir, args->mode);
		}
		ip->i_projid = xfs_get_initial_prid(pip);
	}

	ip->i_disk_size = 0;
	ip->i_df.if_nextents = 0;
	ASSERT(ip->i_nblocks == 0);

	ip->i_extsize = 0;
	ip->i_diflags = 0;

	if (xfs_has_v3inodes(mp)) {
		inode_set_iversion(inode, 1);
		/* also covers the di_used_blocks union arm: */
		ip->i_cowextsize = 0;
		times |= XFS_ICHGTIME_CREATE;
	}

	xfs_trans_ichgtime(tp, ip, times);

	flags = XFS_ILOG_CORE;
	switch (args->mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		ip->i_df.if_format = XFS_DINODE_FMT_DEV;
		flags |= XFS_ILOG_DEV;
		break;
	case S_IFREG:
	case S_IFDIR:
		if (pip && (pip->i_diflags & XFS_DIFLAG_ANY))
			xfs_inode_inherit_flags(ip, pip);
		if (pip && (pip->i_diflags2 & XFS_DIFLAG2_ANY))
			xfs_inode_inherit_flags2(ip, pip);
		fallthrough;
	case S_IFLNK:
		ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;
		ip->i_df.if_bytes = 0;
		ip->i_df.if_data = NULL;
		break;
	default:
		ASSERT(0);
	}

	if (xfs_icreate_want_attrfork(mp, args)) {
		ip->i_forkoff = xfs_default_attroffset(ip) >> 3;
		xfs_ifork_init_attr(ip, XFS_DINODE_FMT_EXTENTS, 0);

		if (!xfs_has_attr(mp)) {
			spin_lock(&mp->m_sb_lock);
			xfs_add_attr(mp);
			spin_unlock(&mp->m_sb_lock);
			xfs_log_sb(tp);
		}
	}

	/*
	 * sess48 (393-c3 fatal root, RULE 4): a just-allocated inode CANNOT
	 * be on any unlinked list — xfs_dialloc returned it free, and a free
	 * ino's remove already committed di_next_unlinked = NULLAGINO.  In
	 * multi-node operation that remove's home write can be lost (the
	 * fossil family): the platter slot keeps the DEAD chain value, the
	 * reuse-create stamps a NEW di_gen around it at iflush (which never
	 * touches nu), and every gen-keyed defense goes blind (GENSKEW
	 * keep-and-skip; the store's record retired when the new-gen image
	 * destaged).  The next unlink of the reused ino then trips
	 * P53 (expected NULLAGINO, found fossil) → EFSCORRUPTED shutdown.
	 * Enforce the invariant at the one point it is PROVABLE: clear a
	 * non-NULLAGINO dinode nu in the create transaction (the exact
	 * iunlink-item write idiom: value + CRC + 4-byte buffer log).
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		struct xfs_buf		*nubp;
		struct xfs_dinode	*nudip;

		if (!xfs_imap_to_bp(mp, tp, &ip->i_imap, &nubp)) {
			nudip = xfs_buf_offset(nubp, ip->i_imap.im_boffset);
			if (!(nubp->b_flags & XBF_STALE) &&
			    be16_to_cpu(nudip->di_magic) == XFS_DINODE_MAGIC &&
			    nudip->di_next_unlinked !=
						cpu_to_be32(NULLAGINO)) {
				int nuoff = ip->i_imap.im_boffset +
					offsetof(struct xfs_dinode,
						 di_next_unlinked);

				pr_warn("mxfs: P-CREATE-NUFIX ino=0x%llx fossil_next=0x%x disk_gen=%u — freshly allocated ino carried a dead chain value; cleared to NULLAGINO in the create transaction\n",
					(unsigned long long)ip->i_ino,
					be32_to_cpu(nudip->di_next_unlinked),
					be32_to_cpu(nudip->di_gen));
				nudip->di_next_unlinked =
						cpu_to_be32(NULLAGINO);
				xfs_dinode_calc_crc(mp, nudip);
				xfs_trans_inode_buf(tp, nubp);
				xfs_trans_log_buf(tp, nubp, nuoff,
					nuoff + sizeof(xfs_agino_t) - 1);
			} else {
				xfs_trans_brelse(tp, nubp);
			}
		}
	}

	xfs_trans_log_inode(tp, ip, flags);
}

/*
 * In-Core Unlinked List Lookups
 * =============================
 *
 * Every inode is supposed to be reachable from some other piece of metadata
 * with the exception of the root directory.  Inodes with a connection to a
 * file descriptor but not linked from anywhere in the on-disk directory tree
 * are collectively known as unlinked inodes, though the filesystem itself
 * maintains links to these inodes so that on-disk metadata are consistent.
 *
 * XFS implements a per-AG on-disk hash table of unlinked inodes.  The AGI
 * header contains a number of buckets that point to an inode, and each inode
 * record has a pointer to the next inode in the hash chain.  This
 * singly-linked list causes scaling problems in the iunlink remove function
 * because we must walk that list to find the inode that points to the inode
 * being removed from the unlinked hash bucket list.
 *
 * Hence we keep an in-memory double linked list to link each inode on an
 * unlinked list. Because there are 64 unlinked lists per AGI, keeping pointer
 * based lists would require having 64 list heads in the perag, one for each
 * list. This is expensive in terms of memory (think millions of AGs) and cache
 * misses on lookups. Instead, use the fact that inodes on the unlinked list
 * must be referenced at the VFS level to keep them on the list and hence we
 * have an existence guarantee for inodes on the unlinked list.
 *
 * Given we have an existence guarantee, we can use lockless inode cache lookups
 * to resolve aginos to xfs inodes. This means we only need 8 bytes per inode
 * for the double linked unlinked list, and we don't need any extra locking to
 * keep the list safe as all manipulations are done under the AGI buffer lock.
 * Keeping the list up to date does not require memory allocation, just finding
 * the XFS inode and updating the next/prev unlinked list aginos.
 */

/*
 * mxfs sess40 — D-AGI-UNLINKED F1: per-slot AGI unlinked buckets.
 *
 * Upstream hashes agino % 64, which makes bucket membership CROSS-NODE under
 * a shared LUN: nodes' zombies interleave in one chain, every adjacent-member
 * stitch touches state whose authoritative copy lives in a peer's icache
 * (i_prev_unlinked has no on-disk form), and xfs_iunlink_reload_next faults a
 * peer's LIVE open-unlinked inode in as an "unrecovered orphan".  Proven
 * deterministic corruption: tests/agi_bucket_repro.sh (B's insert invalidates
 * A's in-core self-view; A's remove then fails the head-mismatch lookup ->
 * -EFSCORRUPTED -> shutdown -> withdrawal).
 *
 * In multi-node mode each node therefore inserts into ITS OWN slot's bucket
 * (disklock slots are 0..63, unique per live node — architectural invariant
 * 3 — and XFS_AGI_UNLINKED_BUCKETS is 64).  All members of a node's bucket
 * are its own zombies, restoring upstream's per-node existence guarantee and
 * making cross-node adjacency, cross-node reloads, and cross-node stitching
 * structurally unreachable at runtime.  Recovery walks are scoped to owned
 * buckets (see xlog_recover_iunlink_ag) and every membership-establishing
 * path stamps ip->i_unlinked_bucket, which the remove path USES — never
 * recomputes — so removals stay correct across a runtime knob flip and
 * during foreign adoption.
 *
 * Knob (cluster-uniform ONLY — mixed settings recreate the shared-bucket
 * hazard for new inserts): mxfs.iunlink_slot_buckets, default 1; 0 = legacy
 * hashing as the same-build A/B control.  Registered in pal/linux (kernel
 * builds); plain variable here so user-mode libxfs links.
 */
unsigned int mxfs_iunlink_slot_buckets = 1;

static inline short
xfs_iunlink_pick_bucket(
	struct xfs_mount	*mp,
	xfs_agino_t		agino)
{
	if (mxfs_iunlink_slot_buckets && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return (short)(mp->m_mxfs_node_slot %
			       XFS_AGI_UNLINKED_BUCKETS);
	return (short)(agino % XFS_AGI_UNLINKED_BUCKETS);
}

/*
 * The bucket an inode's existing list entry lives in.  Trusts the stamp when
 * present; falls back to legacy hashing for an entry established before the
 * stamp existed (or with the knob off since insert).
 */
static inline short
xfs_iunlink_member_bucket(
	struct xfs_inode	*ip,
	xfs_agino_t		agino)
{
	if (ip->i_unlinked_bucket >= 0)
		return (short)ip->i_unlinked_bucket;
	return (short)(agino % XFS_AGI_UNLINKED_BUCKETS);
}

/*
 * Update the prev pointer of the next agino.  Returns -ENOLINK if the inode
 * is not in cache.
 */
static int
xfs_iunlink_update_backref(
	struct xfs_perag	*pag,
	xfs_agino_t		prev_agino,
	xfs_agino_t		next_agino)
{
	struct xfs_inode	*ip;

	/* No update necessary if we are at the end of the list. */
	if (next_agino == NULLAGINO)
		return 0;

	ip = xfs_iunlink_lookup(pag, next_agino);
	if (!ip)
		return -ENOLINK;

	ip->i_prev_unlinked = prev_agino;
	return 0;
}

/*
 * Point the AGI unlinked bucket at an inode and log the results.  The caller
 * is responsible for validating the old value.
 */
STATIC int
xfs_iunlink_update_bucket(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_buf		*agibp,
	unsigned int		bucket_index,
	xfs_agino_t		new_agino)
{
	struct xfs_agi		*agi = agibp->b_addr;
	xfs_agino_t		old_value;
	int			offset;

	ASSERT(xfs_verify_agino_or_null(pag, new_agino));

	old_value = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	trace_xfs_iunlink_update_bucket(pag, bucket_index, old_value,
			new_agino);

	/*
	 * We should never find the head of the list already set to the value
	 * passed in because either we're adding or removing ourselves from the
	 * head of the list.
	 */
	if (old_value == new_agino) {
		/* sess387: was a SILENT -EFSCORRUPTED — one of the two unnamed
		 * exits a lap-2 droplink rc=-117 could have escaped through. */
		pr_warn("mxfs: P-IUNL-BUCKETSAME agno=%u bucket=%u old=new=0x%x disk_head=0x%x agi_gen=%llu comm=%s\n",
			pag_agno(pag), bucket_index, old_value,
			mxfs_agi_disk_bucket_head(agibp, bucket_index),
			(unsigned long long)agibp->b_mxfs_ag_gen,
			current->comm);
		xfs_buf_mark_corrupt(agibp);
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
		return -EFSCORRUPTED;
	}

	agi->agi_unlinked[bucket_index] = cpu_to_be32(new_agino);
	offset = offsetof(struct xfs_agi, agi_unlinked) +
			(sizeof(xfs_agino_t) * bucket_index);
	xfs_trans_log_buf(tp, agibp, offset, offset + sizeof(xfs_agino_t) - 1);
	return 0;
}

static int
xfs_iunlink_insert_inode(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_buf		*agibp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_agi		*agi = agibp->b_addr;
	xfs_agino_t		next_agino;
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	short			bucket_index = xfs_iunlink_pick_bucket(mp, agino);
	int			error;

	/*
	 * Get the index into the agi hash table for the list this inode will
	 * go on.  Make sure the pointer isn't garbage and that this inode
	 * isn't already on the list.
	 */
	next_agino = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	if (next_agino == agino ||
	    !xfs_verify_agino_or_null(pag, next_agino)) {
		pr_warn("mxfs: MX-INSTR agi-recycle ino=0x%llx agino=0x%x next_agino=0x%x bucket=%d agno=%u nlink=%u mode=0x%x recycled=%s verify_ok=%d",
			(unsigned long long)ip->i_ino, agino, next_agino,
			(int)bucket_index, pag_agno(pag),
			VFS_I(ip)->i_nlink, VFS_I(ip)->i_mode,
			(next_agino == agino) ? "yes" : "no",
			xfs_verify_agino_or_null(pag, next_agino));
		/*
		 * mxfs (ccloop-4dd7 sess2, ino 0x80008e round-3 autopsy): a
		 * bucket head ALREADY naming our agino is a LEAKED entry from
		 * this number's PRIOR life (an inactivation skip whose unleak
		 * could not run — the P2L-INACT-LEAK family), hit again when
		 * the reused number is unlinked.  Upstream's detect-only
		 * -EFSCORRUPTED fires inside xfs_droplink's DIRTY transaction
		 * = cluster-wide shutdown.  The on-disk state ALREADY equals
		 * the post-add state we want (head = our agino), and the
		 * reused dinode's di_next_unlinked was re-initialized to
		 * NULLAGINO at icreate, so the chain terminates cleanly —
		 * ADOPT the leaked entry as our own insert instead of dying
		 * (same bounded-loss precedent as the broken-list sole-head
		 * heal below).  Multinode only; single-node keeps upstream's
		 * strict check.
		 */
		if (next_agino == agino && mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			pr_warn("mxfs: P-IUNLINK-RECYCLE-HEAL ino=0x%llx agino=0x%x bucket=%d — adopting leaked prior-life bucket entry as this unlink's insert\n",
				(unsigned long long)ip->i_ino, agino,
				(int)bucket_index);
			ip->i_next_unlinked = NULLAGINO;
			ip->i_prev_unlinked = NULLAGINO;
			ip->i_unlinked_bucket = bucket_index;
			return 0;
		}
		xfs_buf_mark_corrupt(agibp);
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
		return -EFSCORRUPTED;
	}

	/*
	 * Update the prev pointer in the next inode to point back to this
	 * inode.
	 */
	error = xfs_iunlink_update_backref(pag, agino, next_agino);
	if (error == -ENOLINK)
		error = xfs_iunlink_reload_next(tp, agibp, agino, next_agino,
				bucket_index);
	if (error == -ENOENT && next_agino != NULLAGINO) {
		/*
		 * mxfs (sess53 ccloop): the in-core AGI bucket head (next_agino)
		 * names an inode that reload found FREE on disk (ENOENT).
		 * Upstream propagates this; xfs_remove then cancels a DIRTY
		 * transaction -> forced FS shutdown (seen as xfs_trans_cancel
		 * line 1060 under a 16-node rm-rf storm).  A free inode can
		 * never be a live unlinked-list member, so chaining to it is
		 * always wrong.  This is the cross-node AGI read-coherency
		 * family: a peer freed next_agino and committed a fresh bucket
		 * head, but our cached AGI still names the now-free inode.
		 * FUA-read the authoritative on-disk head and recover instead
		 * of shutting the filesystem down.
		 */
		uint32_t disk_head = mxfs_agi_disk_bucket_head(agibp,
				bucket_index);
		int valid = (disk_head != 0xfffffffeU) &&
			    xfs_verify_agino_or_null(pag, disk_head);
		pr_warn("mxfs: P-INS-STALE agno=%u bucket=%d incore_head=0x%x "
			"disk_head=0x%x valid=%d ino=%llu agino=0x%x differs=%d\n",
			pag_agno(pag), (int)bucket_index, next_agino, disk_head,
			valid, (unsigned long long)ip->i_ino, agino,
			(disk_head != next_agino));
		if (valid && disk_head != next_agino && disk_head != agino) {
			/* In-core head was stale: adopt the coherent disk head. */
			next_agino = disk_head;
			if (next_agino != NULLAGINO) {
				error = xfs_iunlink_update_backref(pag, agino,
						next_agino);
				if (error == -ENOLINK)
					error = xfs_iunlink_reload_next(tp,
						agibp, agino, next_agino,
						bucket_index);
				if (error) {
					/* Fresh head also unrecoverable: heal. */
					next_agino = NULLAGINO;
					error = 0;
				}
			} else {
				error = 0;
			}
		} else {
			/*
			 * Disk head agrees it is the (now free) inode, or is
			 * itself garbage: the on-disk list is broken.  Make our
			 * inode the sole head and drop the dangling reference;
			 * the freed inode's tail (if any) was already unreachable
			 * through a free inode, so no live inode is lost.
			 */
			next_agino = NULLAGINO;
			error = 0;
		}
	}
	if (error) {
		/* sess387: backref/reload chain error leaving insert unnamed. */
		pr_warn("mxfs: P-IUNL-INSFAIL ino=%llu agino=0x%x bucket=%d next=0x%x rc=%d comm=%s\n",
			(unsigned long long)ip->i_ino, agino,
			(int)bucket_index, next_agino, error, current->comm);
		return error;
	}

	if (next_agino != NULLAGINO) {
		/*
		 * There is already another inode in the bucket, so point this
		 * inode to the current head of the list.
		 *
		 * sess388 (D-FOSSIL-NEXT-UNLINKED-IGET-LOGSAME-388, deterministic
		 * lap-3 shutdown on test7 ino 12585587): xfs_iunlink_log_inode
		 * force-shuts-down when ip->i_next_unlinked == next_agino != NULL.
		 * We are on the INSERT path — this inode is definitionally NOT on
		 * any unlinked list yet (adding it is the whole point), so its
		 * pre-insert i_next_unlinked MUST be NULLAGINO.  A non-NULL value
		 * that happens to equal the bucket head we just read is a FOSSIL:
		 * a prior life's di_next_unlinked reloaded from a platter whose
		 * removal (NULLAGINO) never landed home (the P119 flush-skip
		 * retired the committed removal), re-adopted at iget, and the next
		 * lap's identical rename order made the same agino the head again.
		 * The genuine-split hazard GPT ruling-4 warns about is a READ-side
		 * ambiguity (deciding a linked dinode's list membership); it does
		 * NOT apply here, where the insert itself proves fresh membership.
		 * Reset the fossil so the transition is the legitimate
		 * NULLAGINO -> next_agino; the != next_agino fossil case is already
		 * handled downstream by the precommit fossil backstop (sess203).
		 * Multinode only; single-node keeps upstream's strict detector.
		 */
		if (mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    ip->i_next_unlinked == next_agino) {
			pr_warn("mxfs: P-IUNL-FOSSIL-RESET ino=%llu agino=0x%x bucket=%d fossil_next=0x%x head=0x%x gen=%u comm=%s — insert-path i_next_unlinked is a reloaded prior-life fossil; resetting to NULLAGINO before insert\n",
				(unsigned long long)ip->i_ino, agino,
				(int)bucket_index, ip->i_next_unlinked,
				next_agino, VFS_I(ip)->i_generation,
				current->comm);
			ip->i_next_unlinked = NULLAGINO;
		}
		error = xfs_iunlink_log_inode(tp, ip, pag, next_agino);
		if (error) {
			/* sess387: xfs_iunlink_log_inode's i_next_unlinked ==
			 * next_agino check is the other silent -EFSCORRUPTED. */
			pr_warn("mxfs: P-IUNL-LOGSAME ino=%llu agino=0x%x bucket=%d incore_next=0x%x head=0x%x prev=0x%x ub=%d lu=%d au=%d rc=%d comm=%s\n",
				(unsigned long long)ip->i_ino, agino,
				(int)bucket_index, ip->i_next_unlinked,
				next_agino, ip->i_prev_unlinked,
				(int)ip->i_unlinked_bucket,
				xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK) ? 1 : 0,
				xfs_iflags_test(ip, MXFS_IF_ADOPTED_UNLINK) ? 1 : 0,
				error, current->comm);
			return error;
		}
		ip->i_next_unlinked = next_agino;
	}

	/* Point the head of the list to point to this inode. */
	ip->i_prev_unlinked = NULLAGINO;
	ip->i_unlinked_bucket = bucket_index;
	return xfs_iunlink_update_bucket(tp, pag, agibp, bucket_index, agino);
}

/*
 * This is called when the inode's link count has gone to 0 or we are creating
 * a tmpfile via O_TMPFILE.  The inode @ip must have nlink == 0.
 *
 * We place the on-disk inode on a list in the AGI.  It will be pulled from this
 * list when the inode is freed.
 */
int
xfs_iunlink(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_perag	*pag;
	struct xfs_buf		*agibp;
	int			error;
	bool			dlm_held = false;
	const char		*stage = "dlm_lock";

	ASSERT(VFS_I(ip)->i_nlink == 0);
	ASSERT(VFS_I(ip)->i_mode != 0);
	trace_xfs_iunlink(ip);

	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ip->i_ino));

	/*
	 * MXFS: acquire AG DLM around the AGI-unlinked-list mutation.
	 * xfs_iunlink reads the AGI bucket head, logs the AGI buffer,
	 * and updates inode->next_unlinked.  Without cluster-wide
	 * serialization on the AGI buffer, T1 and T2 race on
	 * agi_unlinked[bucket] — both read the same bucket head, both
	 * insert their inode pointing at it, but only one's write reaches
	 * disk first; the other's view is stale by the time AIL push
	 * lands.  Symptom seen at v0.3.21 15-iter soak iter-4:
	 *   Metadata corruption at xfs_iunlink, agi block 0x2
	 *   xfs_droplink rc=-117 EFSCORRUPTED
	 * Sister path xfs_iunlink_remove is called under
	 * xfs_inactive_ifree which already holds the AG DLM (xfs_inode.c
	 * :1299), so the REMOVE side is already coordinated; only the
	 * INSERT side (this function, called from xfs_remove via
	 * xfs_droplink) was missing.
	 */
	error = mxfs_ag_dlm_lock(mp, pag);
	if (error)
		goto out;
	dlm_held = true;

	/* Get the agi buffer first.  It ensures lock ordering on the list. */
	stage = "read_agi";
	error = xfs_read_agi(pag, tp, 0, &agibp);
	if (error)
		goto out;

	stage = "insert";
	error = xfs_iunlink_insert_inode(tp, pag, agibp, ip);
	/* sess43 P82-ADD: trace every unlinked-list ADD (ino+agino+bucket+nlink)
	 * so the cross-node correlation for the P71 iunlink corruption is
	 * decisive: did the ADD run for the failing inode, on which node, and is
	 * its bucket-head update visible to the node that later inactivates it?
	 * Fires once per unlink (rm-rf storm volume, but bounded + concise). */
	/* sess9 (72513a13) CAPPED: at drc@32 rm storms this fired ~2000×/145s
	 * and — with its 5 sibling teardown probes — put 22k lines through
	 * printk while the SAME kworkers service DLM requests: peers saw
	 * 130s P-LKTIMEOUT blackouts from serialized console time alone. */
	{
		static atomic_t p82a_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p82a_n) <= 300)
			pr_warn("mxfs: P82-ADD ino=%llu agno=%u agino=0x%x bucket=%d vfs_nlink=%u rc=%d realns=%llu\n",
				(unsigned long long)ip->i_ino, pag_agno(pag),
				XFS_INO_TO_AGINO(mp, ip->i_ino),
				(int)ip->i_unlinked_bucket,
				VFS_I(ip)->i_nlink, error,
				(unsigned long long)ktime_get_real_ns());
	}
	/* sess387 publication obligation: this inode is now (or is about to be,
	 * when this txn commits) an on-disk unlinked-list member; its home
	 * dinode owes a nlink=0 conversion before any AG release publishes the
	 * list.  Armed here because every caller's transaction is already
	 * dirty (a cancel after this point is a shutdown, never a clean
	 * unwind).  Enforced at AG release; discharged by xfs_iflush_finish
	 * or by the remove below. */
	if (!error) {
		extern void mxfs_pubob_arm(struct xfs_mount *,
					   struct xfs_inode *);
		mxfs_pubob_arm(mp, ip);
	}
out:
	/* sess387: the lap-2 rsync collapse EXITS this function with -117 while
	 * every named probe stays silent — P82-ADD's 300-event cap had suppressed
	 * the failing add's rc line.  An ERROR exit is the rare case the trace
	 * exists for: log it unconditionally, with the stage that produced it,
	 * so no -EFSCORRUPTED can leave here unnamed again. */
	if (error)
		pr_warn("mxfs: P82-ADD-FAIL ino=%llu agno=%u agino=0x%x stage=%s rc=%d nlink=%u next_unlinked=0x%x prev=0x%x ub=%d comm=%s\n",
			(unsigned long long)ip->i_ino, pag_agno(pag),
			XFS_INO_TO_AGINO(mp, ip->i_ino), stage, error,
			VFS_I(ip)->i_nlink, ip->i_next_unlinked,
			ip->i_prev_unlinked, (int)ip->i_unlinked_bucket,
			current->comm);
	if (dlm_held) {
		if (error)
			mxfs_ag_dlm_unlock(mp, pag);
		else
			mxfs_ag_dlm_unlock_deferred(tp, pag);
	}
	xfs_perag_put(pag);
	return error;
}

static int
xfs_iunlink_remove_inode(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_buf		*agibp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_agi		*agi = agibp->b_addr;
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	xfs_agino_t		head_agino;
	short			bucket_index = xfs_iunlink_member_bucket(ip, agino);
	int			error;

	trace_xfs_iunlink_remove(ip);

	/* sess47 (D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372): entering the remove
	 * with NO in-core chain state (i_prev_unlinked==0 means "not on any
	 * in-core list") is the precondition of the silent mid-list failure —
	 * a reaped zombie whose shell was reclaimed between the open-defer and
	 * the retry lost prev/next, and only the bucket+authority snapshot was
	 * restored.  Loud: this must never be reached without a prior bucket
	 * reload. */
	if (!ip->i_prev_unlinked)
		pr_warn("mxfs: P-UNLREM-INCOMPLETE ino=%llu agino=0x%x bucket=%d ub=%d prev=0 next=0x%x lu=%d au=%d comm=%s\n",
			(unsigned long long)ip->i_ino, agino, (int)bucket_index,
			(int)ip->i_unlinked_bucket, ip->i_next_unlinked,
			xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK) ? 1 : 0,
			xfs_iflags_test(ip, MXFS_IF_ADOPTED_UNLINK) ? 1 : 0,
			current->comm);

	/* mxfs sess40: an unstamped membership in multi-node mode means this
	 * entry predates the stamp (legacy insert) — legal during a knob
	 * transition, but loud so an unexpected population is visible. */
	if (mxfs_iunlink_slot_buckets && ip->i_unlinked_bucket < 0 &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		static atomic_t p84_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p84_n) <= 100)
			pr_warn("mxfs: P84-UNL-BUCKET-UNSET ino=%llu agino=0x%x fallback_bucket=%d comm=%s\n",
				(unsigned long long)ip->i_ino, agino,
				(int)bucket_index, current->comm);
	}

	/*
	 * Get the index into the agi hash table for the list this inode will
	 * go on.  Make sure the head pointer isn't garbage.
	 */
	head_agino = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	if (!xfs_verify_agino(pag, head_agino)) {
		/* sess42 P71-INSTR: fire-only-on-corruption probe — is the
		 * in-core AGI STALE vs disk (read-coherency bug) or does it
		 * MATCH disk (genuine on-disk garbage / block double-alloc)? */
		int p71_d = mxfs_ag_buf_disk_differs(agibp);
		uint32_t p71_disk_head =
			mxfs_agi_disk_bucket_head(agibp, bucket_index);
		uint32_t p71_dnlink = 0;
		int p71_dmode = mxfs_inode_disk_mode(ip, &p71_dnlink);
		pr_warn("mxfs: P71-INSTR agi-unlinked-garbage agno=%u bucket=%d head_agino=0x%x "
			"disk_head=0x%x ino=%llu agino=0x%x nlink=%u next_unlinked=0x%x disk_dimode=0%o disk_dnlink=%u agi_daddr=%lld agi_gen=%llu agi_bflags=0x%x agi_disk_differs=%d pag_gen=%llu\n",
			pag_agno(pag), bucket_index, head_agino,
			p71_disk_head,
			(unsigned long long)ip->i_ino, agino,
			VFS_I(ip)->i_nlink, ip->i_next_unlinked, p71_dmode, p71_dnlink,
			(long long)agibp->b_maps[0].bm_bn,
			(unsigned long long)agibp->b_mxfs_ag_gen,
			agibp->b_flags, p71_d,
			(unsigned long long)pag->pag_dlm_meta_gen);
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp,
				agi, sizeof(*agi));
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
		return -EFSCORRUPTED;
	}

	/*
	 * sess38 P83-UNL-REMCHK (D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN
	 * RULE-4 discriminator, instr-gated: one FUA dinode read per remove):
	 * compare the ON-DISK di_next_unlinked with the in-core value we are
	 * about to stitch the shared bucket with.  A peer's mid-bucket remove
	 * legally rewires OUR unlinked inode's disk next pointer; nothing
	 * refreshes the in-core copy across AG-DLM handoffs.  STALE=1 here,
	 * correlated with the later droplink rc=-117 shutdown, proves the
	 * stale-stitch mechanism (and names the wrong agino we wrote).
	 */
	if (unlikely(mxfs_instr_enabled)) {
		uint32_t p83_dnl = 0, p83_dnext = 0;
		int p83_dmode = mxfs_inode_disk_unlinked(ip, &p83_dnl,
							 &p83_dnext);
		int p83_stale = (p83_dmode >= 0 &&
				 p83_dnext != ip->i_next_unlinked);

		if (p83_stale || ip->i_next_unlinked != NULLAGINO)
			pr_warn("mxfs: P83-UNL-REMCHK ino=%llu agno=%u agino=0x%x bucket=%d incore_next=0x%x disk_next=0x%x STALE=%d incore_prev=0x%x head=0x%x disk_nlink=%u dmode=0%o agi_gen=%llu realns=%llu\n",
				(unsigned long long)ip->i_ino, pag_agno(pag),
				agino, (int)bucket_index,
				ip->i_next_unlinked, p83_dnext, p83_stale,
				ip->i_prev_unlinked, head_agino,
				p83_dnl, p83_dmode < 0 ? 0 : p83_dmode,
				(unsigned long long)agibp->b_mxfs_ag_gen,
				(unsigned long long)ktime_get_real_ns());
	}

	/*
	 * Set our inode's next_unlinked pointer to NULL and then return
	 * the old pointer value so that we can update whatever was previous
	 * to us in the list to point to whatever was next in the list.
	 */
	error = xfs_iunlink_log_inode(tp, ip, pag, NULLAGINO);
	if (error) {
		pr_warn("mxfs: P-UNLREM-LOGSELF ino=%llu agino=0x%x bucket=%d rc=%d\n",
			(unsigned long long)ip->i_ino, agino,
			(int)bucket_index, error);
		return error;
	}

	/*
	 * Update the prev pointer in the next inode to point back to previous
	 * inode in the chain.
	 */
	error = xfs_iunlink_update_backref(pag, ip->i_prev_unlinked,
			ip->i_next_unlinked);
	if (error == -ENOLINK)
		error = xfs_iunlink_reload_next(tp, agibp, ip->i_prev_unlinked,
				ip->i_next_unlinked, bucket_index);
	if (error) {
		pr_warn("mxfs: P-UNLREM-BACKREF ino=%llu agino=0x%x bucket=%d prev=0x%x next=0x%x rc=%d\n",
			(unsigned long long)ip->i_ino, agino,
			(int)bucket_index, ip->i_prev_unlinked,
			ip->i_next_unlinked, error);
		return error;
	}

	if (head_agino != agino) {
		struct xfs_inode	*prev_ip;

		prev_ip = xfs_iunlink_lookup(pag, ip->i_prev_unlinked);
		if (!prev_ip) {
			/* sess47: the ONLY silent -EFSCORRUPTED exit in this
			 * function — the run2 ring's -117 had no P71-INSTR, no
			 * XFS_CORRUPTION_ERROR, no P82-REM.  Name it. */
			pr_warn("mxfs: P-UNLREM-NOPREV ino=%llu agino=0x%x bucket=%d head=0x%x prev=0x%x next=0x%x lu=%d au=%d comm=%s — mid-list remove, prev not in-core\n",
				(unsigned long long)ip->i_ino, agino,
				(int)bucket_index, head_agino,
				ip->i_prev_unlinked, ip->i_next_unlinked,
				xfs_iflags_test(ip, MXFS_IF_LOCAL_UNLINK) ? 1 : 0,
				xfs_iflags_test(ip, MXFS_IF_ADOPTED_UNLINK) ? 1 : 0,
				current->comm);
			xfs_inode_mark_sick(ip, XFS_SICK_INO_CORE);
			return -EFSCORRUPTED;
		}

		error = xfs_iunlink_log_inode(tp, prev_ip, pag,
				ip->i_next_unlinked);
		prev_ip->i_next_unlinked = ip->i_next_unlinked;
	} else {
		/* Point the head of the list to the next unlinked inode. */
		error = xfs_iunlink_update_bucket(tp, pag, agibp, bucket_index,
				ip->i_next_unlinked);
	}

	/* sess2 (a9a03929) P82-REM: mirror of P82-ADD — trace every
	 * unlinked-list REMOVE so a leak (an ADD with no matching REM, e.g. a
	 * skipped inactivation) is directly visible by agino pairing in one
	 * run's log.  next= is the value the head/prev slot was repointed to. */
	pr_warn("mxfs: P82-REM ino=%llu agno=%u agino=0x%x bucket=%d head=0x%x next=0x%x at_head=%d rc=%d realns=%llu\n",
		(unsigned long long)ip->i_ino, pag_agno(pag), agino,
		(int)bucket_index, head_agino, ip->i_next_unlinked,
		head_agino == agino ? 1 : 0, error,
		(unsigned long long)ktime_get_real_ns());
	ip->i_next_unlinked = NULLAGINO;
	ip->i_prev_unlinked = 0;
	ip->i_unlinked_bucket = -1;
	/* sess387: leaving the on-disk list discharges the publication
	 * obligation — the entry peers could dereference is gone. */
	if (!error) {
		extern void mxfs_pubob_discharge(struct xfs_mount *,
						 struct xfs_inode *,
						 const char *);
		mxfs_pubob_discharge(mp, ip, "removed");
	}
	return error;
}

/*
 * Pull the on-disk inode from the AGI unlinked list.
 */
int
xfs_iunlink_remove(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_inode	*ip)
{
	struct xfs_buf		*agibp;
	int			error;

	trace_xfs_iunlink_remove(ip);

	/* Get the agi buffer first.  It ensures lock ordering on the list. */
	error = xfs_read_agi(pag, tp, 0, &agibp);
	if (error)
		return error;

	return xfs_iunlink_remove_inode(tp, pag, agibp, ip);
}

/*
 * Decrement the link count on an inode & log the change.  If this causes the
 * link count to go to zero, move the inode to AGI unlinked list so that it can
 * be freed when the last active reference goes away via xfs_inactive().
 */
int
xfs_droplink(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct inode		*inode = VFS_I(ip);

	xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_CHG);

	if (inode->i_nlink == 0) {
		xfs_info_ratelimited(tp->t_mountp,
 "Inode 0x%llx link count dropped below zero.  Pinning link count.",
				ip->i_ino);
		mxfs_set_nlink(ip, XFS_NLINK_PINNED);
	}
	if (inode->i_nlink != XFS_NLINK_PINNED)
		mxfs_drop_nlink(ip);

	/*
	 * ccloop c7ee71c6 sess20: disarm the P186 link-count revert detector for
	 * this inode.  That detector flags an outgoing dinode whose di_nlink is
	 * below one this node already saw durable, which is only a valid
	 * inference while the count is MONOTONIC.  A legitimate removal breaks
	 * that: measured 812 of 984 P186 hits came from the storm's own
	 * `rm -rf` teardown, where the count is correctly going down and the
	 * high-water mark can never come back with it.  Clearing the mark here
	 * is the conservative direction — it can only cost us detections on a
	 * directory that is being torn down, never produce a false accusation.
	 */
	if (S_ISDIR(inode->i_mode))
		ip->i_mxfs_disk_nlink_seen = 0;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);

	if (inode->i_nlink)
		return 0;

	/*
	 * mxfs (sess19 ccloop): THIS node just drove the link count to 0 via a
	 * user-level remove/rename-over/rmdir.  Record the local-unlink intent so
	 * the clustered destructive-inactivation guard (xfs_inactive) knows a
	 * later nlink==0 inactivation of THIS incarnation is legitimately ours and
	 * may free its blocks — as opposed to a torn/stale in-core copy of a
	 * peer's still-live inode (flag CLEAR), whose free would double-free a
	 * block the peer's on-disk inode still owns (bnobt ltbno+ltlen>bno
	 * shutdown).  This is the genuine intent point (user remove path); the
	 * low-level xfs_iunlink below is shared with internal re-insert paths and
	 * is NOT a reliable intent signal.  See MXFS_IF_LOCAL_UNLINK.
	 */
	xfs_iflags_set(ip, MXFS_IF_LOCAL_UNLINK);

	return xfs_iunlink(tp, ip);
}

/*
 * Increment the link count on an inode & log the change.
 */
void
xfs_bumplink(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct inode		*inode = VFS_I(ip);

	xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_CHG);

	if (inode->i_nlink == XFS_NLINK_PINNED - 1)
		xfs_info_ratelimited(tp->t_mountp,
 "Inode 0x%llx link count exceeded maximum.  Pinning link count.",
				ip->i_ino);
	if (inode->i_nlink != XFS_NLINK_PINNED)
		mxfs_inc_nlink(ip);

	/*
	 * ccloop c7ee71c6 sess19 nlink LEDGER (RULE 4).  tests/sf_mkdir_storm.sh
	 * reproduces a DURABLE lost update of a shared parent's link count under
	 * concurrent cross-node mkdir (32 nodes, one shortform parent: nlink
	 * settles at 29 with 32 visible subdirectories, still 29 minutes later on
	 * every node), while the same mkdirs SERIALIZED propagate perfectly
	 * (2->6 across 4 nodes).  So the count is lost in a race, not by a
	 * missing propagation.  This is the BUMP end of the ledger: the other two
	 * are the reload adopt (P180-NLR) and the platter publish (P180-NLW).
	 * Ordering all three by realns across nodes shows exactly which node
	 * bumped from a base that a peer had already advanced past.
	 * Param-gated (mxfs.nlink_ledger, default 0) — inert in normal runs.
	 */
	if (unlikely(mxfs_nlink_ledger) && S_ISDIR(inode->i_mode))
		pr_warn("mxfs: P180-NLB ino=%llu to=%u cc=%llu comm=%s realns=%llu\n",
			(unsigned long long)ip->i_ino, inode->i_nlink,
			(unsigned long long)inode_peek_iversion(inode),
			current->comm,
			(unsigned long long)ktime_get_real_ns());

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
}

/* Free an inode in the ondisk index and zero it out. */
int
xfs_inode_uninit(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	struct xfs_inode	*ip,
	struct xfs_icluster	*xic)
{
	struct xfs_mount	*mp = ip->i_mount;
	int			error;

	/*
	 * Free the inode first so that we guarantee that the AGI lock is going
	 * to be taken before we remove the inode from the unlinked list. This
	 * makes the AGI lock -> unlinked list modification order the same as
	 * used in O_TMPFILE creation.
	 */
	error = xfs_difree(tp, pag, ip->i_ino, xic);
	if (error)
		return error;

	error = xfs_iunlink_remove(tp, pag, ip);
	if (error)
		return error;

	/*
	 * Free any local-format data sitting around before we reset the
	 * data fork to extents format.  Note that the attr fork data has
	 * already been freed by xfs_attr_inactive.
	 */
	if (ip->i_df.if_format == XFS_DINODE_FMT_LOCAL) {
		kfree(ip->i_df.if_data);
		ip->i_df.if_data = NULL;
		ip->i_df.if_bytes = 0;
	}

	VFS_I(ip)->i_mode = 0;		/* mark incore inode as free */
	ip->i_diflags = 0;
	ip->i_diflags2 = mp->m_ino_geo.new_diflags2;
	ip->i_forkoff = 0;		/* mark the attr fork not in use */
	ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;

	/*
	 * Bump the generation count so no one will be confused
	 * by reincarnations of this inode.
	 */
	VFS_I(ip)->i_generation++;
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	return 0;
}
