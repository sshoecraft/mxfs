// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_btree.h"
#include "xfs_ialloc.h"
#include "xfs_ialloc_btree.h"
#include "xfs_alloc.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_bmap.h"
#include "xfs_trans.h"
#include "xfs_buf_item.h"
#include "xfs_icreate_item.h"
#include "xfs_icache.h"
#include "xfs_mxfs_dlm.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_rmap.h"
#include "xfs_ag.h"
#include "xfs_health.h"
#include "xfs_buf.h"
#include "../../dlm/v5_mount.h"
#include "xfs_mxfs_dlm.h"

/*
 * Lookup a record by ino in the btree given by cur.
 */
int					/* error */
xfs_inobt_lookup(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_agino_t		ino,	/* starting inode of chunk */
	xfs_lookup_t		dir,	/* <=, >=, == */
	int			*stat)	/* success/failure */
{
	cur->bc_rec.i.ir_startino = ino;
	cur->bc_rec.i.ir_holemask = 0;
	cur->bc_rec.i.ir_count = 0;
	cur->bc_rec.i.ir_freecount = 0;
	cur->bc_rec.i.ir_free = 0;
	return xfs_btree_lookup(cur, dir, stat);
}

/*
 * Update the record referred to by cur to the value given.
 * This either works (return 0) or gets an EFSCORRUPTED error.
 */
STATIC int				/* error */
xfs_inobt_update(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_inobt_rec_incore_t	*irec)	/* btree record */
{
	union xfs_btree_rec	rec;

	rec.inobt.ir_startino = cpu_to_be32(irec->ir_startino);
	if (xfs_has_sparseinodes(cur->bc_mp)) {
		rec.inobt.ir_u.sp.ir_holemask = cpu_to_be16(irec->ir_holemask);
		rec.inobt.ir_u.sp.ir_count = irec->ir_count;
		rec.inobt.ir_u.sp.ir_freecount = irec->ir_freecount;
	} else {
		/* ir_holemask/ir_count not supported on-disk */
		rec.inobt.ir_u.f.ir_freecount = cpu_to_be32(irec->ir_freecount);
	}
	rec.inobt.ir_free = cpu_to_be64(irec->ir_free);
	return xfs_btree_update(cur, &rec);
}

/* Convert on-disk btree record to incore inobt record. */
void
xfs_inobt_btrec_to_irec(
	struct xfs_mount		*mp,
	const union xfs_btree_rec	*rec,
	struct xfs_inobt_rec_incore	*irec)
{
	irec->ir_startino = be32_to_cpu(rec->inobt.ir_startino);
	if (xfs_has_sparseinodes(mp)) {
		irec->ir_holemask = be16_to_cpu(rec->inobt.ir_u.sp.ir_holemask);
		irec->ir_count = rec->inobt.ir_u.sp.ir_count;
		irec->ir_freecount = rec->inobt.ir_u.sp.ir_freecount;
	} else {
		/*
		 * ir_holemask/ir_count not supported on-disk. Fill in hardcoded
		 * values for full inode chunks.
		 */
		irec->ir_holemask = XFS_INOBT_HOLEMASK_FULL;
		irec->ir_count = XFS_INODES_PER_CHUNK;
		irec->ir_freecount =
				be32_to_cpu(rec->inobt.ir_u.f.ir_freecount);
	}
	irec->ir_free = be64_to_cpu(rec->inobt.ir_free);
}

/* Compute the freecount of an incore inode record. */
uint8_t
xfs_inobt_rec_freecount(
	const struct xfs_inobt_rec_incore	*irec)
{
	uint64_t				realfree = irec->ir_free;

	if (xfs_inobt_issparse(irec->ir_holemask))
		realfree &= xfs_inobt_irec_to_allocmask(irec);
	return hweight64(realfree);
}

/* Simple checks for inode records. */
xfs_failaddr_t
xfs_inobt_check_irec(
	struct xfs_perag			*pag,
	const struct xfs_inobt_rec_incore	*irec)
{
	/* Record has to be properly aligned within the AG. */
	if (!xfs_verify_agino(pag, irec->ir_startino))
		return __this_address;
	if (!xfs_verify_agino(pag,
				irec->ir_startino + XFS_INODES_PER_CHUNK - 1))
		return __this_address;
	if (irec->ir_count < XFS_INODES_PER_HOLEMASK_BIT ||
	    irec->ir_count > XFS_INODES_PER_CHUNK)
		return __this_address;
	if (irec->ir_freecount > XFS_INODES_PER_CHUNK)
		return __this_address;

	if (xfs_inobt_rec_freecount(irec) != irec->ir_freecount)
		return __this_address;

	return NULL;
}

static inline int
xfs_inobt_complain_bad_rec(
	struct xfs_btree_cur		*cur,
	xfs_failaddr_t			fa,
	const struct xfs_inobt_rec_incore *irec)
{
	struct xfs_mount		*mp = cur->bc_mp;

	xfs_warn(mp,
		"%sbt record corruption in AG %d detected at %pS!",
		cur->bc_ops->name, cur->bc_group->xg_gno, fa);
	xfs_warn(mp,
"start inode 0x%x, count 0x%x, free 0x%x freemask 0x%llx, holemask 0x%x",
		irec->ir_startino, irec->ir_count, irec->ir_freecount,
		irec->ir_free, irec->ir_holemask);
	xfs_btree_mark_sick(cur);
	return -EFSCORRUPTED;
}

/*
 * Get the data from the pointed-to record.
 */
int
xfs_inobt_get_rec(
	struct xfs_btree_cur		*cur,
	struct xfs_inobt_rec_incore	*irec,
	int				*stat)
{
	struct xfs_mount		*mp = cur->bc_mp;
	union xfs_btree_rec		*rec;
	xfs_failaddr_t			fa;
	int				error;

	error = xfs_btree_get_rec(cur, &rec, stat);
	if (error || *stat == 0)
		return error;

	xfs_inobt_btrec_to_irec(mp, rec, irec);
	fa = xfs_inobt_check_irec(to_perag(cur->bc_group), irec);
	if (fa)
		return xfs_inobt_complain_bad_rec(cur, fa, irec);

	return 0;
}

/*
 * Insert a single inobt record. Cursor must already point to desired location.
 */
int
xfs_inobt_insert_rec(
	struct xfs_btree_cur	*cur,
	uint16_t		holemask,
	uint8_t			count,
	int32_t			freecount,
	xfs_inofree_t		free,
	int			*stat)
{
	cur->bc_rec.i.ir_holemask = holemask;
	cur->bc_rec.i.ir_count = count;
	cur->bc_rec.i.ir_freecount = freecount;
	cur->bc_rec.i.ir_free = free;
	return xfs_btree_insert(cur, stat);
}

/*
 * Insert records describing a newly allocated inode chunk into the inobt.
 */
STATIC int
xfs_inobt_insert(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct xfs_buf		*agbp,
	xfs_agino_t		newino,
	xfs_agino_t		newlen,
	bool			is_finobt)
{
	struct xfs_btree_cur	*cur;
	xfs_agino_t		thisino;
	int			i;
	int			error;

	if (is_finobt)
		cur = xfs_finobt_init_cursor(pag, tp, agbp);
	else
		cur = xfs_inobt_init_cursor(pag, tp, agbp);

	for (thisino = newino;
	     thisino < newino + newlen;
	     thisino += XFS_INODES_PER_CHUNK) {
		error = xfs_inobt_lookup(cur, thisino, XFS_LOOKUP_EQ, &i);
		if (error) {
			xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
			return error;
		}
		ASSERT(i == 0);

		error = xfs_inobt_insert_rec(cur, XFS_INOBT_HOLEMASK_FULL,
					     XFS_INODES_PER_CHUNK,
					     XFS_INODES_PER_CHUNK,
					     XFS_INOBT_ALL_FREE, &i);
		if (error) {
			xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
			return error;
		}
		ASSERT(i == 1);
	}

	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);

	return 0;
}

/*
 * Verify that the number of free inodes in the AGI is correct.
 */
#ifdef DEBUG
static int
xfs_check_agi_freecount(
	struct xfs_btree_cur	*cur)
{
	if (cur->bc_nlevels == 1) {
		xfs_inobt_rec_incore_t rec;
		int		freecount = 0;
		int		error;
		int		i;

		error = xfs_inobt_lookup(cur, 0, XFS_LOOKUP_GE, &i);
		if (error)
			return error;

		do {
			error = xfs_inobt_get_rec(cur, &rec, &i);
			if (error)
				return error;

			if (i) {
				freecount += rec.ir_freecount;
				error = xfs_btree_increment(cur, 0, &i);
				if (error)
					return error;
			}
		} while (i == 1);

		if (!xfs_is_shutdown(cur->bc_mp)) {
			ASSERT(freecount ==
				to_perag(cur->bc_group)->pagi_freecount);
		}
	}
	return 0;
}
#else
#define xfs_check_agi_freecount(cur)	0
#endif

/*
 * Initialise a new set of inodes. When called without a transaction context
 * (e.g. from recovery) we initiate a delayed write of the inode buffers rather
 * than logging them (which in a transaction context puts them into the AIL
 * for writeback rather than the xfsbufd queue).
 *
 * sess338 513B: @mxfs_foreign_recovery — the recovery caller (icreate item
 * replay) is applying a DEAD PEER's log slice through a foreign shadow xlog;
 * stamp its queued buffers with the write-failure provenance so a failed
 * write fails the replay instead of shutting down the survivor's live
 * b_mount.  Always false with a transaction context.
 */
int
xfs_ialloc_inode_init(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct list_head	*buffer_list,
	bool			mxfs_foreign_recovery,
	int			icount,
	xfs_agnumber_t		agno,
	xfs_agblock_t		agbno,
	xfs_agblock_t		length,
	unsigned int		gen)
{
	struct xfs_buf		*fbuf;
	struct xfs_dinode	*free;
	int			nbufs;
	int			version;
	int			i, j;
	xfs_daddr_t		d;
	xfs_ino_t		ino = 0;
	int			error;

	/*
	 * Loop over the new block(s), filling in the inodes.  For small block
	 * sizes, manipulate the inodes in buffers  which are multiples of the
	 * blocks size.
	 */
	nbufs = length / M_IGEO(mp)->blocks_per_cluster;

	/*
	 * sess45 (ccloop 8ddb16a2) RULE-4 PROBE — the 2/tcp durable wedge is a
	 * PARTIALLY-zeroed inode cluster on disk (slots 0-3 valid, 4-15 zero).
	 * Log every inode-chunk init in multi-node: agbno (-> daddr=agbno*spb),
	 * blocks (length), inodes (icount), nbufs (=length/bpc, integer div),
	 * and the cluster geometry.  If nbufs==0 (length<blocks_per_cluster) the
	 * for(j<nbufs) loop below NEVER runs -> the allocated block is never
	 * stamped with inode magic -> reads back as zeros.  Catch it red-handed.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		static atomic_t p45_init = ATOMIC_INIT(0);

		if (atomic_inc_return(&p45_init) <= 40)
			pr_warn("mxfs: P45-INIT agno=%u agbno=%u daddr=%lld length=%u icount=%d nbufs=%d ipc=%d bpc=%d\n",
				agno, agbno,
				(long long)XFS_AGB_TO_DADDR(mp, agno, agbno),
				length, icount, nbufs,
				M_IGEO(mp)->inodes_per_cluster,
				M_IGEO(mp)->blocks_per_cluster);
	}

	/*
	 * Figure out what version number to use in the inodes we create.  If
	 * the superblock version has caught up to the one that supports the new
	 * inode format, then use the new inode version.  Otherwise use the old
	 * version so that old kernels will continue to be able to use the file
	 * system.
	 *
	 * For v3 inodes, we also need to write the inode number into the inode,
	 * so calculate the first inode number of the chunk here as
	 * XFS_AGB_TO_AGINO() only works within a filesystem block, not
	 * across multiple filesystem blocks (such as a cluster) and so cannot
	 * be used in the cluster buffer loop below.
	 *
	 * Further, because we are writing the inode directly into the buffer
	 * and calculating a CRC on the entire inode, we have ot log the entire
	 * inode so that the entire range the CRC covers is present in the log.
	 * That means for v3 inode we log the entire buffer rather than just the
	 * inode cores.
	 */
	if (xfs_has_v3inodes(mp)) {
		version = 3;
		ino = XFS_AGINO_TO_INO(mp, agno, XFS_AGB_TO_AGINO(mp, agbno));

		/*
		 * log the initialisation that is about to take place as an
		 * logical operation. This means the transaction does not
		 * need to log the physical changes to the inode buffers as log
		 * recovery will know what initialisation is actually needed.
		 * Hence we only need to log the buffers as "ordered" buffers so
		 * they track in the AIL as if they were physically logged.
		 */
		if (tp)
			xfs_icreate_log(tp, agno, agbno, icount,
					mp->m_sb.sb_inodesize, length, gen);
	} else
		version = 2;

	for (j = 0; j < nbufs; j++) {
		/*
		 * Get the block.
		 */
		d = XFS_AGB_TO_DADDR(mp, agno, agbno +
				(j * M_IGEO(mp)->blocks_per_cluster));
		error = xfs_trans_get_buf(tp, mp->m_ddev_targp, d,
				mp->m_bsize * M_IGEO(mp)->blocks_per_cluster,
				0, &fbuf);
		if (error)
			return error;

		/*
		 * sess39 ALWAYS-ON double-alloc detector.  We are about to
		 * initialize this block as an inode cluster.  If the very same
		 * daddr is already cached as a LIVE directory/btree metadata
		 * buffer (its b_ops is a dir op, and especially if it is dirty /
		 * pinned / has a buffer-log-item), then this physical block has
		 * been allocated to BOTH an inode chunk AND a directory — the
		 * AG free-space lost-update that produces the EFSBADCRC "dir
		 * block reads as inode cluster" shutdown under concurrent
		 * same-dir rename.  Blindly overwriting b_ops below would
		 * silently clobber the dir block.  Catch it red-handed.
		 */
		{
			const struct xfs_buf_ops *o = fbuf->b_ops;

			/*
			 * If this daddr already carries a non-inode metadata
			 * verifier (b_ops set, content present) or is dirty /
			 * pinned / log-item-attached, it is a LIVE buffer for
			 * another owner — initializing it as an inode cluster
			 * means the block was double-allocated.  o is the
			 * smoking-gun verifier pointer (cross-ref with the
			 * kernel symbol table to see which: dir3/bnobt/etc.).
			 */
			if (o && o != &xfs_inode_buf_ops &&
			    o != &xfs_inode_buf_ra_ops &&
			    (fbuf->b_flags & XBF_DONE))
				xfs_warn(mp,
				    "MXFS DOUBLE-ALLOC: inode-init daddr=0x%llx agno=%u agbno=%u was a LIVE non-inode buf (b_ops=%ps flags=0x%x pin=%d) — block allocated to TWO owners",
				    (unsigned long long)d, agno,
				    agbno + (unsigned)(j * M_IGEO(mp)->blocks_per_cluster),
				    o, fbuf->b_flags,
				    atomic_read(&fbuf->b_pin_count));
		}

		/* Initialize the inode buffers and log them appropriately. */
		fbuf->b_ops = &xfs_inode_buf_ops;
		xfs_buf_zero(fbuf, 0, BBTOB(fbuf->b_length));
		for (i = 0; i < M_IGEO(mp)->inodes_per_cluster; i++) {
			int	ioffset = i << mp->m_sb.sb_inodelog;

			free = xfs_make_iptr(mp, fbuf, i);
			free->di_magic = cpu_to_be16(XFS_DINODE_MAGIC);
			free->di_version = version;
			free->di_gen = cpu_to_be32(gen);
			free->di_next_unlinked = cpu_to_be32(NULLAGINO);

			if (version == 3) {
				free->di_ino = cpu_to_be64(ino);
				ino++;
				uuid_copy(&free->di_uuid,
					  &mp->m_sb.sb_meta_uuid);
				xfs_dinode_calc_crc(mp, free);
			} else if (tp) {
				/* just log the inode core */
				xfs_trans_log_buf(tp, fbuf, ioffset,
					  ioffset + XFS_DINODE_SIZE(mp) - 1);
			}
		}

		if (tp) {
			/*
			 * Mark the buffer as an inode allocation buffer so it
			 * sticks in AIL at the point of this allocation
			 * transaction. This ensures the they are on disk before
			 * the tail of the log can be moved past this
			 * transaction (i.e. by preventing relogging from moving
			 * it forward in the log).
			 */
			xfs_trans_inode_alloc_buf(tp, fbuf);
			if (version == 3) {
				/*
				 * Mark the buffer as ordered so that they are
				 * not physically logged in the transaction but
				 * still tracked in the AIL as part of the
				 * transaction and pin the log appropriately.
				 */
				xfs_trans_ordered_buf(tp, fbuf);
			}

			/*
			 * MXFS multi-node: also queue this fresh cluster buffer
			 * on the AG's delwri list so mxfs_ag_dlm_unlock can
			 * synchronously submit it before releasing the DLM
			 * lock.  The ordered-buf path alone leaves the home LBA
			 * undefined until AIL push runs; a peer reading the
			 * updated AGI would see zeros there.
			 *
			 * xfs_buf_delwri_queue takes its own reference (via
			 * xfs_buf_hold), independent of the trans attachment.
			 * The buffer stays locked and owned by the transaction;
			 * the delwri list just gives mxfs_ag_dlm_unlock a
			 * targeted, bounded set of buffers to flush, sidestepping
			 * the global xfs_ail_push_all_sync livelock.
			 */
			if (mp->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
				struct xfs_perag *qpag =
					xfs_perag_get(mp, agno);
				/*
				 * sess3 (ccloop 8ba7ae5c) ROOT FIX — fresh-chunk
				 * GARBAGE-READ race (iter_1b: posix_multi 0/32,
				 * 85× xfs_inode_buf_verify EFSCORRUPTED, hexdump
				 * = prior owner's urandom file data).  Inode
				 * VISIBILITY travels via the DIR-DLM (dirent add
				 * + dir handoff) while cluster-init DURABILITY
				 * was tied only to the AG-DLM release drain — and
				 * under AG affinity the carver's AG may not
				 * release for seconds.  A peer lookup in that
				 * window FUA-reads the cluster's home LBA and
				 * finds the PRIOR block owner's bytes: the read
				 * VERIFIER hard-fails (EFSCORRUPTED → EIO) before
				 * any mxfs reload/staleness guard can run — no
				 * retry, cluster-wide collapse.  (The mode-0
				 * free-image window is different: it verifies
				 * fine and is handled by the deferred-publish /
				 * reload machinery.)
				 *
				 * Enforce the GFS2-style ordering at the source:
				 * synchronously write the fully-initialized (v5:
				 * per-dinode CRC already computed) cluster buffer
				 * NOW, before the carve transaction commits and
				 * long before any dirent can expose the chunk.
				 * Content is idempotent init (all-free dinodes):
				 * a cancelled tx leaves harmless bytes on
				 * unreferenced blocks; crash replay re-inits via
				 * the icreate item.  Cost: one sync 8-16K write
				 * per NEW CHUNK (once per 64 inodes).  The
				 * alloc-buflist queueing below stays — the AG
				 * release drain then finds it clean or rewrites
				 * identical content.
				 *
				 * MUST be a raw SCSI FUA write, NEVER
				 * xfs_bwrite: fbuf's BLI is joined to the OPEN
				 * carve transaction (trans_get_buf + ordered),
				 * and buffer write completion runs
				 * xfs_buf_item_done — AIL-delete (not-in-AIL →
				 * log shutdown) + bli free while still linked
				 * in tp->t_items, after which the next
				 * t_items walk (xfs_trans_buf_item_match from
				 * xfs_inobt_insert) spins forever on the
				 * corrupted list holding the dir DLM EX
				 * (proven: iter_2b test30 soft lockup +
				 * 31-node ETIMEDOUT collapse).  The FUA bit
				 * also forces the image past the target's
				 * volatile write cache, which plain
				 * xfs_bwrite never did — a peer FUA READ
				 * would still have missed a cached-only init.
				 * Bounce through kmalloc (P15I idiom):
				 * b_addr may be vmalloc-backed, which the
				 * SCSI passthrough does not map.
				 */
				if (version == 3) {
					extern int mxfs_pal_scsi_write_fua_bdev(
						struct block_device *, uint64_t,
						const void *, uint32_t);
					static atomic_t p133_n = ATOMIC_INIT(0);
					uint32_t p133_len = BBTOB(fbuf->b_length);
					void *p133_mb = kmalloc(p133_len, GFP_NOFS);
					int p133_rc = -ENOMEM;

					if (p133_mb) {
						memcpy(p133_mb, fbuf->b_addr,
						       p133_len);
						p133_rc = mxfs_pal_scsi_write_fua_bdev(
							fbuf->b_target->bt_bdev,
							(uint64_t)fbuf->b_maps[0].bm_bn +
							fbuf->b_target->bt_sector_offset,
							p133_mb, p133_len);
						kfree(p133_mb);
					}
					if (atomic_inc_return(&p133_n) <= 20 ||
					    p133_rc)
						pr_warn("mxfs: P133-ICLUSTER-SYNCINIT agno=%u daddr=%lld len=%u rc=%d comm=%s\n",
							agno,
							(long long)xfs_buf_daddr(fbuf),
							fbuf->b_length, p133_rc,
							current->comm);
				}
				if (qpag) {
					mutex_lock(&qpag->pag_mxfs_alloc_buflist_lock);
					xfs_buf_delwri_queue(fbuf,
						&qpag->pag_mxfs_alloc_buflist);
					/*
					 * v0.3.148 sess33: mark this buf as
					 * "queued by mxfs's alloc-buflist path"
					 * so xfs_ail_push_ag_sync can
					 * distinguish it from regular
					 * xfsaild-managed _XBF_DELWRI_Q bufs.
					 * See xfs_buf.h for full reasoning.
					 */
					fbuf->b_flags |= _XBF_MXFS_ALLOC_QUEUED;
					mutex_unlock(&qpag->pag_mxfs_alloc_buflist_lock);
					xfs_perag_put(qpag);
				}
			}
		} else {
			int	qerr;

			fbuf->b_flags |= XBF_DONE;
			/* sess340 513B: ownership-safe foreign provenance +
			 * queue; a conflict refuses the replay (earlier
			 * clusters stay queued for the caller's unwind). */
			qerr = xfs_buf_delwri_queue_recovery(fbuf, buffer_list,
					mxfs_foreign_recovery);
			xfs_buf_relse(fbuf);
			if (qerr)
				return qerr;
		}
	}
	return 0;
}

/*
 * Align startino and allocmask for a recently allocated sparse chunk such that
 * they are fit for insertion (or merge) into the on-disk inode btrees.
 *
 * Background:
 *
 * When enabled, sparse inode support increases the inode alignment from cluster
 * size to inode chunk size. This means that the minimum range between two
 * non-adjacent inode records in the inobt is large enough for a full inode
 * record. This allows for cluster sized, cluster aligned block allocation
 * without need to worry about whether the resulting inode record overlaps with
 * another record in the tree. Without this basic rule, we would have to deal
 * with the consequences of overlap by potentially undoing recent allocations in
 * the inode allocation codepath.
 *
 * Because of this alignment rule (which is enforced on mount), there are two
 * inobt possibilities for newly allocated sparse chunks. One is that the
 * aligned inode record for the chunk covers a range of inodes not already
 * covered in the inobt (i.e., it is safe to insert a new sparse record). The
 * other is that a record already exists at the aligned startino that considers
 * the newly allocated range as sparse. In the latter case, record content is
 * merged in hope that sparse inode chunks fill to full chunks over time.
 */
STATIC void
xfs_align_sparse_ino(
	struct xfs_mount		*mp,
	xfs_agino_t			*startino,
	uint16_t			*allocmask)
{
	xfs_agblock_t			agbno;
	xfs_agblock_t			mod;
	int				offset;

	agbno = XFS_AGINO_TO_AGBNO(mp, *startino);
	mod = agbno % mp->m_sb.sb_inoalignmt;
	if (!mod)
		return;

	/* calculate the inode offset and align startino */
	offset = XFS_AGB_TO_AGINO(mp, mod);
	*startino -= offset;

	/*
	 * Since startino has been aligned down, left shift allocmask such that
	 * it continues to represent the same physical inodes relative to the
	 * new startino.
	 */
	*allocmask <<= offset / XFS_INODES_PER_HOLEMASK_BIT;
}

/*
 * Determine whether the source inode record can merge into the target. Both
 * records must be sparse, the inode ranges must match and there must be no
 * allocation overlap between the records.
 */
STATIC bool
__xfs_inobt_can_merge(
	struct xfs_inobt_rec_incore	*trec,	/* tgt record */
	struct xfs_inobt_rec_incore	*srec)	/* src record */
{
	uint64_t			talloc;
	uint64_t			salloc;

	/* records must cover the same inode range */
	if (trec->ir_startino != srec->ir_startino)
		return false;

	/* both records must be sparse */
	if (!xfs_inobt_issparse(trec->ir_holemask) ||
	    !xfs_inobt_issparse(srec->ir_holemask))
		return false;

	/* both records must track some inodes */
	if (!trec->ir_count || !srec->ir_count)
		return false;

	/* can't exceed capacity of a full record */
	if (trec->ir_count + srec->ir_count > XFS_INODES_PER_CHUNK)
		return false;

	/* verify there is no allocation overlap */
	talloc = xfs_inobt_irec_to_allocmask(trec);
	salloc = xfs_inobt_irec_to_allocmask(srec);
	if (talloc & salloc)
		return false;

	return true;
}

/*
 * Merge the source inode record into the target. The caller must call
 * __xfs_inobt_can_merge() to ensure the merge is valid.
 */
STATIC void
__xfs_inobt_rec_merge(
	struct xfs_inobt_rec_incore	*trec,	/* target */
	struct xfs_inobt_rec_incore	*srec)	/* src */
{
	ASSERT(trec->ir_startino == srec->ir_startino);

	/* combine the counts */
	trec->ir_count += srec->ir_count;
	trec->ir_freecount += srec->ir_freecount;

	/*
	 * Merge the holemask and free mask. For both fields, 0 bits refer to
	 * allocated inodes. We combine the allocated ranges with bitwise AND.
	 */
	trec->ir_holemask &= srec->ir_holemask;
	trec->ir_free &= srec->ir_free;
}

/*
 * Insert a new sparse inode chunk into the associated inode allocation btree.
 * The inode record for the sparse chunk is pre-aligned to a startino that
 * should match any pre-existing sparse inode record in the tree. This allows
 * sparse chunks to fill over time.
 *
 * If no preexisting record exists, the provided record is inserted.
 * If there is a preexisting record, the provided record is merged with the
 * existing record and updated in place. The merged record is returned in nrec.
 *
 * It is considered corruption if a merge is requested and not possible. Given
 * the sparse inode alignment constraints, this should never happen.
 */
STATIC int
xfs_inobt_insert_sprec(
	struct xfs_perag		*pag,
	struct xfs_trans		*tp,
	struct xfs_buf			*agbp,
	struct xfs_inobt_rec_incore	*nrec)	/* in/out: new/merged rec. */
{
	struct xfs_mount		*mp = pag_mount(pag);
	struct xfs_btree_cur		*cur;
	int				error;
	int				i;
	struct xfs_inobt_rec_incore	rec;

	cur = xfs_inobt_init_cursor(pag, tp, agbp);

	/* the new record is pre-aligned so we know where to look */
	error = xfs_inobt_lookup(cur, nrec->ir_startino, XFS_LOOKUP_EQ, &i);
	if (error)
		goto error;
	/* if nothing there, insert a new record and return */
	if (i == 0) {
		error = xfs_inobt_insert_rec(cur, nrec->ir_holemask,
					     nrec->ir_count, nrec->ir_freecount,
					     nrec->ir_free, &i);
		if (error)
			goto error;
		if (XFS_IS_CORRUPT(mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error;
		}

		goto out;
	}

	/*
	 * A record exists at this startino.  Merge the records.
	 */
	error = xfs_inobt_get_rec(cur, &rec, &i);
	if (error)
		goto error;
	if (XFS_IS_CORRUPT(mp, i != 1)) {
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error;
	}
	if (XFS_IS_CORRUPT(mp, rec.ir_startino != nrec->ir_startino)) {
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error;
	}

	/*
	 * This should never fail. If we have coexisting records that
	 * cannot merge, something is seriously wrong.
	 */
	if (XFS_IS_CORRUPT(mp, !__xfs_inobt_can_merge(nrec, &rec))) {
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error;
	}

	trace_xfs_irec_merge_pre(pag, &rec, nrec);

	/* merge to nrec to output the updated record */
	__xfs_inobt_rec_merge(nrec, &rec);

	trace_xfs_irec_merge_post(pag, nrec);

	error = xfs_inobt_rec_check_count(mp, nrec);
	if (error)
		goto error;

	error = xfs_inobt_update(cur, nrec);
	if (error)
		goto error;

out:
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	return 0;
error:
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}

/*
 * Insert a new sparse inode chunk into the free inode btree. The inode
 * record for the sparse chunk is pre-aligned to a startino that should match
 * any pre-existing sparse inode record in the tree. This allows sparse chunks
 * to fill over time.
 *
 * The new record is always inserted, overwriting a pre-existing record if
 * there is one.
 */
STATIC int
xfs_finobt_insert_sprec(
	struct xfs_perag		*pag,
	struct xfs_trans		*tp,
	struct xfs_buf			*agbp,
	struct xfs_inobt_rec_incore	*nrec)	/* in/out: new rec. */
{
	struct xfs_mount		*mp = pag_mount(pag);
	struct xfs_btree_cur		*cur;
	int				error;
	int				i;

	cur = xfs_finobt_init_cursor(pag, tp, agbp);

	/* the new record is pre-aligned so we know where to look */
	error = xfs_inobt_lookup(cur, nrec->ir_startino, XFS_LOOKUP_EQ, &i);
	if (error)
		goto error;
	/* if nothing there, insert a new record and return */
	if (i == 0) {
		error = xfs_inobt_insert_rec(cur, nrec->ir_holemask,
					     nrec->ir_count, nrec->ir_freecount,
					     nrec->ir_free, &i);
		if (error)
			goto error;
		if (XFS_IS_CORRUPT(mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error;
		}
	} else {
		error = xfs_inobt_update(cur, nrec);
		if (error)
			goto error;
	}

	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	return 0;
error:
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}


/*
 * Allocate new inodes in the allocation group specified by agbp.  Returns 0 if
 * inodes were allocated in this AG; -EAGAIN if there was no space in this AG so
 * the caller knows it can try another AG, a hard -ENOSPC when over the maximum
 * inode count threshold, or the usual negative error code for other errors.
 */
STATIC int
xfs_ialloc_ag_alloc(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct xfs_buf		*agbp)
{
	struct xfs_agi		*agi;
	struct xfs_alloc_arg	args;
	int			error;
	xfs_agino_t		newino;		/* new first inode's number */
	xfs_agino_t		newlen;		/* new number of inodes */
	int			isaligned = 0;	/* inode allocation at stripe */
						/* unit boundary */
	/* init. to full chunk */
	struct xfs_inobt_rec_incore rec;
	struct xfs_ino_geometry	*igeo = M_IGEO(tp->t_mountp);
	uint16_t		allocmask = (uint16_t) -1;
	int			do_sparse = 0;

	memset(&args, 0, sizeof(args));
	args.tp = tp;
	args.mp = tp->t_mountp;
	args.fsbno = NULLFSBLOCK;
	args.oinfo = XFS_RMAP_OINFO_INODES;
	args.pag = pag;

#ifdef DEBUG
	/* randomly do sparse inode allocations */
	if (xfs_has_sparseinodes(tp->t_mountp) &&
	    igeo->ialloc_min_blks < igeo->ialloc_blks)
		do_sparse = get_random_u32_below(2);
#endif

	/*
	 * Locking will ensure that we don't have two callers in here
	 * at one time.
	 */
	newlen = igeo->ialloc_inos;
	if (igeo->maxicount &&
	    percpu_counter_read_positive(&args.mp->m_icount) + newlen >
							igeo->maxicount)
		return -ENOSPC;
	args.minlen = args.maxlen = igeo->ialloc_blks;
	/*
	 * First try to allocate inodes contiguous with the last-allocated
	 * chunk of inodes.  If the filesystem is striped, this will fill
	 * an entire stripe unit with inodes.
	 */
	agi = agbp->b_addr;
	newino = be32_to_cpu(agi->agi_newino);
	args.agbno = XFS_AGINO_TO_AGBNO(args.mp, newino) +
		     igeo->ialloc_blks;
	if (do_sparse)
		goto sparse_alloc;
	if (likely(newino != NULLAGINO &&
		  (args.agbno < be32_to_cpu(agi->agi_length)))) {
		args.prod = 1;

		/*
		 * We need to take into account alignment here to ensure that
		 * we don't modify the free list if we fail to have an exact
		 * block. If we don't have an exact match, and every oher
		 * attempt allocation attempt fails, we'll end up cancelling
		 * a dirty transaction and shutting down.
		 *
		 * For an exact allocation, alignment must be 1,
		 * however we need to take cluster alignment into account when
		 * fixing up the freelist. Use the minalignslop field to
		 * indicate that extra blocks might be required for alignment,
		 * but not to use them in the actual exact allocation.
		 */
		args.alignment = 1;
		args.minalignslop = igeo->cluster_align - 1;

		/* Allow space for the inode btree to split. */
		args.minleft = igeo->inobt_maxlevels;
		error = xfs_alloc_vextent_exact_bno(&args,
				xfs_agbno_to_fsb(pag, args.agbno));
		if (error)
			return error;

		/*
		 * This request might have dirtied the transaction if the AG can
		 * satisfy the request, but the exact block was not available.
		 * If the allocation did fail, subsequent requests will relax
		 * the exact agbno requirement and increase the alignment
		 * instead. It is critical that the total size of the request
		 * (len + alignment + slop) does not increase from this point
		 * on, so reset minalignslop to ensure it is not included in
		 * subsequent requests.
		 */
		args.minalignslop = 0;
	}

	if (unlikely(args.fsbno == NULLFSBLOCK)) {
		/*
		 * Set the alignment for the allocation.
		 * If stripe alignment is turned on then align at stripe unit
		 * boundary.
		 * If the cluster size is smaller than a filesystem block
		 * then we're doing I/O for inodes in filesystem block size
		 * pieces, so don't need alignment anyway.
		 */
		isaligned = 0;
		if (igeo->ialloc_align) {
			ASSERT(!xfs_has_noalign(args.mp));
			args.alignment = args.mp->m_dalign;
			isaligned = 1;
		} else
			args.alignment = igeo->cluster_align;
		/*
		 * Allocate a fixed-size extent of inodes.
		 */
		args.prod = 1;
		/*
		 * Allow space for the inode btree to split.
		 */
		args.minleft = igeo->inobt_maxlevels;
		error = xfs_alloc_vextent_near_bno(&args,
				xfs_agbno_to_fsb(pag,
					be32_to_cpu(agi->agi_root)));
		if (error)
			return error;
	}

	/*
	 * If stripe alignment is turned on, then try again with cluster
	 * alignment.
	 */
	if (isaligned && args.fsbno == NULLFSBLOCK) {
		args.alignment = igeo->cluster_align;
		error = xfs_alloc_vextent_near_bno(&args,
				xfs_agbno_to_fsb(pag,
					be32_to_cpu(agi->agi_root)));
		if (error)
			return error;
	}

	/*
	 * Finally, try a sparse allocation if the filesystem supports it and
	 * the sparse allocation length is smaller than a full chunk.
	 */
	if (xfs_has_sparseinodes(args.mp) &&
	    igeo->ialloc_min_blks < igeo->ialloc_blks &&
	    args.fsbno == NULLFSBLOCK) {
sparse_alloc:
		args.alignment = args.mp->m_sb.sb_spino_align;
		args.prod = 1;

		args.minlen = igeo->ialloc_min_blks;
		args.maxlen = args.minlen;

		/*
		 * The inode record will be aligned to full chunk size. We must
		 * prevent sparse allocation from AG boundaries that result in
		 * invalid inode records, such as records that start at agbno 0
		 * or extend beyond the AG.
		 *
		 * Set min agbno to the first chunk aligned, non-zero agbno and
		 * max to one less than the last chunk aligned agbno from the
		 * end of the AG. We subtract 1 from max so that the cluster
		 * allocation alignment takes over and allows allocation within
		 * the last full inode chunk in the AG.
		 */
		args.min_agbno = args.mp->m_sb.sb_inoalignmt;
		args.max_agbno = round_down(xfs_ag_block_count(args.mp,
							pag_agno(pag)),
					    args.mp->m_sb.sb_inoalignmt) - 1;

		error = xfs_alloc_vextent_near_bno(&args,
				xfs_agbno_to_fsb(pag,
					be32_to_cpu(agi->agi_root)));
		if (error)
			return error;

		newlen = XFS_AGB_TO_AGINO(args.mp, args.len);
		ASSERT(newlen <= XFS_INODES_PER_CHUNK);
		allocmask = (1 << (newlen / XFS_INODES_PER_HOLEMASK_BIT)) - 1;
	}

	if (args.fsbno == NULLFSBLOCK)
		return -EAGAIN;

	ASSERT(args.len == args.minlen);

	/*
	 * Stamp and write the inode buffers.
	 *
	 * Seed the new inode cluster with a random generation number. This
	 * prevents short-term reuse of generation numbers if a chunk is
	 * freed and then immediately reallocated. We use random numbers
	 * rather than a linear progression to prevent the next generation
	 * number from being easily guessable.
	 */
	error = xfs_ialloc_inode_init(args.mp, tp, NULL, false, newlen,
			pag_agno(pag), args.agbno, args.len,
			get_random_u32());

	if (error)
		return error;

	/*
	 * MXFS: flag this AG so its DLM release path flushes dirty cluster
	 * buffers to disk before the AGI update becomes visible to peers.
	 * Without this, a peer can read the new AGI, look up an inode in
	 * the new chunk via xfs_imap_to_bp, and hit zero-filled (or stale)
	 * bytes at the home LBA because the cluster's ordered-buf AIL
	 * writeback has not yet run.
	 */
	if (args.mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(args.mp->m_mxfs_dlm))
		pag->pag_mxfs_alloc_dirty = true;
	/*
	 * Convert the results.
	 */
	newino = XFS_AGB_TO_AGINO(args.mp, args.agbno);

	if (xfs_inobt_issparse(~allocmask)) {
		/*
		 * We've allocated a sparse chunk. Align the startino and mask.
		 */
		xfs_align_sparse_ino(args.mp, &newino, &allocmask);

		rec.ir_startino = newino;
		rec.ir_holemask = ~allocmask;
		rec.ir_count = newlen;
		rec.ir_freecount = newlen;
		rec.ir_free = XFS_INOBT_ALL_FREE;

		/*
		 * Insert the sparse record into the inobt and allow for a merge
		 * if necessary. If a merge does occur, rec is updated to the
		 * merged record.
		 */
		error = xfs_inobt_insert_sprec(pag, tp, agbp, &rec);
		if (error == -EFSCORRUPTED) {
			xfs_alert(args.mp,
	"invalid sparse inode record: ino 0x%llx holemask 0x%x count %u",
				  xfs_agino_to_ino(pag, rec.ir_startino),
				  rec.ir_holemask, rec.ir_count);
			xfs_force_shutdown(args.mp, SHUTDOWN_CORRUPT_INCORE);
		}
		if (error)
			return error;

		/*
		 * We can't merge the part we've just allocated as for the inobt
		 * due to finobt semantics. The original record may or may not
		 * exist independent of whether physical inodes exist in this
		 * sparse chunk.
		 *
		 * We must update the finobt record based on the inobt record.
		 * rec contains the fully merged and up to date inobt record
		 * from the previous call. Set merge false to replace any
		 * existing record with this one.
		 */
		if (xfs_has_finobt(args.mp)) {
			error = xfs_finobt_insert_sprec(pag, tp, agbp, &rec);
			if (error)
				return error;
		}
	} else {
		/* full chunk - insert new records to both btrees */
		error = xfs_inobt_insert(pag, tp, agbp, newino, newlen, false);
		if (error)
			return error;

		if (xfs_has_finobt(args.mp)) {
			error = xfs_inobt_insert(pag, tp, agbp, newino,
						 newlen, true);
			if (error)
				return error;
		}
	}

	/*
	 * Update AGI counts and newino.
	 */
	be32_add_cpu(&agi->agi_count, newlen);
	be32_add_cpu(&agi->agi_freecount, newlen);
	pag->pagi_freecount += newlen;
	pag->pagi_count += newlen;
	agi->agi_newino = cpu_to_be32(newino);

	/*
	 * Log allocation group header fields
	 */
	xfs_ialloc_log_agi(tp, agbp,
		XFS_AGI_COUNT | XFS_AGI_FREECOUNT | XFS_AGI_NEWINO);
	/*
	 * Modify/log superblock values for inode count and inode free count.
	 */
	xfs_trans_mod_sb(tp, XFS_TRANS_SB_ICOUNT, (long)newlen);
	xfs_trans_mod_sb(tp, XFS_TRANS_SB_IFREE, (long)newlen);
	return 0;
}

/*
 * Try to retrieve the next record to the left/right from the current one.
 */
STATIC int
xfs_ialloc_next_rec(
	struct xfs_btree_cur	*cur,
	xfs_inobt_rec_incore_t	*rec,
	int			*done,
	int			left)
{
	int                     error;
	int			i;

	if (left)
		error = xfs_btree_decrement(cur, 0, &i);
	else
		error = xfs_btree_increment(cur, 0, &i);

	if (error)
		return error;
	*done = !i;
	if (i) {
		error = xfs_inobt_get_rec(cur, rec, &i);
		if (error)
			return error;
		if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			return -EFSCORRUPTED;
		}
	}

	return 0;
}

STATIC int
xfs_ialloc_get_rec(
	struct xfs_btree_cur	*cur,
	xfs_agino_t		agino,
	xfs_inobt_rec_incore_t	*rec,
	int			*done)
{
	int                     error;
	int			i;

	error = xfs_inobt_lookup(cur, agino, XFS_LOOKUP_EQ, &i);
	if (error)
		return error;
	*done = !i;
	if (i) {
		error = xfs_inobt_get_rec(cur, rec, &i);
		if (error)
			return error;
		if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			return -EFSCORRUPTED;
		}
	}

	return 0;
}

/*
 * Return the offset of the first free inode in the record. If the inode chunk
 * is sparsely allocated, we convert the record holemask to inode granularity
 * and mask off the unallocated regions from the inode free mask.
 */
STATIC int
xfs_inobt_first_free_inode(
	struct xfs_inobt_rec_incore	*rec)
{
	xfs_inofree_t			realfree;

	/* if there are no holes, return the first available offset */
	if (!xfs_inobt_issparse(rec->ir_holemask))
		return xfs_lowbit64(rec->ir_free);

	realfree = xfs_inobt_irec_to_allocmask(rec);
	realfree &= rec->ir_free;

	return xfs_lowbit64(realfree);
}

/*
 * If this AG has corrupt inodes, check if allocating this inode would fail
 * with corruption errors.  Returns 0 if we're clear, or EAGAIN to try again
 * somewhere else.
 */
static int
xfs_dialloc_check_ino(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	xfs_ino_t		ino)
{
	struct xfs_imap		imap;
	struct xfs_buf		*bp;
	int			error;

	error = xfs_imap(pag, tp, ino, &imap, 0);
	if (error)
		return -EAGAIN;

	error = xfs_imap_to_bp(pag_mount(pag), tp, &imap, &bp);
	if (error)
		return -EAGAIN;

	xfs_trans_brelse(tp, bp);
	return 0;
}

#ifdef __KERNEL__
/*
 * P150 (RULE-4, ccloop-4dd7 inobt double-free record corruption): record-
 * level trace of EVERY inobt/finobt record RMW in multi-node mode.  Joined
 * across nodes per (agno,startino), the ALLOC/FREE interleaving shows
 * directly where a peer's alloc/free vanished from the record (stale-base
 * RMW / lost destage), independent of WHICH buffer-coherency mechanism
 * failed.  tenure/mgen are the AG-DLM coherency stamps at RMW time;
 * btenure/bgen are the leaf buffer's stamps (btenure!=tenure at an RMW =
 * modifying a base not re-validated under the current AG hold).  Capped.
 */
static void
mxfs_p150_inorec(
	struct xfs_btree_cur		*cur,
	const char			*tag,
	int				offset,
	uint64_t			pre_free,
	int				pre_fc,
	const struct xfs_inobt_rec_incore *post)
{
	static atomic_t			p150_n = ATOMIC_INIT(0);
	struct xfs_perag		*pag;
	struct xfs_buf			*bp = NULL;
	struct xfs_btree_block		*bb;
	struct xfs_mount		*mp = cur->bc_mp;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (atomic_inc_return(&p150_n) > 20000)
		return;
	pag = to_perag(cur->bc_group);
	bb = xfs_btree_get_block(cur, 0, &bp);
	pr_warn("mxfs: P150-%s agno=%u startino=%u off=%d pre=0x%llx/%d post=0x%llx/%d tenure=%llu mgen=%llu btenure=%llu bgen=%llu daddr=%lld lsn=%llx comm=%s realns=%llu\n",
		tag, pag_agno(pag), (unsigned)post->ir_startino, offset,
		(unsigned long long)pre_free, pre_fc,
		(unsigned long long)post->ir_free, (int)post->ir_freecount,
		(unsigned long long)pag->ag_dlm_tenure_id,
		(unsigned long long)pag->pag_dlm_meta_gen,
		bp ? (unsigned long long)bp->b_tenure_id : 0,
		bp ? (unsigned long long)bp->b_mxfs_ag_gen : 0,
		bp ? (long long)bp->b_maps[0].bm_bn : -1LL,
		bb ? (unsigned long long)be64_to_cpu(bb->bb_u.s.bb_lsn) : 0,
		current->comm,
		(unsigned long long)ktime_get_real_ns());
}
#else
#define mxfs_p150_inorec(cur, tag, offset, pre_free, pre_fc, post) do { } while (0)
#endif

#ifdef __KERNEL__
/*
 * ccloop-4dd7 sess2 (GPT-reviewed design; deadlock-3 autopsy): reserve the
 * candidate ino's cluster DLM EX at SELECTION time, BEFORE the inobt/finobt
 * record RMW dirties the transaction.  Upstream's create order is
 * AG -> (dirty) -> child-ino ILOCK at icreate/iget; a peer's truncate order
 * is ino -> AG.  When the peer holds a grant on our candidate with its
 * holder blocked wanting OUR AG, the old blocking child acquire at iget
 * deadlocked with BOTH edges dirty (unbreakable; 180s -> -110 -> cluster
 * shutdown).  The invariant this enforces: no NEW blocking cluster acquire
 * after the transaction is irrevocable.  Bounded 1-retry acquire (~1s: one
 * master round-trip + one BAST-served release; uncontended = fast); on
 * contention while still CLEAN return -EAGAIN — xfs_dialloc's AG loop skips
 * to the next AG (same contract as mxfs_ag_dlm_trylock above).  If already
 * dirty (mid-chunk-alloc path that did not roll), proceed loudly — the old
 * behavior, now instrumented as the invariant violation it is.  On success
 * the grant is node-cached, so icreate/iget's ilock fast-paths on it — the
 * reservation IS the handoff token.
 */
static int
mxfs_dialloc_reserve_ino(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	xfs_ino_t		ino)
{
	struct xfs_mount	*mp = pag_mount(pag);
	int			rc;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;

	rc = mxfs_v5_dlm_inode_lock_retries(mp->m_mxfs_dlm, ino,
					    MXFS_LOCK_EX, 1, NULL);
	if (rc == 0)
		return 0;

	if (tp->t_flags & XFS_TRANS_DIRTY) {
		pr_warn_ratelimited(
		    "mxfs: P-DIALLOC-RESV-DIRTY ino=%llu agno=%u rc=%d — candidate contended but trans already dirty; falling through to blocking iget acquire\n",
			(unsigned long long)ino, pag_agno(pag), rc);
		return 0;
	}
	pr_warn_ratelimited(
	    "mxfs: P-DIALLOC-RESV-BUSY ino=%llu agno=%u rc=%d — peer holds candidate ino; skipping AG this pass\n",
		(unsigned long long)ino, pag_agno(pag), rc);
	return -EAGAIN;
}
#else
#define mxfs_dialloc_reserve_ino(pag, tp, ino) (0)
#endif

/*
 * Allocate an inode using the inobt-only algorithm.
 */
STATIC int
xfs_dialloc_ag_inobt(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct xfs_buf		*agbp,
	xfs_ino_t		parent,
	xfs_ino_t		*inop)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_agi		*agi = agbp->b_addr;
	xfs_agnumber_t		pagno = XFS_INO_TO_AGNO(mp, parent);
	xfs_agino_t		pagino = XFS_INO_TO_AGINO(mp, parent);
	struct xfs_btree_cur	*cur, *tcur;
	struct xfs_inobt_rec_incore rec, trec;
	xfs_ino_t		ino;
	int			error;
	int			offset;
	int			i, j;
	int			searchdistance = 10;

	ASSERT(xfs_perag_initialised_agi(pag));
	ASSERT(xfs_perag_allows_inodes(pag));
	ASSERT(pag->pagi_freecount > 0);

 restart_pagno:
	cur = xfs_inobt_init_cursor(pag, tp, agbp);
	/*
	 * If pagino is 0 (this is the root inode allocation) use newino.
	 * This must work because we've just allocated some.
	 */
	if (!pagino)
		pagino = be32_to_cpu(agi->agi_newino);

	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error0;

	/*
	 * If in the same AG as the parent, try to get near the parent.
	 */
	if (pagno == pag_agno(pag)) {
		int		doneleft;	/* done, to the left */
		int		doneright;	/* done, to the right */

		error = xfs_inobt_lookup(cur, pagino, XFS_LOOKUP_LE, &i);
		if (error)
			goto error0;
		if (XFS_IS_CORRUPT(mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error0;
		}

		error = xfs_inobt_get_rec(cur, &rec, &j);
		if (error)
			goto error0;
		if (XFS_IS_CORRUPT(mp, j != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error0;
		}

		if (rec.ir_freecount > 0) {
			/*
			 * Found a free inode in the same chunk
			 * as the parent, done.
			 */
			goto alloc_inode;
		}


		/*
		 * In the same AG as parent, but parent's chunk is full.
		 */

		/* duplicate the cursor, search left & right simultaneously */
		error = xfs_btree_dup_cursor(cur, &tcur);
		if (error)
			goto error0;

		/*
		 * Skip to last blocks looked up if same parent inode.
		 */
		if (pagino != NULLAGINO &&
		    pag->pagl_pagino == pagino &&
		    pag->pagl_leftrec != NULLAGINO &&
		    pag->pagl_rightrec != NULLAGINO) {
			error = xfs_ialloc_get_rec(tcur, pag->pagl_leftrec,
						   &trec, &doneleft);
			if (error)
				goto error1;

			error = xfs_ialloc_get_rec(cur, pag->pagl_rightrec,
						   &rec, &doneright);
			if (error)
				goto error1;
		} else {
			/* search left with tcur, back up 1 record */
			error = xfs_ialloc_next_rec(tcur, &trec, &doneleft, 1);
			if (error)
				goto error1;

			/* search right with cur, go forward 1 record. */
			error = xfs_ialloc_next_rec(cur, &rec, &doneright, 0);
			if (error)
				goto error1;
		}

		/*
		 * Loop until we find an inode chunk with a free inode.
		 */
		while (--searchdistance > 0 && (!doneleft || !doneright)) {
			int	useleft;  /* using left inode chunk this time */

			/* figure out the closer block if both are valid. */
			if (!doneleft && !doneright) {
				useleft = pagino -
				 (trec.ir_startino + XFS_INODES_PER_CHUNK - 1) <
				  rec.ir_startino - pagino;
			} else {
				useleft = !doneleft;
			}

			/* free inodes to the left? */
			if (useleft && trec.ir_freecount) {
				xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
				cur = tcur;

				pag->pagl_leftrec = trec.ir_startino;
				pag->pagl_rightrec = rec.ir_startino;
				pag->pagl_pagino = pagino;
				rec = trec;
				goto alloc_inode;
			}

			/* free inodes to the right? */
			if (!useleft && rec.ir_freecount) {
				xfs_btree_del_cursor(tcur, XFS_BTREE_NOERROR);

				pag->pagl_leftrec = trec.ir_startino;
				pag->pagl_rightrec = rec.ir_startino;
				pag->pagl_pagino = pagino;
				goto alloc_inode;
			}

			/* get next record to check */
			if (useleft) {
				error = xfs_ialloc_next_rec(tcur, &trec,
								 &doneleft, 1);
			} else {
				error = xfs_ialloc_next_rec(cur, &rec,
								 &doneright, 0);
			}
			if (error)
				goto error1;
		}

		if (searchdistance <= 0) {
			/*
			 * Not in range - save last search
			 * location and allocate a new inode
			 */
			xfs_btree_del_cursor(tcur, XFS_BTREE_NOERROR);
			pag->pagl_leftrec = trec.ir_startino;
			pag->pagl_rightrec = rec.ir_startino;
			pag->pagl_pagino = pagino;

		} else {
			/*
			 * We've reached the end of the btree. because
			 * we are only searching a small chunk of the
			 * btree each search, there is obviously free
			 * inodes closer to the parent inode than we
			 * are now. restart the search again.
			 */
			pag->pagl_pagino = NULLAGINO;
			pag->pagl_leftrec = NULLAGINO;
			pag->pagl_rightrec = NULLAGINO;
			xfs_btree_del_cursor(tcur, XFS_BTREE_NOERROR);
			xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
			goto restart_pagno;
		}
	}

	/*
	 * In a different AG from the parent.
	 * See if the most recently allocated block has any free.
	 */
	if (agi->agi_newino != cpu_to_be32(NULLAGINO)) {
		error = xfs_inobt_lookup(cur, be32_to_cpu(agi->agi_newino),
					 XFS_LOOKUP_EQ, &i);
		if (error)
			goto error0;

		if (i == 1) {
			error = xfs_inobt_get_rec(cur, &rec, &j);
			if (error)
				goto error0;

			if (j == 1 && rec.ir_freecount > 0) {
				/*
				 * The last chunk allocated in the group
				 * still has a free inode.
				 */
				goto alloc_inode;
			}
		}
	}

	/*
	 * None left in the last group, search the whole AG
	 */
	error = xfs_inobt_lookup(cur, 0, XFS_LOOKUP_GE, &i);
	if (error)
		goto error0;
	if (XFS_IS_CORRUPT(mp, i != 1)) {
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error0;
	}

	for (;;) {
		error = xfs_inobt_get_rec(cur, &rec, &i);
		if (error)
			goto error0;
		if (XFS_IS_CORRUPT(mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error0;
		}
		if (rec.ir_freecount > 0)
			break;
		error = xfs_btree_increment(cur, 0, &i);
		if (error)
			goto error0;
		if (XFS_IS_CORRUPT(mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error0;
		}
	}

alloc_inode:
	offset = xfs_inobt_first_free_inode(&rec);
	ASSERT(offset >= 0);
	ASSERT(offset < XFS_INODES_PER_CHUNK);
	ASSERT((XFS_AGINO_TO_OFFSET(mp, rec.ir_startino) %
				   XFS_INODES_PER_CHUNK) == 0);
	ino = xfs_agino_to_ino(pag, rec.ir_startino + offset);

	if (xfs_ag_has_sickness(pag, XFS_SICK_AG_INODES)) {
		error = xfs_dialloc_check_ino(pag, tp, ino);
		if (error)
			goto error0;
	}

	error = mxfs_dialloc_reserve_ino(pag, tp, ino);
	if (error)
		goto error0;

	{
		uint64_t p150_pre = rec.ir_free;
		int p150_fc = rec.ir_freecount;

		rec.ir_free &= ~XFS_INOBT_MASK(offset);
		rec.ir_freecount--;
		mxfs_p150_inorec(cur, "ALLOC-IBT", offset, p150_pre, p150_fc,
				 &rec);
	}
	error = xfs_inobt_update(cur, &rec);
	if (error)
		goto error0;
	be32_add_cpu(&agi->agi_freecount, -1);
	xfs_ialloc_log_agi(tp, agbp, XFS_AGI_FREECOUNT);
	pag->pagi_freecount--;

	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error0;

	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	xfs_trans_mod_sb(tp, XFS_TRANS_SB_IFREE, -1);
	*inop = ino;
	return 0;
error1:
	xfs_btree_del_cursor(tcur, XFS_BTREE_ERROR);
error0:
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}

/*
 * Use the free inode btree to allocate an inode based on distance from the
 * parent. Note that the provided cursor may be deleted and replaced.
 */
STATIC int
xfs_dialloc_ag_finobt_near(
	xfs_agino_t			pagino,
	struct xfs_btree_cur		**ocur,
	struct xfs_inobt_rec_incore	*rec)
{
	struct xfs_btree_cur		*lcur = *ocur;	/* left search cursor */
	struct xfs_btree_cur		*rcur;	/* right search cursor */
	struct xfs_inobt_rec_incore	rrec;
	int				error;
	int				i, j;

	error = xfs_inobt_lookup(lcur, pagino, XFS_LOOKUP_LE, &i);
	if (error)
		return error;

	if (i == 1) {
		error = xfs_inobt_get_rec(lcur, rec, &i);
		if (error)
			return error;
		if (XFS_IS_CORRUPT(lcur->bc_mp, i != 1)) {
			pr_warn("mxfs: P-DIAG-NEAR-LE-GETREC agno=%u pagino=%u i=%d\n",
				pag_agno(to_perag(lcur->bc_group)), pagino, i);
			xfs_btree_mark_sick(lcur);
			return -EFSCORRUPTED;
		}

		/*
		 * See if we've landed in the parent inode record. The finobt
		 * only tracks chunks with at least one free inode, so record
		 * existence is enough.
		 */
		if (pagino >= rec->ir_startino &&
		    pagino < (rec->ir_startino + XFS_INODES_PER_CHUNK))
			return 0;
	}

	error = xfs_btree_dup_cursor(lcur, &rcur);
	if (error)
		return error;

	error = xfs_inobt_lookup(rcur, pagino, XFS_LOOKUP_GE, &j);
	if (error)
		goto error_rcur;
	if (j == 1) {
		error = xfs_inobt_get_rec(rcur, &rrec, &j);
		if (error)
			goto error_rcur;
		if (XFS_IS_CORRUPT(lcur->bc_mp, j != 1)) {
			xfs_btree_mark_sick(lcur);
			error = -EFSCORRUPTED;
			goto error_rcur;
		}
	}

	if (XFS_IS_CORRUPT(lcur->bc_mp, i != 1 && j != 1)) {
		/* sess42 P72-INSTR: fire-only-on-corruption — is the finobt
		 * leaf STALE vs disk (read-coherency) or on-disk garbage? */
		{
			struct xfs_perag *p72_pag = to_perag(lcur->bc_group);
			struct xfs_buf *p72_lb = lcur->bc_levels[0].bp;
			int p72_d = p72_lb ? mxfs_ag_buf_disk_differs(p72_lb) : -99;
			int p72_pin = p72_lb ? atomic_read(&p72_lb->b_pin_count) : -1;
			int p72_dirty = (p72_lb && p72_lb->b_log_item &&
				test_bit(XFS_LI_DIRTY, &p72_lb->b_log_item->bli_item.li_flags)) ? 1 : 0;
			pr_warn("mxfs: P72-INSTR finobt-near-fail agno=%u i=%d j=%d pagino=%u pag_gen=%llu cached=%d holders=%d "
				"fino_daddr=%lld fino_gen=%llu fino_bflags=0x%x fino_disk_differs=%d fino_pin=%d fino_dirty=%d\n",
				pag_agno(p72_pag), i, j, pagino,
				(unsigned long long)p72_pag->pag_dlm_meta_gen,
				p72_pag->pag_dlm_cached, p72_pag->pag_dlm_holders,
				p72_lb ? (long long)p72_lb->b_maps[0].bm_bn : -1LL,
				(unsigned long long)(p72_lb ? p72_lb->b_mxfs_ag_gen : 0),
				p72_lb ? p72_lb->b_flags : 0, p72_d, p72_pin, p72_dirty);
		}
		xfs_btree_mark_sick(lcur);
		error = -EFSCORRUPTED;
		goto error_rcur;
	}
	if (i == 1 && j == 1) {
		/*
		 * Both the left and right records are valid. Choose the closer
		 * inode chunk to the target.
		 */
		if ((pagino - rec->ir_startino + XFS_INODES_PER_CHUNK - 1) >
		    (rrec.ir_startino - pagino)) {
			*rec = rrec;
			xfs_btree_del_cursor(lcur, XFS_BTREE_NOERROR);
			*ocur = rcur;
		} else {
			xfs_btree_del_cursor(rcur, XFS_BTREE_NOERROR);
		}
	} else if (j == 1) {
		/* only the right record is valid */
		*rec = rrec;
		xfs_btree_del_cursor(lcur, XFS_BTREE_NOERROR);
		*ocur = rcur;
	} else if (i == 1) {
		/* only the left record is valid */
		xfs_btree_del_cursor(rcur, XFS_BTREE_NOERROR);
	}

	return 0;

error_rcur:
	xfs_btree_del_cursor(rcur, XFS_BTREE_ERROR);
	return error;
}

/*
 * Use the free inode btree to find a free inode based on a newino hint. If
 * the hint is NULL, find the first free inode in the AG.
 */
STATIC int
xfs_dialloc_ag_finobt_newino(
	struct xfs_agi			*agi,
	struct xfs_btree_cur		*cur,
	struct xfs_inobt_rec_incore	*rec)
{
	int error;
	int i;

	if (agi->agi_newino != cpu_to_be32(NULLAGINO)) {
		error = xfs_inobt_lookup(cur, be32_to_cpu(agi->agi_newino),
					 XFS_LOOKUP_EQ, &i);
		if (error)
			return error;
		if (i == 1) {
			error = xfs_inobt_get_rec(cur, rec, &i);
			if (error)
				return error;
			if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
				pr_warn("mxfs: P-DIAG-NEWINO-HINT agno=%u newino=%u i=%d\n",
					pag_agno(to_perag(cur->bc_group)),
					be32_to_cpu(agi->agi_newino), i);
				xfs_btree_mark_sick(cur);
				return -EFSCORRUPTED;
			}
			return 0;
		}
	}

	/*
	 * Find the first inode available in the AG.
	 */
	error = xfs_inobt_lookup(cur, 0, XFS_LOOKUP_GE, &i);
	if (error)
		return error;
	if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
		/* sess95 P-DIAG: the finobt says this AG has free inodes (agi
		 * freecount>0 got us here) but the finobt B-tree itself has NO
		 * record at all (GE 0 returns nothing).  finobt buffer is stale
		 * vs AGI, or empty/torn. */
		{
			struct xfs_perag *dp = to_perag(cur->bc_group);
			struct xfs_buf *lb = cur->bc_levels[0].bp;
			pr_warn("mxfs: P-DIAG-NEWINO-FIRST agno=%u i=%d agi_freecnt=%u "
				"fino_daddr=%lld fino_disk_differs=%d pag_meta_gen=%llu cached=%d holders=%d\n",
				pag_agno(dp), i, be32_to_cpu(agi->agi_freecount),
				lb ? (long long)lb->b_maps[0].bm_bn : -1LL,
				lb ? mxfs_ag_buf_disk_differs(lb) : -99,
				(unsigned long long)dp->pag_dlm_meta_gen,
				dp->pag_dlm_cached, dp->pag_dlm_holders);
		}
		xfs_btree_mark_sick(cur);
		return -EFSCORRUPTED;
	}

	error = xfs_inobt_get_rec(cur, rec, &i);
	if (error)
		return error;
	if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
		pr_warn("mxfs: P-DIAG-NEWINO-GETREC agno=%u i=%d\n",
			pag_agno(to_perag(cur->bc_group)), i);
		xfs_btree_mark_sick(cur);
		return -EFSCORRUPTED;
	}

	return 0;
}

/*
 * Update the inobt based on a modification made to the finobt. Also ensure that
 * the records from both trees are equivalent post-modification.
 */
STATIC int
xfs_dialloc_ag_update_inobt(
	struct xfs_btree_cur		*cur,	/* inobt cursor */
	struct xfs_inobt_rec_incore	*frec,	/* finobt record */
	int				offset) /* inode offset */
{
	struct xfs_inobt_rec_incore	rec;
	int				error;
	int				i;

	error = xfs_inobt_lookup(cur, frec->ir_startino, XFS_LOOKUP_EQ, &i);
	if (error)
		return error;
	if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
		/* sess95 P-DIAG: finobt selected startino %llu but the INOBT has
		 * NO matching record (i=%d) — inobt cached buffer is STALE vs
		 * finobt (cross-tree desync). */
		{
			struct xfs_perag *dp = to_perag(cur->bc_group);
			struct xfs_buf *lb = cur->bc_levels[0].bp;
			pr_warn("mxfs: P-DIAG-UI-LOOKUP agno=%u startino=%llu i=%d "
				"inobt_daddr=%lld inobt_disk_differs=%d pag_meta_gen=%llu cached=%d\n",
				pag_agno(dp), (unsigned long long)frec->ir_startino, i,
				lb ? (long long)lb->b_maps[0].bm_bn : -1LL,
				lb ? mxfs_ag_buf_disk_differs(lb) : -99,
				(unsigned long long)dp->pag_dlm_meta_gen, dp->pag_dlm_cached);
		}
		xfs_btree_mark_sick(cur);
		return -EFSCORRUPTED;
	}

	error = xfs_inobt_get_rec(cur, &rec, &i);
	if (error)
		return error;
	if (XFS_IS_CORRUPT(cur->bc_mp, i != 1)) {
		pr_warn("mxfs: P-DIAG-UI-GETREC agno=%u startino=%llu i=%d\n",
			pag_agno(to_perag(cur->bc_group)),
			(unsigned long long)frec->ir_startino, i);
		xfs_btree_mark_sick(cur);
		return -EFSCORRUPTED;
	}
	ASSERT((XFS_AGINO_TO_OFFSET(cur->bc_mp, rec.ir_startino) %
				   XFS_INODES_PER_CHUNK) == 0);

	{
		uint64_t p150_pre = rec.ir_free;
		int p150_fc = rec.ir_freecount;

		rec.ir_free &= ~XFS_INOBT_MASK(offset);
		rec.ir_freecount--;
		mxfs_p150_inorec(cur, "ALLOC-UI", offset, p150_pre, p150_fc,
				 &rec);
	}

	if (XFS_IS_CORRUPT(cur->bc_mp,
			   rec.ir_free != frec->ir_free ||
			   rec.ir_freecount != frec->ir_freecount)) {
		/* sess95 P-DIAG: the inobt record for this chunk DISAGREES with
		 * the finobt record after applying the same alloc — the two
		 * btrees are out of sync.  Dump both so we can see which side is
		 * stale (cached-buffer coherency vs torn write). */
		{
			struct xfs_perag *dp = to_perag(cur->bc_group);
			struct xfs_buf *lb = cur->bc_levels[0].bp;
			pr_warn("mxfs: P-DIAG-UI-MISMATCH agno=%u startino=%llu offset=%d "
				"inobt_free=0x%llx finobt_free=0x%llx inobt_fcnt=%d finobt_fcnt=%d "
				"inobt_daddr=%lld inobt_disk_differs=%d pag_meta_gen=%llu cached=%d\n",
				pag_agno(dp), (unsigned long long)rec.ir_startino, offset,
				(unsigned long long)rec.ir_free, (unsigned long long)frec->ir_free,
				rec.ir_freecount, frec->ir_freecount,
				lb ? (long long)lb->b_maps[0].bm_bn : -1LL,
				lb ? mxfs_ag_buf_disk_differs(lb) : -99,
				(unsigned long long)dp->pag_dlm_meta_gen, dp->pag_dlm_cached);
		}
		xfs_btree_mark_sick(cur);
		return -EFSCORRUPTED;
	}

	return xfs_inobt_update(cur, &rec);
}

/*
 * Allocate an inode using the free inode btree, if available. Otherwise, fall
 * back to the inobt search algorithm.
 *
 * The caller selected an AG for us, and made sure that free inodes are
 * available.
 */
static int
xfs_dialloc_ag(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct xfs_buf		*agbp,
	xfs_ino_t		parent,
	xfs_ino_t		*inop)
{
	struct xfs_mount		*mp = tp->t_mountp;
	struct xfs_agi			*agi = agbp->b_addr;
	xfs_agnumber_t			pagno = XFS_INO_TO_AGNO(mp, parent);
	xfs_agino_t			pagino = XFS_INO_TO_AGINO(mp, parent);
	struct xfs_btree_cur		*cur;	/* finobt cursor */
	struct xfs_btree_cur		*icur;	/* inobt cursor */
	struct xfs_inobt_rec_incore	rec;
	xfs_ino_t			ino;
	int				error;
	int				offset;
	int				i;

	if (!xfs_has_finobt(mp))
		return xfs_dialloc_ag_inobt(pag, tp, agbp, parent, inop);

	/*
	 * If pagino is 0 (this is the root inode allocation) use newino.
	 * This must work because we've just allocated some.
	 */
	if (!pagino)
		pagino = be32_to_cpu(agi->agi_newino);

	cur = xfs_finobt_init_cursor(pag, tp, agbp);

	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error_cur;

	/*
	 * The search algorithm depends on whether we're in the same AG as the
	 * parent. If so, find the closest available inode to the parent. If
	 * not, consider the agi hint or find the first free inode in the AG.
	 */
	if (pag_agno(pag) == pagno)
		error = xfs_dialloc_ag_finobt_near(pagino, &cur, &rec);
	else
		error = xfs_dialloc_ag_finobt_newino(agi, cur, &rec);
	if (error)
		goto error_cur;

	offset = xfs_inobt_first_free_inode(&rec);
	ASSERT(offset >= 0);
	ASSERT(offset < XFS_INODES_PER_CHUNK);
	ASSERT((XFS_AGINO_TO_OFFSET(mp, rec.ir_startino) %
				   XFS_INODES_PER_CHUNK) == 0);
	ino = xfs_agino_to_ino(pag, rec.ir_startino + offset);

	if (xfs_ag_has_sickness(pag, XFS_SICK_AG_INODES)) {
		error = xfs_dialloc_check_ino(pag, tp, ino);
		if (error)
			goto error_cur;
	}

	error = mxfs_dialloc_reserve_ino(pag, tp, ino);
	if (error)
		goto error_cur;

	/*
	 * Modify or remove the finobt record.
	 */
	{
		uint64_t p150_pre = rec.ir_free;
		int p150_fc = rec.ir_freecount;

		rec.ir_free &= ~XFS_INOBT_MASK(offset);
		rec.ir_freecount--;
		mxfs_p150_inorec(cur, "ALLOC-FIN", offset, p150_pre, p150_fc,
				 &rec);
	}
	if (rec.ir_freecount)
		error = xfs_inobt_update(cur, &rec);
	else
		error = xfs_btree_delete(cur, &i);
	if (error)
		goto error_cur;

	/*
	 * The finobt has now been updated appropriately. We haven't updated the
	 * agi and superblock yet, so we can create an inobt cursor and validate
	 * the original freecount. If all is well, make the equivalent update to
	 * the inobt using the finobt record and offset information.
	 */
	icur = xfs_inobt_init_cursor(pag, tp, agbp);

	error = xfs_check_agi_freecount(icur);
	if (error)
		goto error_icur;

	error = xfs_dialloc_ag_update_inobt(icur, &rec, offset);
	if (error)
		goto error_icur;

	/*
	 * Both trees have now been updated. We must update the perag and
	 * superblock before we can check the freecount for each btree.
	 */
	be32_add_cpu(&agi->agi_freecount, -1);
	xfs_ialloc_log_agi(tp, agbp, XFS_AGI_FREECOUNT);
	pag->pagi_freecount--;

	xfs_trans_mod_sb(tp, XFS_TRANS_SB_IFREE, -1);

	error = xfs_check_agi_freecount(icur);
	if (error)
		goto error_icur;
	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error_icur;

	xfs_btree_del_cursor(icur, XFS_BTREE_NOERROR);
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	*inop = ino;
	return 0;

error_icur:
	xfs_btree_del_cursor(icur, XFS_BTREE_ERROR);
error_cur:
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}

static int
xfs_dialloc_roll(
	struct xfs_trans	**tpp,
	struct xfs_buf		*agibp)
{
	struct xfs_trans	*tp = *tpp;
	struct xfs_dquot_acct	*dqinfo;
	int			error;

	/*
	 * Hold to on to the agibp across the commit so no other allocation can
	 * come in and take the free inodes we just allocated for our caller.
	 */
	xfs_trans_bhold(tp, agibp);

	/*
	 * We want the quota changes to be associated with the next transaction,
	 * NOT this one. So, detach the dqinfo from this and attach it to the
	 * next transaction.
	 */
	dqinfo = tp->t_dqinfo;
	tp->t_dqinfo = NULL;

	error = xfs_trans_roll(&tp);

	/* Re-attach the quota info that we detached from prev trx. */
	tp->t_dqinfo = dqinfo;

	/*
	 * Join the buffer even on commit error so that the buffer is released
	 * when the caller cancels the transaction and doesn't have to handle
	 * this error case specially.
	 */
	xfs_trans_bjoin(tp, agibp);
	*tpp = tp;
	return error;
}

static bool
xfs_dialloc_good_ag(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	umode_t			mode,
	int			flags,
	bool			ok_alloc)
{
	struct xfs_mount	*mp = tp->t_mountp;
	xfs_extlen_t		ineed;
	xfs_extlen_t		longest = 0;
	int			needspace;
	int			error;

	if (!pag)
		return false;
	if (!xfs_perag_allows_inodes(pag))
		return false;

	if (!xfs_perag_initialised_agi(pag)) {
		error = xfs_ialloc_read_agi(pag, tp, 0, NULL);
		if (error)
			return false;
	}

	if (pag->pagi_freecount)
		return true;
	if (!ok_alloc)
		return false;

	if (!xfs_perag_initialised_agf(pag)) {
		error = xfs_alloc_read_agf(pag, tp, flags, NULL);
		if (error)
			return false;
	}

	/*
	 * Check that there is enough free space for the file plus a chunk of
	 * inodes if we need to allocate some. If this is the first pass across
	 * the AGs, take into account the potential space needed for alignment
	 * of inode chunks when checking the longest contiguous free space in
	 * the AG - this prevents us from getting ENOSPC because we have free
	 * space larger than ialloc_blks but alignment constraints prevent us
	 * from using it.
	 *
	 * If we can't find an AG with space for full alignment slack to be
	 * taken into account, we must be near ENOSPC in all AGs.  Hence we
	 * don't include alignment for the second pass and so if we fail
	 * allocation due to alignment issues then it is most likely a real
	 * ENOSPC condition.
	 *
	 * XXX(dgc): this calculation is now bogus thanks to the per-ag
	 * reservations that xfs_alloc_fix_freelist() now does via
	 * xfs_alloc_space_available(). When the AG fills up, pagf_freeblks will
	 * be more than large enough for the check below to succeed, but
	 * xfs_alloc_space_available() will fail because of the non-zero
	 * metadata reservation and hence we won't actually be able to allocate
	 * more inodes in this AG. We do soooo much unnecessary work near ENOSPC
	 * because of this.
	 */
	ineed = M_IGEO(mp)->ialloc_min_blks;
	if (flags && ineed > 1)
		ineed += M_IGEO(mp)->cluster_align;
	longest = pag->pagf_longest;
	if (!longest)
		longest = pag->pagf_flcount > 0;
	needspace = S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode);

	if (pag->pagf_freeblks < needspace + ineed || longest < ineed)
		return false;
	return true;
}

static int
xfs_dialloc_try_ag(
	struct xfs_perag	*pag,
	struct xfs_trans	**tpp,
	xfs_ino_t		parent,
	xfs_ino_t		*new_ino,
	bool			ok_alloc,
	int			flags)
{
	struct xfs_mount	*mp = (*tpp)->t_mountp;
	struct xfs_buf		*agbp;
	xfs_ino_t		ino;
	int			error;

	/*
	 * MXFS: acquire per-AG DLM lock for inode allocation.  On the
	 * XFS_ALLOC_FLAG_TRYLOCK first pass use the non-blocking acquire: if a
	 * peer holds this AG, return -EAGAIN so xfs_dialloc skips to the next
	 * AG instead of blocking up to 120s with the parent-dir ILOCK held
	 * (the proven create-path hold-and-wait deadlock).  The blocking
	 * second pass (flags==0) waits as before.
	 */
	if (flags & XFS_ALLOC_FLAG_TRYLOCK)
		error = mxfs_ag_dlm_trylock(mp, pag);
	else
		error = mxfs_ag_dlm_lock(mp, pag);
	if (error)
		return error;

	/*
	 * Then read in the AGI buffer and recheck with the AGI buffer
	 * lock held.
	 */
	error = xfs_ialloc_read_agi(pag, *tpp, 0, &agbp);
	if (error)
		goto out_dlm;

	if (!pag->pagi_freecount) {
		if (!ok_alloc) {
			error = -EAGAIN;
			goto out_release;
		}

		error = xfs_ialloc_ag_alloc(pag, *tpp, agbp);
		if (error < 0)
			goto out_release;

		/*
		 * We successfully allocated space for an inode cluster in this
		 * AG.  Roll the transaction so that we can allocate one of the
		 * new inodes.
		 */
		ASSERT(pag->pagi_freecount > 0);
		error = xfs_dialloc_roll(tpp, agbp);
		if (error)
			goto out_release;
	}

	/* Allocate an inode in the found AG */
	error = xfs_dialloc_ag(pag, *tpp, agbp, parent, &ino);
	if (!error)
		*new_ino = ino;
	/*
	 * sess24 (ccloop 4eef1f39) RULE-4 DETECTOR (P-IALLOC-DBLALLOC): we just
	 * carved `ino` out of this AG's inobt as FREE.  Read its COHERENT on-disk
	 * mode (plain bio = the image a peer sees).  If it is already a LIVE
	 * inode (mode != 0 and != 0xFFFF), a peer owns that inode number -> the
	 * inobt we read was STALE -> same-chunk double-allocation (the
	 * RELOAD-TYPEFLIP-STALE-SKIP / inobt-corruption root).  Gated off by
	 * default (one extra plain block read per alloc); set
	 * mxfs.dbg_ialloc_dblcheck=1 via sysfs for a cache_coherency repro.
	 */
	{
	extern int mxfs_dbg_ialloc_dblcheck;
	extern uint16_t mxfs_dbg_disk_di_mode_coherent(struct xfs_mount *,
			xfs_ino_t, uint32_t *);
	if (!error && mxfs_dbg_ialloc_dblcheck && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		uint32_t cgen = 0;
		uint16_t cmode = mxfs_dbg_disk_di_mode_coherent(mp, ino, &cgen);

		if (cmode != 0 && cmode != 0xFFFF)
			pr_warn_ratelimited(
				"mxfs: P-IALLOC-DBLALLOC ino=%llu agno=%u carved-FREE-from-inobt but coherent-disk mode=0%o gen=%u is LIVE — inobt stale at alloc (same-chunk double-alloc)\n",
				(unsigned long long)ino,
				(unsigned)XFS_INO_TO_AGNO(mp, ino),
				(unsigned)cmode, cgen);
	}
	}
	/*
	 * MXFS sess386 (474 leg A unwind): a reserve-contended skip
	 * (-EAGAIN from mxfs_dialloc_reserve_ino, transaction still clean)
	 * used to fall through to the deferred-unlock tail below, leaving
	 * THIS AG's AGI buffer locked in the transaction and its AG DLM
	 * grant held until the create finally committed or cancelled —
	 * exactly the held-resource window that froze inactive-ifree, the
	 * AIL min and the release fence fleet-wide.  A skipped AG modified
	 * nothing under the hold, so release both NOW, the same contract as
	 * the !pagi_freecount skip above.
	 */
	if (error == -EAGAIN)
		goto out_release;

	/*
	 * MXFS: defer the DLM unlock to trans commit (priority-2 fix).
	 * Releasing here lets a peer ACQ-FRESH and read pre-allocation AGI /
	 * inobt / finobt content while our trans is still active, leading to
	 * inode double-allocation (same family as bnobt double-alloc fixed
	 * in xfs_alloc.c:3704).
	 */
	mxfs_ag_dlm_unlock_deferred(*tpp, pag);
	return error;

out_release:
	xfs_trans_brelse(*tpp, agbp);
out_dlm:
	mxfs_ag_dlm_unlock(mp, pag);
	return error;
}

/*
 * Pick an AG for the new inode.
 *
 * Directories, symlinks, and regular files frequently allocate at least one
 * block, so factor that potential expansion when we examine whether an AG has
 * enough space for file creation.  Try to keep metadata files all in the same
 * AG.
 */
static inline xfs_agnumber_t
xfs_dialloc_pick_ag(
	struct xfs_mount	*mp,
	struct xfs_inode	*dp,
	umode_t			mode)
{
	xfs_agnumber_t		start_agno;

	if (!dp)
		return 0;
	if (xfs_is_metadir_inode(dp)) {
		if (mp->m_sb.sb_logstart)
			return XFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart);
		return 0;
	}

	if (S_ISDIR(mode)) {
		/*
		 * MXFS AG affinity.  In multi-node, PIN directory inodes to
		 * THIS node's own AG (node_slot %% maxagi), exactly like the
		 * regular-file path below.  The old cluster-wide rotor
		 * (node_slot + agirotor) scattered each node's directories
		 * across ALL AGs, so two nodes doing concurrent mkdirs into
		 * their OWN disjoint subtrees still constantly landed dir
		 * inodes in the SAME AG and ping-ponged that AG's AGI/AGF DLM
		 * grant cross-node — every such acquire is a CAW poll (up to
		 * seconds), which serialized the nodes (the rsync_paired
		 * blow-up).  Keeping a node's dirs in its own AG (alongside
		 * its files) makes every AG-DLM acquire a local nested
		 * fast-path: no cross-node CAW latency.  Single-node keeps the
		 * spreading rotor.
		 */
		if (mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
			return mp->m_mxfs_node_slot % mp->m_maxagi;
		if (mp->m_mxfs_dlm) {
			return (mp->m_mxfs_node_slot +
				atomic_inc_return(&mp->m_agirotor) - 1) %
				mp->m_maxagi;
		}
		return (atomic_inc_return(&mp->m_agirotor) - 1) % mp->m_maxagi;
	}

	/*
	 * MXFS node-affine regular-file allocation (sess45 architectural fix
	 * for the cross_write_read di_size=0 / inode-cluster lost-update).
	 *
	 * Upstream XFS co-locates a new file with its PARENT DIRECTORY's AG
	 * for locality.  In a cluster that is fatal when the parent is a
	 * SHARED directory: every node creating files in one directory
	 * (e.g. the cross_write_read TESTDIR, created by one node) inherits
	 * that single AG, so two nodes' inodes land in the SAME inode
	 * cluster.  The per-inode DLM cannot protect a shared 16KB cluster
	 * buffer: a node flushing its inode writes the WHOLE cluster, with a
	 * stale copy of the peer's inode region, clobbering the peer's
	 * di_size to 0 (proven via P97 INODE-CLUSTER-CLOBBER).
	 *
	 * Fix: in multi-node, allocate a regular file from THIS node's own
	 * AG (node_slot %% maxagi) regardless of the parent's AG.  Distinct
	 * nodes use distinct AGs, so their inodes never share a cluster and
	 * the cross-node clobber is impossible by construction.  We do NOT
	 * rotor across AGs here (unlike dirs): keeping a node's files in its
	 * own AG maximises cross-node separation.  for_each_perag_wrap_at in
	 * the caller still wraps to other AGs only if this node's AG is full.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		start_agno = mp->m_mxfs_node_slot % mp->m_maxagi;
		return start_agno;
	}

	start_agno = XFS_INO_TO_AGNO(mp, dp->i_ino);
	if (start_agno >= mp->m_maxagi)
		start_agno = 0;

	return start_agno;
}

/*
 * MXFS strict AG partition for inode allocation.
 *
 * Each node OWNS a disjoint stride of AGs: agno %% L == node_slot %% L, where
 * L = the FS's configured node count (m_mxfs_log_node_count, a stable on-disk
 * value, default 4).  Inode allocation is confined to a node's owned AGs so two
 * nodes NEVER allocate from / free into the SAME AG's inobt/finobt/AGI
 * concurrently — the cross-node inode DOUBLE-ALLOCATION that corrupts a shared
 * AG's inode btree and shuts the FS down (proven: under cumulative 2-node load
 * each node's affine AG fills, xfs_dialloc spills via for_each_perag_wrap_at
 * into a shared AG, both nodes then alloc/free there -> AG3 INACT-SKIP-STALE /
 * imap_to_bp -5 / Metadata I/O Error shutdown).  With a 13-AG stride per node
 * (50 AGs / L=4) no single owned AG fills under test load, so spillover never
 * crosses into a peer's AG.
 *
 * No constraint when single-node, no DLM, or L<=1.  A final RELAXED pass (see
 * xfs_dialloc) ignores ownership so a node whose entire partition is genuinely
 * full still allocates rather than false-ENOSPC.
 */
static inline bool
mxfs_ag_inode_owned(struct xfs_mount *mp, xfs_agnumber_t agno)
{
	uint32_t L;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return true;
	L = mp->m_mxfs_log_node_count;
	if (L <= 1)
		return true;
	return (agno % L) == (mp->m_mxfs_node_slot % L);
}

/*
 * Allocate an on-disk inode.
 *
 * Mode is used to tell whether the new inode is a directory and hence where to
 * locate it. The on-disk inode that is allocated will be returned in @new_ino
 * on success, otherwise an error will be set to indicate the failure (e.g.
 * -ENOSPC).
 */
int
xfs_dialloc(
	struct xfs_trans	**tpp,
	const struct xfs_icreate_args *args,
	xfs_ino_t		*new_ino)
{
	struct xfs_mount	*mp = (*tpp)->t_mountp;
	struct xfs_perag	*pag;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	xfs_ino_t		ino = NULLFSINO;
	xfs_ino_t		parent = args->pip ? args->pip->i_ino : 0;
	xfs_agnumber_t		agno;
	xfs_agnumber_t		start_agno;
	umode_t			mode = args->mode & S_IFMT;
	bool			ok_alloc = true;
	bool			low_space = false;
	bool			partition_relaxed = false;
	int			flags;
	int			error = 0;
	/*
	 * MXFS sess386 (RULE-5 ruling): bounded jittered re-sweeps before
	 * ENOSPC.  With the bounded inode-DLM reserve, a fully swept AG set
	 * can mean transient CLUSTER CONTENTION (every candidate's grant
	 * parked on a peer for <1s), not exhaustion — and converting that to
	 * ENOSPC is both wrong and user-visible under exactly the workload
	 * the reserve bound protects.  Retry the whole ladder a few times
	 * with jittered backoff (no locks are held at the retry point).  On
	 * a genuinely full fs the extra sweeps are cheap: every good_ag
	 * check fails without I/O.
	 */
	int			resv_sweeps = 0;

	start_agno = xfs_dialloc_pick_ag(mp, args->pip, mode);

	/*
	 * If we have already hit the ceiling of inode blocks then clear
	 * ok_alloc so we scan all available agi structures for a free
	 * inode.
	 *
	 * Read rough value of mp->m_icount by percpu_counter_read_positive,
	 * which will sacrifice the preciseness but improve the performance.
	 */
	if (igeo->maxicount &&
	    percpu_counter_read_positive(&mp->m_icount) + igeo->ialloc_inos
							> igeo->maxicount) {
		ok_alloc = false;
	}

	/*
	 * If we are near to ENOSPC, we want to prefer allocation from AGs that
	 * have free inodes in them rather than use up free space allocating new
	 * inode chunks. Hence we turn off allocation for the first non-blocking
	 * pass through the AGs if we are near ENOSPC to consume free inodes
	 * that we can immediately allocate, but then we allow allocation on the
	 * second pass if we fail to find an AG with free inodes in it.
	 */
	if (xfs_estimate_freecounter(mp, XC_FREE_BLOCKS) <
			mp->m_low_space[XFS_LOWSP_1_PCNT]) {
		ok_alloc = false;
		low_space = true;
	}

	/*
	 * Loop until we find an allocation group that either has free inodes
	 * or in which we can allocate some inodes.  Iterate through the
	 * allocation groups upward, wrapping at the end.
	 */
	flags = XFS_ALLOC_FLAG_TRYLOCK;
	partition_relaxed = false;
retry:
	for_each_perag_wrap_at(mp, start_agno, mp->m_maxagi, agno, pag) {
		/*
		 * MXFS strict AG partition: skip AGs this node does not own so
		 * inode allocation never spills into a peer's AG (cross-node
		 * inobt double-alloc).  The final RELAXED pass below drops the
		 * constraint only if the node's whole partition is full.
		 */
		if (!partition_relaxed &&
		    !mxfs_ag_inode_owned(mp, pag_agno(pag))) {
			if (xfs_is_shutdown(mp)) {
				error = -EFSCORRUPTED;
				break;
			}
			continue;
		}
		if (xfs_dialloc_good_ag(pag, *tpp, mode, flags, ok_alloc)) {
			error = xfs_dialloc_try_ag(pag, tpp, parent,
					&ino, ok_alloc, flags);
			if (error != -EAGAIN)
				break;
			error = 0;
		}

		if (xfs_is_shutdown(mp)) {
			error = -EFSCORRUPTED;
			break;
		}
	}
	if (pag)
		xfs_perag_rele(pag);
	if (error)
		return error;
	if (ino == NULLFSINO) {
		if (flags) {
			flags = 0;
			if (low_space)
				ok_alloc = true;
			goto retry;
		}
		if (!partition_relaxed) {
			/*
			 * Owned partition exhausted (TRYLOCK + blocking passes
			 * found nothing in our AG stride).  Relax ownership and
			 * scan ALL AGs to avoid a false ENOSPC.  Rare — only
			 * when this node's whole 13-AG stride is full.
			 */
			partition_relaxed = true;
			flags = XFS_ALLOC_FLAG_TRYLOCK;
			goto retry;
		}
#ifdef __KERNEL__
		/* MXFS sess386: see resv_sweeps above.  Loud on purpose —
		 * persistent all-AG contention after the deadlock fix is a
		 * defect signal, never something to hide. */
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)
		    && resv_sweeps++ < 4) {
			pr_warn_ratelimited(
			    "mxfs: P-DIALLOC-SWEEP-RETRY sweep=%d start_agno=%u — all AG passes came up empty under cluster contention; jittered re-sweep before any ENOSPC\n",
				resv_sweeps, start_agno);
			msleep(50 + get_random_u32_below(150));
			flags = XFS_ALLOC_FLAG_TRYLOCK;
			partition_relaxed = false;
			if (low_space)
				ok_alloc = false;
			goto retry;
		}
#endif
		return -ENOSPC;
	}

	/*
	 * Protect against obviously corrupt allocation btree records. Later
	 * xfs_iget checks will catch re-allocation of other active in-memory
	 * and on-disk inodes. If we don't catch reallocating the parent inode
	 * here we will deadlock in xfs_iget() so we have to do these checks
	 * first.
	 */
	if (ino == parent || !xfs_verify_dir_ino(mp, ino)) {
		xfs_alert(mp, "Allocated a known in-use inode 0x%llx!", ino);
		xfs_agno_mark_sick(mp, XFS_INO_TO_AGNO(mp, ino),
				XFS_SICK_AG_INOBT);
		return -EFSCORRUPTED;
	}

	*new_ino = ino;
	/* sess36: gate this per-allocation diagnostic (fires on every
	 * create) behind mxfs.instr — default off for perf. */
	{
		extern int mxfs_instr_enabled;
		if (unlikely(mxfs_instr_enabled))
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P9-INSTR dialloc PICK ino=%llu agno=%u parent=%llu",
				(unsigned long long)ino,
				(unsigned int)XFS_INO_TO_AGNO(mp, ino),
				(unsigned long long)parent);
	}
	/* sess90: ALWAYS-ON double-allocation tracer.  P-RELOAD-TYPEFLIP
	 * proved inode 2097285 was handed out as both a DIR and a REG with
	 * the SAME generation (cross/same-node double-alloc via stale
	 * inobt).  Log every PICK with the allocating node's slot + the
	 * mode class so all 4 nodes can be grepped for one ino: same slot
	 * twice = local stale-inobt/reclaim; two slots = affinity-violating
	 * cross-node stale-inobt.  One printk per create — cheap, no instr
	 * 100x slowdown. */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern int mxfs_dirwr_enabled;
		extern int mxfs_instr_enabled;

		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P90-PICK slot=%u ino=%llu agno=%u ifmt=0%o parent=%llu",
				(unsigned int)mp->m_mxfs_node_slot,
				(unsigned long long)ino,
				(unsigned int)XFS_INO_TO_AGNO(mp, ino),
				(unsigned int)mode,
				(unsigned long long)parent);
	}
	return 0;
}

/*
 * Free the blocks of an inode chunk. We must consider that the inode chunk
 * might be sparse and only free the regions that are allocated as part of the
 * chunk.
 */
static int
xfs_difree_inode_chunk(
	struct xfs_trans		*tp,
	struct xfs_perag		*pag,
	struct xfs_inobt_rec_incore	*rec)
{
	struct xfs_mount		*mp = tp->t_mountp;
	xfs_agblock_t			sagbno = XFS_AGINO_TO_AGBNO(mp,
							rec->ir_startino);
	int				startidx, endidx;
	int				nextbit;
	xfs_agblock_t			agbno;
	int				contigblk;
	DECLARE_BITMAP(holemask, XFS_INOBT_HOLEMASK_BITS);

	if (!xfs_inobt_issparse(rec->ir_holemask)) {
		/* not sparse, calculate extent info directly */
		return xfs_free_extent_later(tp, xfs_agbno_to_fsb(pag, sagbno),
				M_IGEO(mp)->ialloc_blks, &XFS_RMAP_OINFO_INODES,
				XFS_AG_RESV_NONE, 0);
	}

	/* holemask is only 16-bits (fits in an unsigned long) */
	ASSERT(sizeof(rec->ir_holemask) <= sizeof(holemask[0]));
	holemask[0] = rec->ir_holemask;

	/*
	 * Find contiguous ranges of zeroes (i.e., allocated regions) in the
	 * holemask and convert the start/end index of each range to an extent.
	 * We start with the start and end index both pointing at the first 0 in
	 * the mask.
	 */
	startidx = endidx = find_first_zero_bit(holemask,
						XFS_INOBT_HOLEMASK_BITS);
	nextbit = startidx + 1;
	while (startidx < XFS_INOBT_HOLEMASK_BITS) {
		int error;

		nextbit = find_next_zero_bit(holemask, XFS_INOBT_HOLEMASK_BITS,
					     nextbit);
		/*
		 * If the next zero bit is contiguous, update the end index of
		 * the current range and continue.
		 */
		if (nextbit != XFS_INOBT_HOLEMASK_BITS &&
		    nextbit == endidx + 1) {
			endidx = nextbit;
			goto next;
		}

		/*
		 * nextbit is not contiguous with the current end index. Convert
		 * the current start/end to an extent and add it to the free
		 * list.
		 */
		agbno = sagbno + (startidx * XFS_INODES_PER_HOLEMASK_BIT) /
				  mp->m_sb.sb_inopblock;
		contigblk = ((endidx - startidx + 1) *
			     XFS_INODES_PER_HOLEMASK_BIT) /
			    mp->m_sb.sb_inopblock;

		ASSERT(agbno % mp->m_sb.sb_spino_align == 0);
		ASSERT(contigblk % mp->m_sb.sb_spino_align == 0);
		error = xfs_free_extent_later(tp, xfs_agbno_to_fsb(pag, agbno),
				contigblk, &XFS_RMAP_OINFO_INODES,
				XFS_AG_RESV_NONE, 0);
		if (error)
			return error;

		/* reset range to current bit and carry on... */
		startidx = endidx = nextbit;

next:
		nextbit++;
	}
	return 0;
}

STATIC int
xfs_difree_inobt(
	struct xfs_perag		*pag,
	struct xfs_trans		*tp,
	struct xfs_buf			*agbp,
	xfs_agino_t			agino,
	struct xfs_icluster		*xic,
	struct xfs_inobt_rec_incore	*orec)
{
	struct xfs_mount		*mp = pag_mount(pag);
	struct xfs_agi			*agi = agbp->b_addr;
	struct xfs_btree_cur		*cur;
	struct xfs_inobt_rec_incore	rec;
	int				ilen;
	int				error;
	int				i;
	int				off;

	ASSERT(agi->agi_magicnum == cpu_to_be32(XFS_AGI_MAGIC));
	ASSERT(XFS_AGINO_TO_AGBNO(mp, agino) < be32_to_cpu(agi->agi_length));

	/*
	 * Initialize the cursor.
	 */
	cur = xfs_inobt_init_cursor(pag, tp, agbp);

	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error0;

	/*
	 * Look for the entry describing this inode.
	 */
	if ((error = xfs_inobt_lookup(cur, agino, XFS_LOOKUP_LE, &i))) {
		xfs_warn(mp, "%s: xfs_inobt_lookup() returned error %d.",
			__func__, error);
		goto error0;
	}
	if (XFS_IS_CORRUPT(mp, i != 1)) {
		pr_warn_ratelimited("mxfs: P-DIFREE-CORRUPT site=inobt-lookup-LE agno=%u agino=%u i=%d — no inobt record covers this agino\n",
			(unsigned)pag_agno(pag), (unsigned)agino, i);
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error0;
	}
	error = xfs_inobt_get_rec(cur, &rec, &i);
	if (error) {
		xfs_warn(mp, "%s: xfs_inobt_get_rec() returned error %d.",
			__func__, error);
		goto error0;
	}
	if (XFS_IS_CORRUPT(mp, i != 1)) {
		pr_warn_ratelimited("mxfs: P-DIFREE-CORRUPT site=inobt-getrec agno=%u agino=%u i=%d\n",
			(unsigned)pag_agno(pag), (unsigned)agino, i);
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error0;
	}
	/*
	 * Get the offset in the inode chunk.
	 */
	off = agino - rec.ir_startino;
	ASSERT(off >= 0 && off < XFS_INODES_PER_CHUNK);
	/*
	 * P-DIFREE-DBL (RULE-4 probe): in multi-node mode, detect the inobt
	 * double-free (the inode being freed is ALREADY marked free in this
	 * node's inobt record).  Upstream this is only an ASSERT (no-op in
	 * production) and then blindly ++freecount, corrupting agi_freecount
	 * and tripping EFSCORRUPTED in finobt cross-check / check_agi_freecount.
	 * Log it so we can confirm this is the xfs_inactive_ifree -117 root.
	 */
	if (rec.ir_free & XFS_INOBT_MASK(off)) {
		struct xfs_agi *dbg_agi = agbp->b_addr;
		pr_warn_ratelimited(
			"mxfs: P-DIFREE-DBL agno=%u agino=%u startino=%u off=%d ir_free=0x%llx freecount=%d agi_freecount=%u multinode=%d — inode ALREADY free in inobt (double-free)\n",
			(unsigned)pag_agno(pag), (unsigned)agino,
			(unsigned)rec.ir_startino, off,
			(unsigned long long)rec.ir_free, (int)rec.ir_freecount,
			(unsigned)be32_to_cpu(dbg_agi->agi_freecount),
			(int)(mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)));
		/*
		 * ccloop-4dd7 sess3 (round-5 ino 134 autopsy): in multi-node
		 * mode this is not a can't-happen — it is the SECOND
		 * inactivation of an inode whose unlink+free a peer already
		 * completed.  Our in-core mirror adopted nlink=0 from disk
		 * (P9-NLEDGE from_disk, rmcnt=0, no local unlink) and VFS
		 * inactivated it again on last iput.  This inobt read is
		 * coherent (AG DLM held; the peer destaged AG-meta before its
		 * handoff — invariant #1), so the set bit is authoritative:
		 * everything this ifree would do is already done.  Proceeding
		 * desynced agi_freecount from the mask popcount and then shut
		 * the FS down at the (coherently empty) AGI bucket in
		 * xfs_iunlink_remove (P71 → -EFSCORRUPTED with the tx dirty).
		 * Nothing in this transaction is modified yet — only lookups
		 * have run — so abort with -ESTALE (unused elsewhere in the
		 * ifree graph) for xfs_inactive_ifree to convert into a clean
		 * adopted-peer-free skip.
		 */
		if (mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
			error = -ESTALE;
			goto error0;
		}
	}
	ASSERT(!(rec.ir_free & XFS_INOBT_MASK(off)));
	/*
	 * Mark the inode free & increment the count.
	 */
	{
		uint64_t p150_pre = rec.ir_free;
		int p150_fc = rec.ir_freecount;

		rec.ir_free |= XFS_INOBT_MASK(off);
		rec.ir_freecount++;
		mxfs_p150_inorec(cur, "FREE-IBT", off, p150_pre, p150_fc,
				 &rec);
	}

	/*
	 * When an inode chunk is free, it becomes eligible for removal. Don't
	 * remove the chunk if the block size is large enough for multiple inode
	 * chunks (that might not be free).
	 *
	 * sess54 (ccloop) — INODE-CHUNK-KEEP in multi-node mode (ikeep
	 * semantics).  PROVEN root of the posix_semantics_multi16 shutdown:
	 * rm-rf frees a fully-free inode chunk -> xfs_ifree_cluster returns
	 * the inode-cluster blocks to AG free space (bnobt) -> a peer with a
	 * stale bnobt view reallocates one of those blocks as a dir-data
	 * block while it actually backs a (re-allocated) live inode cluster
	 * -> dir data is written over the inode cluster -> the cluster fails
	 * its verifier on the next read (imap_to_bp rc=-5 EIO) / dialloc sees
	 * inobt incoherent (-117) -> forced FS shutdown -> every test barrier
	 * hangs 120s -> criterion >600s timeout.  Keeping the chunk means its
	 * blocks never re-enter the AG free pool, so dir data can never alias
	 * an inode cluster; the freed inodes are simply marked free in the
	 * inobt/finobt and reused in place (normal inode-number reuse, already
	 * coherency-handled).  Single-node keeps upstream behaviour (frees the
	 * chunk) so no space is leaked when there is no cross-node aliasing
	 * risk.
	 */
	if (rec.ir_free == XFS_INOBT_ALL_FREE &&
	    mp->m_sb.sb_inopblock <= XFS_INODES_PER_CHUNK &&
	    !(mp->m_mxfs_dlm &&
	      !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))) {
		/*
		 * sess103 RULE-4 DISCRIMINATOR (P103-CHUNKFREE): a fully-free
		 * inode chunk is being deleted and its blocks deferred-freed.
		 * If a peer concurrently drove the same chunk all-free (stale
		 * in-core inobt rec), both nodes free the same chunk blocks =>
		 * bnobt double-free (xfs_alloc.c:2244).  Log the chunk's start
		 * block + len so it can be correlated against the FREE-AG-EXTENT
		 * -FAIL bno at the shutdown.  Multi-node only.
		 */
		if (pag_mount(pag)->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(pag_mount(pag)->m_mxfs_dlm)) {
			struct xfs_agi *dbg_agi = agbp->b_addr;

			pr_warn_ratelimited(
				"mxfs: P103-CHUNKFREE agno=%u chunk_agbno=%u ialloc_blks=%u startino=%u freecount=%d agi_freecount=%u pagi_freecount=%u agi_count=%u holemask=0x%x\n",
				(unsigned)pag_agno(pag),
				(unsigned)XFS_AGINO_TO_AGBNO(mp, rec.ir_startino),
				(unsigned)M_IGEO(mp)->ialloc_blks,
				(unsigned)rec.ir_startino,
				(int)rec.ir_freecount,
				(unsigned)be32_to_cpu(dbg_agi->agi_freecount),
				(unsigned)pag->pagi_freecount,
				(unsigned)be32_to_cpu(dbg_agi->agi_count),
				(unsigned)rec.ir_holemask);
		}
		xic->deleted = true;
		xic->first_ino = xfs_agino_to_ino(pag, rec.ir_startino);
		xic->alloc = xfs_inobt_irec_to_allocmask(&rec);

		/*
		 * Remove the inode cluster from the AGI B+Tree, adjust the
		 * AGI and Superblock inode counts, and mark the disk space
		 * to be freed when the transaction is committed.
		 */
		ilen = rec.ir_freecount;
		be32_add_cpu(&agi->agi_count, -ilen);
		be32_add_cpu(&agi->agi_freecount, -(ilen - 1));
		xfs_ialloc_log_agi(tp, agbp, XFS_AGI_COUNT | XFS_AGI_FREECOUNT);
		pag->pagi_freecount -= ilen - 1;
		pag->pagi_count -= ilen;
		xfs_trans_mod_sb(tp, XFS_TRANS_SB_ICOUNT, -ilen);
		xfs_trans_mod_sb(tp, XFS_TRANS_SB_IFREE, -(ilen - 1));

		if ((error = xfs_btree_delete(cur, &i))) {
			xfs_warn(mp, "%s: xfs_btree_delete returned error %d.",
				__func__, error);
			goto error0;
		}

		error = xfs_difree_inode_chunk(tp, pag, &rec);
		if (error)
			goto error0;
	} else {
		xic->deleted = false;

		error = xfs_inobt_update(cur, &rec);
		if (error) {
			xfs_warn(mp, "%s: xfs_inobt_update returned error %d.",
				__func__, error);
			goto error0;
		}

		/*
		 * Change the inode free counts and log the ag/sb changes.
		 */
		be32_add_cpu(&agi->agi_freecount, 1);
		xfs_ialloc_log_agi(tp, agbp, XFS_AGI_FREECOUNT);
		pag->pagi_freecount++;
		xfs_trans_mod_sb(tp, XFS_TRANS_SB_IFREE, 1);
	}

	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error0;

	*orec = rec;
	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	return 0;

error0:
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}

/*
 * Free an inode in the free inode btree.
 */
STATIC int
xfs_difree_finobt(
	struct xfs_perag		*pag,
	struct xfs_trans		*tp,
	struct xfs_buf			*agbp,
	xfs_agino_t			agino,
	struct xfs_inobt_rec_incore	*ibtrec) /* inobt record */
{
	struct xfs_mount		*mp = pag_mount(pag);
	struct xfs_btree_cur		*cur;
	struct xfs_inobt_rec_incore	rec;
	int				offset = agino - ibtrec->ir_startino;
	int				error;
	int				i;

	cur = xfs_finobt_init_cursor(pag, tp, agbp);

	error = xfs_inobt_lookup(cur, ibtrec->ir_startino, XFS_LOOKUP_EQ, &i);
	if (error)
		goto error;
	if (i == 0) {
		/*
		 * If the record does not exist in the finobt, we must have just
		 * freed an inode in a previously fully allocated chunk. If not,
		 * something is out of sync.
		 */
		if (XFS_IS_CORRUPT(mp, ibtrec->ir_freecount != 1)) {
			pr_warn_ratelimited("mxfs: P-DIFREE-CORRUPT site=finobt-norec agno=%u agino=%u ibt_freecount=%d — finobt missing rec but inobt freecount!=1\n",
				(unsigned)pag_agno(pag), (unsigned)agino, (int)ibtrec->ir_freecount);
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error;
		}

		error = xfs_inobt_insert_rec(cur, ibtrec->ir_holemask,
					     ibtrec->ir_count,
					     ibtrec->ir_freecount,
					     ibtrec->ir_free, &i);
		if (error)
			goto error;
		ASSERT(i == 1);

		goto out;
	}

	/*
	 * Read and update the existing record. We could just copy the ibtrec
	 * across here, but that would defeat the purpose of having redundant
	 * metadata. By making the modifications independently, we can catch
	 * corruptions that we wouldn't see if we just copied from one record
	 * to another.
	 */
	error = xfs_inobt_get_rec(cur, &rec, &i);
	if (error)
		goto error;
	if (XFS_IS_CORRUPT(mp, i != 1)) {
		/* sess46 (D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372): the last
		 * un-probed -EFSCORRUPTED exit under xfs_difree — the one
		 * -117 shutdown observed printed NO P-DIFREE line, so every
		 * exit must self-name for the next occurrence. */
		pr_warn_ratelimited("mxfs: P-DIFREE-CORRUPT site=finobt-getrec agno=%u agino=%u i=%d\n",
			(unsigned)pag_agno(pag), (unsigned)agino, i);
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error;
	}

	{
		uint64_t p150_pre = rec.ir_free;
		int p150_fc = rec.ir_freecount;

		rec.ir_free |= XFS_INOBT_MASK(offset);
		rec.ir_freecount++;
		mxfs_p150_inorec(cur, "FREE-FIN", offset, p150_pre, p150_fc,
				 &rec);
	}

	if (XFS_IS_CORRUPT(mp,
			   rec.ir_free != ibtrec->ir_free ||
			   rec.ir_freecount != ibtrec->ir_freecount)) {
		pr_warn_ratelimited("mxfs: P-DIFREE-CORRUPT site=finobt-mismatch agno=%u agino=%u fin_free=0x%llx ibt_free=0x%llx fin_fc=%d ibt_fc=%d\n",
			(unsigned)pag_agno(pag), (unsigned)agino,
			(unsigned long long)rec.ir_free, (unsigned long long)ibtrec->ir_free,
			(int)rec.ir_freecount, (int)ibtrec->ir_freecount);
		xfs_btree_mark_sick(cur);
		error = -EFSCORRUPTED;
		goto error;
	}

	/*
	 * The content of inobt records should always match between the inobt
	 * and finobt. The lifecycle of records in the finobt is different from
	 * the inobt in that the finobt only tracks records with at least one
	 * free inode. Hence, if all of the inodes are free and we aren't
	 * keeping inode chunks permanently on disk, remove the record.
	 * Otherwise, update the record with the new information.
	 *
	 * Note that we currently can't free chunks when the block size is large
	 * enough for multiple chunks. Leave the finobt record to remain in sync
	 * with the inobt.
	 *
	 * sess54 (ccloop) — keep the finobt record in sync with the
	 * INODE-CHUNK-KEEP gate in xfs_difree_inobt: in multi-node mode the
	 * chunk is never deleted from the inobt, so the all-free finobt record
	 * must be retained (updated) rather than deleted.
	 */
	if (rec.ir_free == XFS_INOBT_ALL_FREE &&
	    mp->m_sb.sb_inopblock <= XFS_INODES_PER_CHUNK &&
	    !(mp->m_mxfs_dlm &&
	      !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))) {
		error = xfs_btree_delete(cur, &i);
		if (error)
			goto error;
		ASSERT(i == 1);
	} else {
		error = xfs_inobt_update(cur, &rec);
		if (error)
			goto error;
	}

out:
	error = xfs_check_agi_freecount(cur);
	if (error)
		goto error;

	xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
	return 0;

error:
	xfs_btree_del_cursor(cur, XFS_BTREE_ERROR);
	return error;
}

/*
 * Free disk inode.  Carefully avoids touching the incore inode, all
 * manipulations incore are the caller's responsibility.
 * The on-disk inode is not changed by this operation, only the
 * btree (free inode mask) is changed.
 */
int
xfs_difree(
	struct xfs_trans	*tp,
	struct xfs_perag	*pag,
	xfs_ino_t		inode,
	struct xfs_icluster	*xic)
{
	/* REFERENCED */
	xfs_agblock_t		agbno;	/* block number containing inode */
	struct xfs_buf		*agbp;	/* buffer for allocation group header */
	xfs_agino_t		agino;	/* allocation group inode number */
	int			error;	/* error return value */
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_inobt_rec_incore rec;/* btree record */

	/*
	 * Break up inode number into its components.
	 */
	if (pag_agno(pag) != XFS_INO_TO_AGNO(mp, inode)) {
		xfs_warn(mp, "%s: agno != pag_agno(pag) (%d != %d).",
			__func__, XFS_INO_TO_AGNO(mp, inode), pag_agno(pag));
		ASSERT(0);
		return -EINVAL;
	}
	agino = XFS_INO_TO_AGINO(mp, inode);
	if (inode != xfs_agino_to_ino(pag, agino))  {
		xfs_warn(mp, "%s: inode != xfs_agino_to_ino() (%llu != %llu).",
			__func__, (unsigned long long)inode,
			(unsigned long long)xfs_agino_to_ino(pag, agino));
		ASSERT(0);
		return -EINVAL;
	}
	agbno = XFS_AGINO_TO_AGBNO(mp, agino);
	if (agbno >= xfs_ag_block_count(mp, pag_agno(pag))) {
		xfs_warn(mp, "%s: agbno >= xfs_ag_block_count (%d >= %d).",
			__func__, agbno, xfs_ag_block_count(mp, pag_agno(pag)));
		ASSERT(0);
		return -EINVAL;
	}
	/*
	 * Get the allocation group header.
	 */
	error = xfs_ialloc_read_agi(pag, tp, 0, &agbp);
	if (error) {
		xfs_warn(mp, "%s: xfs_ialloc_read_agi() returned error %d.",
			__func__, error);
		return error;
	}

	/*
	 * Fix up the inode allocation btree.
	 */
	error = xfs_difree_inobt(pag, tp, agbp, agino, xic, &rec);
	if (error)
		goto error0;

	/*
	 * Fix up the free inode btree.
	 */
	if (xfs_has_finobt(mp)) {
		error = xfs_difree_finobt(pag, tp, agbp, agino, &rec);
		if (error)
			goto error0;
	}

	return 0;

error0:
	return error;
}

STATIC int
xfs_imap_lookup(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	xfs_agino_t		agino,
	xfs_agblock_t		agbno,
	xfs_agblock_t		*chunk_agbno,
	xfs_agblock_t		*offset_agbno,
	int			flags)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_inobt_rec_incore rec;
	struct xfs_btree_cur	*cur;
	struct xfs_buf		*agbp;
	int			error;
	int			i;

	error = xfs_ialloc_read_agi(pag, tp, 0, &agbp);
	if (error) {
		xfs_alert(mp,
			"%s: xfs_ialloc_read_agi() returned error %d, agno %d",
			__func__, error, pag_agno(pag));
		return error;
	}

	/*
	 * Lookup the inode record for the given agino. If the record cannot be
	 * found, then it's an invalid inode number and we should abort. Once
	 * we have a record, we need to ensure it contains the inode number
	 * we are looking up.
	 */
	cur = xfs_inobt_init_cursor(pag, tp, agbp);
	error = xfs_inobt_lookup(cur, agino, XFS_LOOKUP_LE, &i);
	if (!error) {
		if (i)
			error = xfs_inobt_get_rec(cur, &rec, &i);
		if (!error && i == 0)
			error = -EINVAL;
	}

	xfs_trans_brelse(tp, agbp);
	xfs_btree_del_cursor(cur, error);
	if (error)
		return error;

	/* check that the returned record contains the required inode */
	if (rec.ir_startino > agino ||
	    rec.ir_startino + M_IGEO(mp)->ialloc_inos <= agino)
		return -EINVAL;

	/* for untrusted inodes check it is allocated first */
	if ((flags & XFS_IGET_UNTRUSTED) &&
	    (rec.ir_free & XFS_INOBT_MASK(agino - rec.ir_startino)))
		return -EINVAL;

	*chunk_agbno = XFS_AGINO_TO_AGBNO(mp, rec.ir_startino);
	*offset_agbno = agbno - *chunk_agbno;
	return 0;
}

/*
 * Return the location of the inode in imap, for mapping it into a buffer.
 */
int
xfs_imap(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	xfs_ino_t		ino,	/* inode to locate */
	struct xfs_imap		*imap,	/* location map structure */
	uint			flags)	/* flags for inode btree lookup */
{
	struct xfs_mount	*mp = pag_mount(pag);
	xfs_agblock_t		agbno;	/* block number of inode in the alloc group */
	xfs_agino_t		agino;	/* inode number within alloc group */
	xfs_agblock_t		chunk_agbno;	/* first block in inode chunk */
	xfs_agblock_t		cluster_agbno;	/* first block in inode cluster */
	int			error;	/* error code */
	int			offset;	/* index of inode in its buffer */
	xfs_agblock_t		offset_agbno;	/* blks from chunk start to inode */

	ASSERT(ino != NULLFSINO);

	/*
	 * Split up the inode number into its parts.
	 */
	agino = XFS_INO_TO_AGINO(mp, ino);
	agbno = XFS_AGINO_TO_AGBNO(mp, agino);
	if (agbno >= xfs_ag_block_count(mp, pag_agno(pag)) ||
	    ino != xfs_agino_to_ino(pag, agino)) {
		error = -EINVAL;
#ifdef DEBUG
		/*
		 * Don't output diagnostic information for untrusted inodes
		 * as they can be invalid without implying corruption.
		 */
		if (flags & XFS_IGET_UNTRUSTED)
			return error;
		if (agbno >= xfs_ag_block_count(mp, pag_agno(pag))) {
			xfs_alert(mp,
		"%s: agbno (0x%llx) >= mp->m_sb.sb_agblocks (0x%lx)",
				__func__, (unsigned long long)agbno,
				(unsigned long)xfs_ag_block_count(mp,
							pag_agno(pag)));
		}
		if (ino != xfs_agino_to_ino(pag, agino)) {
			xfs_alert(mp,
		"%s: ino (0x%llx) != xfs_agino_to_ino() (0x%llx)",
				__func__, ino,
				xfs_agino_to_ino(pag, agino));
		}
		xfs_stack_trace();
#endif /* DEBUG */
		return error;
	}

	/*
	 * For bulkstat and handle lookups, we have an untrusted inode number
	 * that we have to verify is valid. We cannot do this just by reading
	 * the inode buffer as it may have been unlinked and removed leaving
	 * inodes in stale state on disk. Hence we have to do a btree lookup
	 * in all cases where an untrusted inode number is passed.
	 */
	if (flags & XFS_IGET_UNTRUSTED) {
		error = xfs_imap_lookup(pag, tp, agino, agbno,
					&chunk_agbno, &offset_agbno, flags);
		if (error)
			return error;
		goto out_map;
	}

	/*
	 * If the inode cluster size is the same as the blocksize or
	 * smaller we get to the buffer by simple arithmetics.
	 */
	if (M_IGEO(mp)->blocks_per_cluster == 1) {
		offset = XFS_INO_TO_OFFSET(mp, ino);
		ASSERT(offset < mp->m_sb.sb_inopblock);

		imap->im_blkno = xfs_agbno_to_daddr(pag, agbno);
		imap->im_len = XFS_FSB_TO_BB(mp, 1);
		imap->im_boffset = (unsigned short)(offset <<
							mp->m_sb.sb_inodelog);
		return 0;
	}

	/*
	 * If the inode chunks are aligned then use simple maths to
	 * find the location. Otherwise we have to do a btree
	 * lookup to find the location.
	 */
	if (M_IGEO(mp)->inoalign_mask) {
		offset_agbno = agbno & M_IGEO(mp)->inoalign_mask;
		chunk_agbno = agbno - offset_agbno;
	} else {
		error = xfs_imap_lookup(pag, tp, agino, agbno,
					&chunk_agbno, &offset_agbno, flags);
		if (error)
			return error;
	}

out_map:
	ASSERT(agbno >= chunk_agbno);
	cluster_agbno = chunk_agbno +
		((offset_agbno / M_IGEO(mp)->blocks_per_cluster) *
		 M_IGEO(mp)->blocks_per_cluster);
	offset = ((agbno - cluster_agbno) * mp->m_sb.sb_inopblock) +
		XFS_INO_TO_OFFSET(mp, ino);

	imap->im_blkno = xfs_agbno_to_daddr(pag, cluster_agbno);
	imap->im_len = XFS_FSB_TO_BB(mp, M_IGEO(mp)->blocks_per_cluster);
	imap->im_boffset = (unsigned short)(offset << mp->m_sb.sb_inodelog);

	/*
	 * If the inode number maps to a block outside the bounds
	 * of the file system then return NULL rather than calling
	 * read_buf and panicing when we get an error from the
	 * driver.
	 */
	if ((imap->im_blkno + imap->im_len) >
	    XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks)) {
		xfs_alert(mp,
	"%s: (im_blkno (0x%llx) + im_len (0x%llx)) > sb_dblocks (0x%llx)",
			__func__, (unsigned long long) imap->im_blkno,
			(unsigned long long) imap->im_len,
			XFS_FSB_TO_BB(mp, mp->m_sb.sb_dblocks));
		return -EINVAL;
	}
	return 0;
}

/*
 * Log specified fields for the ag hdr (inode section). The growth of the agi
 * structure over time requires that we interpret the buffer as two logical
 * regions delineated by the end of the unlinked list. This is due to the size
 * of the hash table and its location in the middle of the agi.
 *
 * For example, a request to log a field before agi_unlinked and a field after
 * agi_unlinked could cause us to log the entire hash table and use an excessive
 * amount of log space. To avoid this behavior, log the region up through
 * agi_unlinked in one call and the region after agi_unlinked through the end of
 * the structure in another.
 */
void
xfs_ialloc_log_agi(
	struct xfs_trans	*tp,
	struct xfs_buf		*bp,
	uint32_t		fields)
{
	int			first;		/* first byte number */
	int			last;		/* last byte number */
	static const short	offsets[] = {	/* field starting offsets */
					/* keep in sync with bit definitions */
		offsetof(xfs_agi_t, agi_magicnum),
		offsetof(xfs_agi_t, agi_versionnum),
		offsetof(xfs_agi_t, agi_seqno),
		offsetof(xfs_agi_t, agi_length),
		offsetof(xfs_agi_t, agi_count),
		offsetof(xfs_agi_t, agi_root),
		offsetof(xfs_agi_t, agi_level),
		offsetof(xfs_agi_t, agi_freecount),
		offsetof(xfs_agi_t, agi_newino),
		offsetof(xfs_agi_t, agi_dirino),
		offsetof(xfs_agi_t, agi_unlinked),
		offsetof(xfs_agi_t, agi_free_root),
		offsetof(xfs_agi_t, agi_free_level),
		offsetof(xfs_agi_t, agi_iblocks),
		sizeof(xfs_agi_t)
	};
#ifdef DEBUG
	struct xfs_agi		*agi = bp->b_addr;

	ASSERT(agi->agi_magicnum == cpu_to_be32(XFS_AGI_MAGIC));
#endif

	/*
	 * Compute byte offsets for the first and last fields in the first
	 * region and log the agi buffer. This only logs up through
	 * agi_unlinked.
	 */
	if (fields & XFS_AGI_ALL_BITS_R1) {
		xfs_btree_offsets(fields, offsets, XFS_AGI_NUM_BITS_R1,
				  &first, &last);
		xfs_trans_log_buf(tp, bp, first, last);
	}

	/*
	 * Mask off the bits in the first region and calculate the first and
	 * last field offsets for any bits in the second region.
	 */
	fields &= ~XFS_AGI_ALL_BITS_R1;
	if (fields) {
		xfs_btree_offsets(fields, offsets, XFS_AGI_NUM_BITS_R2,
				  &first, &last);
		xfs_trans_log_buf(tp, bp, first, last);
	}
}

static xfs_failaddr_t
xfs_agi_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_agi		*agi = bp->b_addr;
	xfs_failaddr_t		fa;
	uint32_t		agi_seqno = be32_to_cpu(agi->agi_seqno);
	uint32_t		agi_length = be32_to_cpu(agi->agi_length);
	int			i;

	if (xfs_has_crc(mp)) {
		if (!uuid_equal(&agi->agi_uuid, &mp->m_sb.sb_meta_uuid))
			return __this_address;
		if (!xfs_log_check_lsn(mp, be64_to_cpu(agi->agi_lsn)))
			return __this_address;
	}

	/*
	 * Validate the magic number of the agi block.
	 */
	if (!xfs_verify_magic(bp, agi->agi_magicnum))
		return __this_address;
	if (!XFS_AGI_GOOD_VERSION(be32_to_cpu(agi->agi_versionnum)))
		return __this_address;

	fa = xfs_validate_ag_length(bp, agi_seqno, agi_length);
	if (fa)
		return fa;

	if (be32_to_cpu(agi->agi_level) < 1 ||
	    be32_to_cpu(agi->agi_level) > M_IGEO(mp)->inobt_maxlevels)
		return __this_address;

	if (xfs_has_finobt(mp) &&
	    (be32_to_cpu(agi->agi_free_level) < 1 ||
	     be32_to_cpu(agi->agi_free_level) > M_IGEO(mp)->inobt_maxlevels))
		return __this_address;

	for (i = 0; i < XFS_AGI_UNLINKED_BUCKETS; i++) {
		if (agi->agi_unlinked[i] == cpu_to_be32(NULLAGINO))
			continue;
		if (!xfs_verify_ino(mp, be32_to_cpu(agi->agi_unlinked[i])))
			return __this_address;
	}

	return NULL;
}

#ifdef __KERNEL__
/* sess30(ccloop) AGI-CRC diagnostic: 0=off. When 1, every AGI write logs its
 * stamped CRC + content fingerprint so a failing read (always logged) can be
 * cross-correlated to the write that produced the on-disk image. */
int mxfs_agi_crc_probe;
module_param_named(agi_crc_probe, mxfs_agi_crc_probe, int, 0644);

static void
mxfs_agi_probe_log(struct xfs_buf *bp, const char *tag)
{
	struct xfs_agi	*agi = bp->b_addr;
	__le32		*crcp = (__le32 *)((char *)bp->b_addr + XFS_AGI_CRC_OFF);
	uint32_t	fp;

	if (!bp->b_addr || bp->b_map_count != 1)
		return;
	fp = crc32c(~(uint32_t)0, bp->b_addr, BBTOB(bp->b_length));
	pr_warn("mxfs: P30-AGI-%s daddr=%lld stored_crc=0x%08x fp=0x%08x seqno=%u len=%u count=%u free=%u newino=0x%llx lsn=0x%llx comm=%s realns=%llu\n",
		tag, (long long)bp->b_maps[0].bm_bn,
		le32_to_cpu(*crcp), fp,
		be32_to_cpu(agi->agi_seqno), be32_to_cpu(agi->agi_length),
		be32_to_cpu(agi->agi_count), be32_to_cpu(agi->agi_freecount),
		(unsigned long long)be32_to_cpu(agi->agi_newino),
		(unsigned long long)be64_to_cpu(agi->agi_lsn),
		current->comm, (unsigned long long)ktime_get_real_ns());
}
#endif

static void
xfs_agi_read_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount *mp = bp->b_mount;
	xfs_failaddr_t	fa;

	if (xfs_has_crc(mp) &&
	    !xfs_buf_verify_cksum(bp, XFS_AGI_CRC_OFF)) {
#ifdef __KERNEL__
		/* sess30: AGI CRC read failure — the dir_reuse 8/tcp shutdown.
		 * Always log (rare) regardless of the probe param. */
		mxfs_agi_probe_log(bp, "RDFAIL");
#endif
		xfs_verifier_error(bp, -EFSBADCRC, __this_address);
	} else {
		fa = xfs_agi_verify(bp);
		if (fa || XFS_TEST_ERROR(mp, XFS_ERRTAG_IALLOC_READ_AGI))
			xfs_verifier_error(bp, -EFSCORRUPTED, fa);
	}
}

static void
xfs_agi_write_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_agi		*agi = bp->b_addr;
	xfs_failaddr_t		fa;

	fa = xfs_agi_verify(bp);
	if (fa) {
		xfs_verifier_error(bp, -EFSCORRUPTED, fa);
		return;
	}

	if (!xfs_has_crc(mp))
		return;

	if (bip)
		agi->agi_lsn = cpu_to_be64(bip->bli_item.li_lsn);
	xfs_buf_update_cksum(bp, XFS_AGI_CRC_OFF);
#ifdef __KERNEL__
	if (unlikely(mxfs_agi_crc_probe))
		mxfs_agi_probe_log(bp, "WRITE");
#endif
}

const struct xfs_buf_ops xfs_agi_buf_ops = {
	.name = "xfs_agi",
	.magic = { cpu_to_be32(XFS_AGI_MAGIC), cpu_to_be32(XFS_AGI_MAGIC) },
	.verify_read = xfs_agi_read_verify,
	.verify_write = xfs_agi_write_verify,
	.verify_struct = xfs_agi_verify,
};

/*
 * Read in the allocation group header (inode allocation section)
 */
int
xfs_read_agi(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**agibpp)
{
	struct xfs_mount	*mp = pag_mount(pag);
	int			error;

	trace_xfs_read_agi(pag);

	/* sess40: FUA-re-read a stale cached AGI (inobt roots / free-inode
	 * counts) after a peer modified this AG — anti inode double-alloc. */
	mxfs_ag_meta_invalidate_stale(mp, pag,
			XFS_AG_DADDR(mp, pag_agno(pag), XFS_AGI_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1));

	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, pag_agno(pag), XFS_AGI_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), flags, agibpp, &xfs_agi_buf_ops);
	if (xfs_metadata_is_sick(error))
		xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
	if (error)
		return error;
	/*
	 * sess125: tenure is stamped at MODIFY time now (mxfs_ag_meta_track),
	 * not at read time.  The iunlink INSERT that logs the AGI stamps it
	 * current and keeps the committed unlinked-list head tenure-guarded
	 * (preserves the sess123 AGI fix), while a read-only AGI stays
	 * prior-tenure so a stale cache-hit is refreshed via the gen-based
	 * cold-read rather than re-stamped this-node-authoritative.
	 */
	if (tp)
		xfs_trans_buf_set_type(tp, *agibpp, XFS_BLFT_AGI_BUF);

	xfs_buf_set_ref(*agibpp, XFS_AGI_REF);
	return 0;
}

/*
 * Read in the agi and initialise the per-ag data. If the caller supplies a
 * @agibpp, return the locked AGI buffer to them, otherwise release it.
 */
int
xfs_ialloc_read_agi(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	int			flags,
	struct xfs_buf		**agibpp)
{
	struct xfs_buf		*agibp;
	struct xfs_agi		*agi;
	int			error;

	trace_xfs_ialloc_read_agi(pag);

	error = xfs_read_agi(pag, tp,
			(flags & XFS_IALLOC_FLAG_TRYLOCK) ? XBF_TRYLOCK : 0,
			&agibp);
	if (error)
		return error;

	agi = agibp->b_addr;
	if (!xfs_perag_initialised_agi(pag)) {
		pag->pagi_freecount = be32_to_cpu(agi->agi_freecount);
		pag->pagi_count = be32_to_cpu(agi->agi_count);
		set_bit(XFS_AGSTATE_AGI_INIT, &pag->pag_opstate);
	}

#ifdef DEBUG
	/*
	 * It's possible for the AGF to be out of sync if the block device is
	 * silently dropping writes. This can happen in fstests with dmflakey
	 * enabled, which allows the buffer to be cleaned and reclaimed by
	 * memory pressure and then re-read from disk here. We will get a
	 * stale version of the AGF from disk, and nothing good can happen from
	 * here. Hence if we detect this situation, immediately shut down the
	 * filesystem.
	 *
	 * This can also happen if we are already in the middle of a forced
	 * shutdown, so don't bother checking if we are already shut down.
	 */
	if (!xfs_is_shutdown(pag_mount(pag))) {
		bool	ok = true;

		ok &= pag->pagi_freecount == be32_to_cpu(agi->agi_freecount);
		ok &= pag->pagi_count == be32_to_cpu(agi->agi_count);

		if (XFS_IS_CORRUPT(pag_mount(pag), !ok)) {
			xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
			xfs_trans_brelse(tp, agibp);
			xfs_force_shutdown(pag_mount(pag),
					SHUTDOWN_CORRUPT_ONDISK);
			return -EFSCORRUPTED;
		}
	}
#endif /* DEBUG */

	if (agibpp)
		*agibpp = agibp;
	else
		xfs_trans_brelse(tp, agibp);
	return 0;
}

/* How many inodes are backed by inode clusters ondisk? */
STATIC int
xfs_ialloc_count_ondisk(
	struct xfs_btree_cur		*cur,
	xfs_agino_t			low,
	xfs_agino_t			high,
	unsigned int			*allocated)
{
	struct xfs_inobt_rec_incore	irec;
	unsigned int			ret = 0;
	int				has_record;
	int				error;

	error = xfs_inobt_lookup(cur, low, XFS_LOOKUP_LE, &has_record);
	if (error)
		return error;

	while (has_record) {
		unsigned int		i, hole_idx;

		error = xfs_inobt_get_rec(cur, &irec, &has_record);
		if (error)
			return error;
		if (irec.ir_startino > high)
			break;

		for (i = 0; i < XFS_INODES_PER_CHUNK; i++) {
			if (irec.ir_startino + i < low)
				continue;
			if (irec.ir_startino + i > high)
				break;

			hole_idx = i / XFS_INODES_PER_HOLEMASK_BIT;
			if (!(irec.ir_holemask & (1U << hole_idx)))
				ret++;
		}

		error = xfs_btree_increment(cur, 0, &has_record);
		if (error)
			return error;
	}

	*allocated = ret;
	return 0;
}

/* Is there an inode record covering a given extent? */
int
xfs_ialloc_has_inodes_at_extent(
	struct xfs_btree_cur	*cur,
	xfs_agblock_t		bno,
	xfs_extlen_t		len,
	enum xbtree_recpacking	*outcome)
{
	xfs_agino_t		agino;
	xfs_agino_t		last_agino;
	unsigned int		allocated;
	int			error;

	agino = XFS_AGB_TO_AGINO(cur->bc_mp, bno);
	last_agino = XFS_AGB_TO_AGINO(cur->bc_mp, bno + len) - 1;

	error = xfs_ialloc_count_ondisk(cur, agino, last_agino, &allocated);
	if (error)
		return error;

	if (allocated == 0)
		*outcome = XBTREE_RECPACKING_EMPTY;
	else if (allocated == last_agino - agino + 1)
		*outcome = XBTREE_RECPACKING_FULL;
	else
		*outcome = XBTREE_RECPACKING_SPARSE;
	return 0;
}

struct xfs_ialloc_count_inodes {
	xfs_agino_t			count;
	xfs_agino_t			freecount;
};

/* Record inode counts across all inobt records. */
STATIC int
xfs_ialloc_count_inodes_rec(
	struct xfs_btree_cur		*cur,
	const union xfs_btree_rec	*rec,
	void				*priv)
{
	struct xfs_inobt_rec_incore	irec;
	struct xfs_ialloc_count_inodes	*ci = priv;
	xfs_failaddr_t			fa;

	xfs_inobt_btrec_to_irec(cur->bc_mp, rec, &irec);
	fa = xfs_inobt_check_irec(to_perag(cur->bc_group), &irec);
	if (fa)
		return xfs_inobt_complain_bad_rec(cur, fa, &irec);

	ci->count += irec.ir_count;
	ci->freecount += irec.ir_freecount;

	return 0;
}

/* Count allocated and free inodes under an inobt. */
int
xfs_ialloc_count_inodes(
	struct xfs_btree_cur		*cur,
	xfs_agino_t			*count,
	xfs_agino_t			*freecount)
{
	struct xfs_ialloc_count_inodes	ci = {0};
	int				error;

	ASSERT(xfs_btree_is_ino(cur->bc_ops));
	error = xfs_btree_query_all(cur, xfs_ialloc_count_inodes_rec, &ci);
	if (error)
		return error;

	*count = ci.count;
	*freecount = ci.freecount;
	return 0;
}

/*
 * Initialize inode-related geometry information.
 *
 * Compute the inode btree min and max levels and set maxicount.
 *
 * Set the inode cluster size.  This may still be overridden by the file
 * system block size if it is larger than the chosen cluster size.
 *
 * For v5 filesystems, scale the cluster size with the inode size to keep a
 * constant ratio of inode per cluster buffer, but only if mkfs has set the
 * inode alignment value appropriately for larger cluster sizes.
 *
 * Then compute the inode cluster alignment information.
 */
void
xfs_ialloc_setup_geometry(
	struct xfs_mount	*mp)
{
	struct xfs_sb		*sbp = &mp->m_sb;
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	uint64_t		icount;
	uint			inodes;

	igeo->new_diflags2 = 0;
	if (xfs_has_bigtime(mp))
		igeo->new_diflags2 |= XFS_DIFLAG2_BIGTIME;
	if (xfs_has_large_extent_counts(mp))
		igeo->new_diflags2 |= XFS_DIFLAG2_NREXT64;

	/* Compute inode btree geometry. */
	igeo->agino_log = sbp->sb_inopblog + sbp->sb_agblklog;
	igeo->inobt_mxr[0] = xfs_inobt_maxrecs(mp, sbp->sb_blocksize, true);
	igeo->inobt_mxr[1] = xfs_inobt_maxrecs(mp, sbp->sb_blocksize, false);
	igeo->inobt_mnr[0] = igeo->inobt_mxr[0] / 2;
	igeo->inobt_mnr[1] = igeo->inobt_mxr[1] / 2;

	igeo->ialloc_inos = max_t(uint16_t, XFS_INODES_PER_CHUNK,
			sbp->sb_inopblock);
	igeo->ialloc_blks = igeo->ialloc_inos >> sbp->sb_inopblog;

	if (sbp->sb_spino_align)
		igeo->ialloc_min_blks = sbp->sb_spino_align;
	else
		igeo->ialloc_min_blks = igeo->ialloc_blks;

	/* Compute and fill in value of m_ino_geo.inobt_maxlevels. */
	inodes = (1LL << XFS_INO_AGINO_BITS(mp)) >> XFS_INODES_PER_CHUNK_LOG;
	igeo->inobt_maxlevels = xfs_btree_compute_maxlevels(igeo->inobt_mnr,
			inodes);
	ASSERT(igeo->inobt_maxlevels <= xfs_iallocbt_maxlevels_ondisk());

	/*
	 * Set the maximum inode count for this filesystem, being careful not
	 * to use obviously garbage sb_inopblog/sb_inopblock values.  Regular
	 * users should never get here due to failing sb verification, but
	 * certain users (xfs_db) need to be usable even with corrupt metadata.
	 */
	if (sbp->sb_imax_pct && igeo->ialloc_blks) {
		/*
		 * Make sure the maximum inode count is a multiple
		 * of the units we allocate inodes in.
		 */
		icount = sbp->sb_dblocks * sbp->sb_imax_pct;
		do_div(icount, 100);
		do_div(icount, igeo->ialloc_blks);
		igeo->maxicount = XFS_FSB_TO_INO(mp,
				icount * igeo->ialloc_blks);
	} else {
		igeo->maxicount = 0;
	}

	/*
	 * Compute the desired size of an inode cluster buffer size, which
	 * starts at 8K and (on v5 filesystems) scales up with larger inode
	 * sizes.
	 *
	 * Preserve the desired inode cluster size because the sparse inodes
	 * feature uses that desired size (not the actual size) to compute the
	 * sparse inode alignment.  The mount code validates this value, so we
	 * cannot change the behavior.
	 */
	igeo->inode_cluster_size_raw = XFS_INODE_BIG_CLUSTER_SIZE;
	if (xfs_has_v3inodes(mp)) {
		int	new_size = igeo->inode_cluster_size_raw;

		new_size *= mp->m_sb.sb_inodesize / XFS_DINODE_MIN_SIZE;
		if (mp->m_sb.sb_inoalignmt >= XFS_B_TO_FSBT(mp, new_size))
			igeo->inode_cluster_size_raw = new_size;
	}

	/* Calculate inode cluster ratios. */
	if (igeo->inode_cluster_size_raw > mp->m_sb.sb_blocksize)
		igeo->blocks_per_cluster = XFS_B_TO_FSBT(mp,
				igeo->inode_cluster_size_raw);
	else
		igeo->blocks_per_cluster = 1;
	igeo->inode_cluster_size = XFS_FSB_TO_B(mp, igeo->blocks_per_cluster);
	igeo->inodes_per_cluster = XFS_FSB_TO_INO(mp, igeo->blocks_per_cluster);

	/* Calculate inode cluster alignment. */
	if (xfs_has_align(mp) &&
	    mp->m_sb.sb_inoalignmt >= igeo->blocks_per_cluster)
		igeo->cluster_align = mp->m_sb.sb_inoalignmt;
	else
		igeo->cluster_align = 1;
	igeo->inoalign_mask = igeo->cluster_align - 1;
	igeo->cluster_align_inodes = XFS_FSB_TO_INO(mp, igeo->cluster_align);

	/*
	 * If we are using stripe alignment, check whether
	 * the stripe unit is a multiple of the inode alignment
	 */
	if (mp->m_dalign && igeo->inoalign_mask &&
	    !(mp->m_dalign & igeo->inoalign_mask))
		igeo->ialloc_align = mp->m_dalign;
	else
		igeo->ialloc_align = 0;

	if (mp->m_sb.sb_blocksize > PAGE_SIZE)
		igeo->min_folio_order = mp->m_sb.sb_blocklog - PAGE_SHIFT;
	else
		igeo->min_folio_order = 0;
}

/* Compute the location of the root directory inode that is laid out by mkfs. */
xfs_ino_t
xfs_ialloc_calc_rootino(
	struct xfs_mount	*mp,
	int			sunit)
{
	struct xfs_ino_geometry	*igeo = M_IGEO(mp);
	xfs_agblock_t		first_bno;

	/*
	 * Pre-calculate the geometry of AG 0.  We know what it looks like
	 * because libxfs knows how to create allocation groups now.
	 *
	 * first_bno is the first block in which mkfs could possibly have
	 * allocated the root directory inode, once we factor in the metadata
	 * that mkfs formats before it.  Namely, the four AG headers...
	 */
	first_bno = howmany(4 * mp->m_sb.sb_sectsize, mp->m_sb.sb_blocksize);

	/* ...the two free space btree roots... */
	first_bno += 2;

	/* ...the inode btree root... */
	first_bno += 1;

	/* ...the initial AGFL... */
	first_bno += xfs_alloc_min_freelist(mp, NULL);

	/* ...the free inode btree root... */
	if (xfs_has_finobt(mp))
		first_bno++;

	/* ...the reverse mapping btree root... */
	if (xfs_has_rmapbt(mp))
		first_bno++;

	/* ...the reference count btree... */
	if (xfs_has_reflink(mp))
		first_bno++;

	/*
	 * ...and the log, if it is allocated in the first allocation group.
	 *
	 * This can happen with filesystems that only have a single
	 * allocation group, or very odd geometries created by old mkfs
	 * versions on very small filesystems.
	 */
	if (xfs_ag_contains_log(mp, 0))
		 first_bno += mp->m_sb.sb_logblocks;

	/*
	 * Now round first_bno up to whatever allocation alignment is given
	 * by the filesystem or was passed in.
	 */
	if (xfs_has_dalign(mp) && igeo->ialloc_align > 0)
		first_bno = roundup(first_bno, sunit);
	else if (xfs_has_align(mp) &&
			mp->m_sb.sb_inoalignmt > 1)
		first_bno = roundup(first_bno, mp->m_sb.sb_inoalignmt);

	return XFS_AGINO_TO_INO(mp, 0, XFS_AGB_TO_AGINO(mp, first_bno));
}

/*
 * Ensure there are not sparse inode clusters that cross the new EOAG.
 *
 * This is a no-op for non-spinode filesystems since clusters are always fully
 * allocated and checking the bnobt suffices.  However, a spinode filesystem
 * could have a record where the upper inodes are free blocks.  If those blocks
 * were removed from the filesystem, the inode record would extend beyond EOAG,
 * which will be flagged as corruption.
 */
int
xfs_ialloc_check_shrink(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct xfs_buf		*agibp,
	xfs_agblock_t		new_length)
{
	struct xfs_inobt_rec_incore rec;
	struct xfs_btree_cur	*cur;
	xfs_agino_t		agino;
	int			has;
	int			error;

	if (!xfs_has_sparseinodes(pag_mount(pag)))
		return 0;

	cur = xfs_inobt_init_cursor(pag, tp, agibp);

	/* Look up the inobt record that would correspond to the new EOFS. */
	agino = XFS_AGB_TO_AGINO(pag_mount(pag), new_length);
	error = xfs_inobt_lookup(cur, agino, XFS_LOOKUP_LE, &has);
	if (error || !has)
		goto out;

	error = xfs_inobt_get_rec(cur, &rec, &has);
	if (error)
		goto out;

	if (!has) {
		xfs_ag_mark_sick(pag, XFS_SICK_AG_INOBT);
		error = -EFSCORRUPTED;
		goto out;
	}

	/* If the record covers inodes that would be beyond EOFS, bail out. */
	if (rec.ir_startino + XFS_INODES_PER_CHUNK > agino) {
		error = -ENOSPC;
		goto out;
	}
out:
	xfs_btree_del_cursor(cur, error);
	return error;
}
