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

#ifdef __KERNEL__
/* P-AGIFC-MOD ledger (defined below, after mxfs_agifc_audit). */
static void mxfs_agifc_mod(struct xfs_perag *pag, struct xfs_buf *agbp,
			   const char *site, int delta);
#endif

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
 * 513B: @mxfs_foreign_recovery — the recovery caller (icreate item
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
	struct xfs_icreate_item	*icp = NULL;
	/*
	 * (design-consult ruling, D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES):
	 * on an MXFS mount every cluster of a new chunk is durably initialised
	 * on the platter by a raw FUA write BEFORE the carve transaction
	 * commits, and the ICREATE record is stamped SYNCINIT so a replayer
	 * treats the init as already applied (verify-and-skip, never a blind
	 * re-init over an inode a peer may have modified since).  This is an
	 * ENFORCED invariant: a FUA failure fails the carve (the transaction
	 * is already dirty from the extent allocation, so the cancel shuts
	 * the mount down — fail closed; the record must never be logged
	 * without the proof).  Single-node MXFS mounts keep it too: the
	 * replayer's mode cannot be assumed to equal the writer's.
	 */
	bool			syncinit = mp->m_mxfs_dlm && xfs_has_v3inodes(mp);

	/*
	 * Loop over the new block(s), filling in the inodes.  For small block
	 * sizes, manipulate the inodes in buffers  which are multiples of the
	 * blocks size.
	 */
	nbufs = length / M_IGEO(mp)->blocks_per_cluster;

	/*
	 * INSTRUMENTED PROBE — the 2/tcp durable wedge is a
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
			mxfs_probe("mxfs: P45-INIT agno=%u agbno=%u daddr=%lld length=%u icount=%d nbufs=%d ipc=%d bpc=%d\n",
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
	/*
	 * (design-consult landing review, STOP-SHIP 1/7): the SYNCINIT proof
	 * must never be fail-open.  On an MXFS mount a carve whose chunk
	 * cannot be proven (no v3 inodes to CRC-stamp, or a length that is not
	 * a whole number of clusters so a cluster would go unwritten — the P45
	 * anomaly) fails HERE, before the ICREATE record is logged: a record
	 * without the proof is poison to every replayer.  The transaction is
	 * already dirty from the extent allocation, so the caller's cancel
	 * shuts the mount down — fail closed.
	 */
	if (tp && mp->m_mxfs_dlm &&
	    (!xfs_has_v3inodes(mp) || nbufs <= 0 ||
	     length != (xfs_agblock_t)nbufs * M_IGEO(mp)->blocks_per_cluster)) {
		xfs_alert(mp,
	"MXFS: P133-ICLUSTER-SYNCINIT-GEOMETRY agno=%u agbno=%u length=%u icount=%d nbufs=%d bpc=%d v3=%d — inode chunk cannot be durably initialised whole; failing the carve before any ICREATE record exists",
			  agno, agbno, length, icount, nbufs,
			  M_IGEO(mp)->blocks_per_cluster,
			  xfs_has_v3inodes(mp) ? 1 : 0);
		return -EFSCORRUPTED;
	}

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
			icp = xfs_icreate_log(tp, agno, agbno, icount,
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
		 * ALWAYS-ON double-alloc detector.  We are about to
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
			free->di_magic = cpu_to_be16(MXFS_DINODE_MAGIC);
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
			/*
			 * the sync FUA init is the SYNCINIT invariant
			 * (see the prologue) — every MXFS mount, single-node
			 * included, and its failure FAILS the carve.  It used
			 * to be multi-node-only and warn-and-continue.
			 */
			if (syncinit) {
				extern int mxfs_pal_scsi_write_fua_bdev(
					struct block_device *, uint64_t,
					const void *, uint32_t);
				extern int mxfs_pal_bio_write_fua_bdev(
					struct block_device *, uint64_t,
					const void *, uint32_t);
				static atomic_t p133_n = ATOMIC_INIT(0);
				uint32_t p133_len = BBTOB(fbuf->b_length);
				void *p133_mb = kmalloc(p133_len, GFP_NOFS);
				int p133_rc = -ENOMEM;

				if (p133_mb) {
					memcpy(p133_mb, fbuf->b_addr, p133_len);
					p133_rc = mxfs_pal_scsi_write_fua_bdev(
						fbuf->b_target->bt_bdev,
						(uint64_t)fbuf->b_maps[0].bm_bn +
						fbuf->b_target->bt_sector_offset,
						p133_mb, p133_len);
					/* non-SCSI device (loop): FUA bio */
					if (p133_rc == -EOPNOTSUPP)
						p133_rc = mxfs_pal_bio_write_fua_bdev(
							fbuf->b_target->bt_bdev,
							(uint64_t)fbuf->b_maps[0].bm_bn +
							fbuf->b_target->bt_sector_offset,
							p133_mb, p133_len);
					kfree(p133_mb);
				}
				if (atomic_inc_return(&p133_n) <= 20 || p133_rc)
					mxfs_probe("mxfs: P133-ICLUSTER-SYNCINIT agno=%u daddr=%lld len=%u rc=%d comm=%s\n",
						agno,
						(long long)xfs_buf_daddr(fbuf),
						fbuf->b_length, p133_rc,
						current->comm);
				if (p133_rc) {
					xfs_alert(mp,
	"MXFS: P133-ICLUSTER-SYNCINIT-FAIL agno=%u daddr=%lld rc=%d — the new inode chunk could not be durably initialised before commit; failing the carve (the ICREATE record must never be logged without the proof)",
						  agno,
						  (long long)xfs_buf_daddr(fbuf),
						  p133_rc);
					/* the phantom init image must not
					 * stay reusable in the cache */
					xfs_trans_binval(tp, fbuf);
					return p133_rc;
				}
				/*
				 * D-0948: PROVE THE INIT LANDED, DO NOT ASSUME IT.
				 *
				 * A create was shut down by reading a dir3 data
				 * block (XDD3, carrying that very block address in
				 * its own header) at the home of an inode chunk the
				 * allocator had just carved, on a filesystem whose
				 * free-space btrees chk_mxfs verified as entirely
				 * self-consistent — so the block genuinely belonged
				 * to the chunk and its content was the PREVIOUS
				 * owner's.  Two causes explain that and they have
				 * opposite fixes: this FUA write never reached the
				 * platter, or it did and something wrote the old
				 * image back over it afterwards.
				 *
				 * A write that returns success is not evidence that
				 * the bytes are there.  Read the home straight back
				 * and say what is actually at it.  This is the one
				 * moment where the two causes are still separable:
				 * inode magic here and dir magic later means someone
				 * overwrote us; dir magic here means the write did
				 * not land.  Unconditional and unbudgeted when it
				 * disagrees — a rate limit on the negative case is
				 * how this question stayed open (a budgeted probe
				 * plus a rolled-over ring buffer produced a count
				 * that supported the wrong answer).
				 */
				{
					uint16_t vmode = 0;
					uint32_t vgen = 0;
					bool vmagic = false;
					xfs_ino_t vino = XFS_AGINO_TO_INO(mp,
						agno, XFS_AGB_TO_AGINO(mp,
							agbno + (j * M_IGEO(mp)->blocks_per_cluster)));
					int vrc = mxfs_dbg_disk_di_read_coherent(
						mp, vino, &vmode, &vgen, &vmagic);

					if (vrc || !vmagic)
						xfs_alert(mp,
	"MXFS: P948-SYNCINIT-READBACK agno=%u daddr=%lld ino=%llu rc=%d magic=%d — the FUA init reported success and the home does NOT read back as an inode cluster; the durable init did not land",
							  agno,
							  (long long)xfs_buf_daddr(fbuf),
							  (unsigned long long)vino,
							  vrc, vmagic ? 1 : 0);
					else if (atomic_read(&p133_n) <= 20)
						mxfs_probe("mxfs: P948-SYNCINIT-READBACK-OK agno=%u daddr=%lld ino=%llu dgen=%u — home reads back as an initialised inode cluster\n",
							agno,
							(long long)xfs_buf_daddr(fbuf),
							(unsigned long long)vino,
							vgen);
				}
			}
			if (mp->m_mxfs_dlm &&
			    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
				struct xfs_perag *qpag =
					xfs_perag_get(mp, agno);
				/*
				 * ROOT FIX — fresh-chunk
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
				if (qpag) {
					mutex_lock(&qpag->pag_mxfs_alloc_buflist_lock);
					xfs_buf_delwri_queue(fbuf,
						&qpag->pag_mxfs_alloc_buflist);
					/*
					 * v0.3.148 mark this buf as
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
			/*
			 * D-0976: this recovery initialised every slot of the
			 * cluster and owns all of them until the write lands.
			 * Without the mask, an inode item of the same recovery
			 * that later fills one slot would make the cluster
			 * write partial and drop the other, still-free,
			 * initialised slots from the I/O.
			 */
			fbuf->b_mxfs_recov_slots =
				(M_IGEO(mp)->inodes_per_cluster >= 64) ? ~0ULL :
				((1ULL << M_IGEO(mp)->inodes_per_cluster) - 1);
			/* 513B: ownership-safe foreign provenance +
			 * queue; a conflict refuses the replay (earlier
			 * clusters stay queued for the caller's unwind). */
			qerr = xfs_buf_delwri_queue_recovery(fbuf, buffer_list,
					mxfs_foreign_recovery);
			xfs_buf_relse(fbuf);
			if (qerr)
				return qerr;
		}
	}
	/* every cluster durably initialised — stamp the proof (icp is
	 * non-NULL whenever tp && v3: kmem_cache_zalloc NOFAIL; the geometry
	 * gate above already guaranteed nbufs > 0 and a whole-cluster length) */
	if (icp && syncinit)
		xfs_icreate_mark_syncinit(icp);
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
	int			force_sparse = 0;

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
	 * D-0948, test only: dbg_force_sparse_carve=1 sends every carve down
	 * the sparse path; =2 also takes the UPPER half of the next
	 * chunk-aligned region first (an exact allocation, falling back to
	 * the ordinary near-bno search), which is the record shape the
	 * defect lives on -- holes BELOW the carved inodes -- and one a
	 * fresh volume never produces on its own (its sparse carves fill
	 * regions from the bottom and merge).  0 in production.
	 */
	{
		extern int mxfs_dbg_force_sparse_carve;

		force_sparse = READ_ONCE(mxfs_dbg_force_sparse_carve);
		if (force_sparse && xfs_has_sparseinodes(tp->t_mountp) &&
		    igeo->ialloc_min_blks < igeo->ialloc_blks)
			do_sparse = 1;
		else
			force_sparse = 0;
	}

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

		if (force_sparse == 2) {
			/*
			 * D-0948 test knob, upper-half form: the next
			 * chunk-aligned region at or above the usual hint
			 * (the block after the last carved chunk, or the
			 * first aligned block of the AG), its upper half
			 * exactly.  A failed exact request leaves the
			 * ordinary near-bno search below to run as before.
			 */
			xfs_agblock_t	align = args.mp->m_sb.sb_inoalignmt;
			xfs_agblock_t	hint = (newino != NULLAGINO) ?
						args.agbno : args.min_agbno;
			xfs_agblock_t	region, high;

			if (hint < args.min_agbno)
				hint = args.min_agbno;
			region = roundup(hint, align);
			high = region + (igeo->ialloc_blks - args.minlen);
			if (high + args.minlen <= args.max_agbno + 1) {
				args.alignment = 1;
				args.minalignslop = 0;
				args.minleft = igeo->inobt_maxlevels;
				error = xfs_alloc_vextent_exact_bno(&args,
						xfs_agbno_to_fsb(pag, high));
				if (error)
					return error;
				mxfs_probe_ratelimited(
				    "mxfs: P-DIALLOC-FORCE-SPARSE agno=%u region=%u high=%u got=%s comm=%s — TEST KNOB: upper-half sparse carve requested\n",
					pag_agno(pag), region, high,
					args.fsbno == NULLFSBLOCK ? "no" : "yes",
					current->comm);
				args.alignment = args.mp->m_sb.sb_spino_align;
				args.minalignslop = 0;
			}
		}
		if (args.fsbno == NULLFSBLOCK) {
			error = xfs_alloc_vextent_near_bno(&args,
					xfs_agbno_to_fsb(pag,
						be32_to_cpu(agi->agi_root)));
			if (error)
				return error;
		}

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
	mxfs_agifc_mod(pag, agbp, "ag_alloc", newlen);
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
	/* 0.89.9: the allocation-coverage witness — a chunk carve published
	 * into this transaction, stamped for the overlap test (xfs_ag.h) */
	{
		u64 now = ktime_get_real_ns();

		atomic64_inc(&pag->pag_mxfs_wit_carves);
		atomic64_cmpxchg(&pag->pag_mxfs_wit_carve_first_ns, 0, now);
		atomic64_set(&pag->pag_mxfs_wit_carve_last_ns, now);
	}
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
 *
 * Only the user-mode build picks this way; the kernel's
 * mxfs_dialloc_pick_in_rec walks the record under a reservation instead.
 */
#ifndef __KERNEL__
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
#endif

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
 * P150 (instrumented, inobt double-free record corruption): record-
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
	mxfs_probe("mxfs: P150-%s agno=%u startino=%u off=%d pre=0x%llx/%d post=0x%llx/%d tenure=%llu mgen=%llu btenure=%llu bgen=%llu daddr=%lld lsn=%llx comm=%s realns=%llu\n",
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
 * P-AGIFC (instrumented): always-on multi-node audit of the AGI free-inode
 * count against BOTH btrees.  The 0.23.9 tmpfile-churn run left AG 0 and AG 5
 * (the two-owner AGs at 32 slots / 25 AGs) with agi_freecount == inobt free +
 * 1 == finobt free + 1 on the platter, AGI + both btree roots stamped with
 * ONE LSN — the last writer carried the +1 in core, so the divergence is
 * either introduced inside one node's alloc/free transaction or imported at
 * AG entry by reading the AGI and the leaves from different tenures.  This
 * audit runs at exactly those points (try_ag entry, alloc post, free post,
 * chunk-grow post) and names the first one that disagrees, with the buffer
 * tenure/gen stamps of the AGI and of each leaf.  Bounded: single-level
 * btrees only (a leaf root holds <= 255 records), capped prints.  Upstream's
 * xfs_check_agi_freecount is DEBUG-only and ASSERT-only; this build is
 * neither, and the failure we chase has no other observer until the AG is
 * full.
 */
void
mxfs_agifc_audit(
	struct xfs_perag		*pag,
	struct xfs_trans		*tp,
	struct xfs_buf			*agbp,
	const char			*site)
{
	static atomic_t			agifc_n = ATOMIC_INIT(0);
	struct xfs_mount		*mp = pag_mount(pag);
	struct xfs_agi			*agi = agbp->b_addr;
	struct xfs_btree_cur		*cur;
	struct xfs_inobt_rec_incore	rec;
	int				ibt_sum = -1, fin_sum = -1;
	int				ibt_n = 0, fin_n = 0;
	uint64_t			ibt_lsn = 0, fin_lsn = 0;
	uint64_t			ibt_bt = 0, fin_bt = 0;
	int				pass, error, i;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (xfs_is_shutdown(mp))
		return;
	if (be32_to_cpu(agi->agi_level) != 1 ||
	    (xfs_has_finobt(mp) && be32_to_cpu(agi->agi_free_level) != 1))
		return;
	for (pass = 0; pass < (xfs_has_finobt(mp) ? 2 : 1); pass++) {
		struct xfs_buf		*lbp = NULL;
		struct xfs_btree_block	*bb;
		int			sum = 0, n = 0;

		cur = pass == 0 ? xfs_inobt_init_cursor(pag, tp, agbp) :
				  xfs_finobt_init_cursor(pag, tp, agbp);
		error = xfs_inobt_lookup(cur, 0, XFS_LOOKUP_GE, &i);
		while (!error && i == 1) {
			error = xfs_inobt_get_rec(cur, &rec, &i);
			if (error || i != 1)
				break;
			sum += rec.ir_freecount;
			n++;
			error = xfs_btree_increment(cur, 0, &i);
		}
		bb = xfs_btree_get_block(cur, 0, &lbp);
		if (pass == 0) {
			ibt_sum = error ? -1 : sum; ibt_n = n;
			ibt_lsn = bb ? be64_to_cpu(bb->bb_u.s.bb_lsn) : 0;
			ibt_bt = lbp ? lbp->b_tenure_id : 0;
		} else {
			fin_sum = error ? -1 : sum; fin_n = n;
			fin_lsn = bb ? be64_to_cpu(bb->bb_u.s.bb_lsn) : 0;
			fin_bt = lbp ? lbp->b_tenure_id : 0;
		}
		xfs_btree_del_cursor(cur, error ? XFS_BTREE_ERROR :
						  XFS_BTREE_NOERROR);
	}
	if (ibt_sum == (int)be32_to_cpu(agi->agi_freecount) &&
	    ibt_sum == (int)pag->pagi_freecount &&
	    (!xfs_has_finobt(mp) || fin_sum == ibt_sum))
		return;
	if (atomic_inc_return(&agifc_n) > 400)
		return;
	mxfs_probe("mxfs: P-AGIFC-MISMATCH site=%s agno=%u agi_freecount=%u pagi_freecount=%u ibt_sum=%d/%drecs fin_sum=%d/%drecs agi_count=%u agi_lsn=%llx agi_btenure=%llu agi_bgen=%llu ibt_lsn=%llx ibt_btenure=%llu fin_lsn=%llx fin_btenure=%llu tenure=%llu mgen=%llu comm=%s realns=%llu — AGI free count disagrees with the btrees at this point\n",
		site, pag_agno(pag),
		be32_to_cpu(agi->agi_freecount), (unsigned)pag->pagi_freecount,
		ibt_sum, ibt_n, fin_sum, fin_n, be32_to_cpu(agi->agi_count),
		(unsigned long long)be64_to_cpu(agi->agi_lsn),
		(unsigned long long)agbp->b_tenure_id,
		(unsigned long long)agbp->b_mxfs_ag_gen,
		(unsigned long long)ibt_lsn, (unsigned long long)ibt_bt,
		(unsigned long long)fin_lsn, (unsigned long long)fin_bt,
		(unsigned long long)pag->ag_dlm_tenure_id,
		(unsigned long long)pag->pag_dlm_meta_gen,
		current->comm, (unsigned long long)ktime_get_real_ns());
}

/*
 * P-AGIFC-MOD: every AGI free-count modification, so the AGI side
 * can be joined against the P150 leaf-record ledger.  Capped like P150.
 */
static void
mxfs_agifc_mod(
	struct xfs_perag	*pag,
	struct xfs_buf		*agbp,
	const char		*site,
	int			delta)
{
	static atomic_t		mod_n = ATOMIC_INIT(0);
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_agi		*agi = agbp->b_addr;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (atomic_inc_return(&mod_n) > 20000)
		return;
	mxfs_probe("mxfs: P-AGIFC-MOD site=%s agno=%u delta=%d agi_freecount=%u pagi_freecount=%u agi_count=%u agi_lsn=%llx agi_btenure=%llu agi_bgen=%llu tenure=%llu mgen=%llu comm=%s realns=%llu\n",
		site, pag_agno(pag), delta, be32_to_cpu(agi->agi_freecount),
		(unsigned)pag->pagi_freecount, be32_to_cpu(agi->agi_count),
		(unsigned long long)be64_to_cpu(agi->agi_lsn),
		(unsigned long long)agbp->b_tenure_id,
		(unsigned long long)agbp->b_mxfs_ag_gen,
		(unsigned long long)pag->ag_dlm_tenure_id,
		(unsigned long long)pag->pag_dlm_meta_gen,
		current->comm, (unsigned long long)ktime_get_real_ns());
}
#else
#define mxfs_agifc_mod(pag, agbp, site, delta) do { } while (0)
#endif

/*
 * (reviewed design; deadlock-3 autopsy): reserve the
 * candidate ino's cluster DLM EX at SELECTION time, BEFORE the inobt/finobt
 * record RMW dirties the transaction.  Upstream's create order is
 * AG -> (dirty) -> child-ino ILOCK at icreate/iget; a peer's truncate order
 * is ino -> AG.  When the peer holds a grant on our candidate with its
 * holder blocked wanting OUR AG, the old blocking child acquire at iget
 * deadlocked with BOTH edges dirty (unbreakable; 180s -> -110 -> cluster
 * shutdown).  The invariant this enforces: no NEW blocking cluster acquire
 * after the transaction is irrevocable.  On success the grant is
 * node-cached, so icreate/iget's ilock fast-paths on it — the reservation IS
 * the handoff token.
 *
 * 0.23.0 (design-consult ruling dialloc-
 * try-reserve-candidate-rotation; D-RSYNC-LAP-PACE-AG-SHARING-388): the
 * reserve is a NONQUEUED try (one CAW slot CAS, no waiter, nothing outlives
 * the call) and a contended candidate is SKIPPED — the next free inode in
 * the record, then the next record — instead of waited for.  The
 * 1 s bounded acquire that this replaces was measured as THE lap-2 pace
 * root at agcount<nodes: two nodes sharing an AG, the first-free candidate
 * is always an inode the peer just freed and still holds (noino lifecycle,
 * released only by its BAST-driven AIL drain fence, which itself queues on
 * the AG we hold) — a cross-resource wait broken only by the deadline, once
 * per candidate, re-picked on every pass (43 x 1 s on one node's 49 s
 * rsync).  Rules: (1) never block on a peer-held slot while holding the
 * AGI/AG; (2) modify nothing on-tree until a reserve succeeded; (3) at most
 * MXFS_RESV_PROBES_MAX probes / MXFS_RESV_VISIT_NS per AG visit, then
 * -EAGAIN (AGI+AG released by the caller, cursor kept for the next visit);
 * (4) contended candidates enter a short jittered per-AG cooldown;
 * (5) backoff only in xfs_dialloc after a full failed sweep, outside every
 * lock, escalating to DEMAND (sticky revoke on the holder's slot) so an
 * idle holder is eventually told to release; (6) contention never becomes
 * ENOSPC.
 */
#ifdef __KERNEL__
#define MXFS_RESV_PROBES_MAX	8
#define MXFS_RESV_VISIT_NS	(4 * NSEC_PER_MSEC)
#define MXFS_RESV_COOL_MS	500
#define MXFS_RESV_COOL_JIT_MS	500
/*
 * D-0946 progress rule.  A candidate refused because THIS node's own free of
 * it is still unpublished is skipped and cooled; after this many such refusals
 * in ONE allocation the allocator stops merely re-picking and drives the write
 * that is blocking it.  DRIVE_AT is small because on a small inode population
 * (rapid unlink/create churn -- exactly this rig's workload) the same handful
 * of numbers come back round immediately; DRIVE_MS bounds how long a create may
 * wait on a local log force + AIL push, and DRIVE_MAX stops one allocation from
 * spending its whole life driving.
 */
/*
 * A publication-pending candidate cools for far less time than a peer-held one.
 * The owed write is local and was kicked at the moment of refusal; a measured
 * one landed in 8 ms.  Holding the number out of play for the peer-contention
 * ring's 500-1000 ms keeps a healthy AG looking empty for a hundred times
 * longer than the condition actually lasts.
 */
#define MXFS_PUBPEND_COOL_MS	40
#define MXFS_PUBPEND_COOL_JIT_MS 40
/*
 * TRIED AND REVERTED (0.75.122, instrumented): yielding the AG early on a run of
 * publication-pending refusals -- instead of re-picking to the generic
 * 64-restart storm bound -- sounded obviously right, because only the passage
 * of time can change the answer and a tight re-pick loop yields none.  It
 * measured WORSE on both counts it was meant to improve.  Directory churn,
 * 12 rounds, same harness and same build family: unnecessary chunk carves per
 * fix round went from 0-4 up to 8-13, and the fix arm's wall went from roughly
 * level with the control arm (4779-5417 ms vs 4838-5545) to clearly behind it
 * (4636-7452 ms vs 4180-6124).  Handing the AG back sends the allocation to
 * another AG or to a grow, which is more expensive than finishing the re-pick.
 * Do not reintroduce it without a measurement that beats those numbers.
 */
#define MXFS_PUBPEND_DRIVE_AT	4
#define MXFS_PUBPEND_DRIVE_MS	200
#define MXFS_PUBPEND_DRIVE_MAX	4
/*
 * 0.87.13 (D-0939): a candidate refused by a probe that carried DEMAND has
 * had its holder told to let go; the master BASTs the holder on the deny
 * (both engines since the TCP parity fix in mxfs_v5_dlm_inode_reserve_try),
 * and a cached grant on a number the holder already freed releases in
 * milliseconds — the very next queued EX on such a number handed off in
 * ~10 ms on the 2-node TCP rig.  Cooling it for the silent-probe ring's
 * 500-1000 ms keeps a released number out of play for a hundred times longer
 * than the release takes, and on this rig's small inode population that was
 * the round's whole allocation stall.  A separate class, not the
 * publication-pending one: that one is bounded by a LOCAL write we kicked,
 * this one by a PEER's release fence, and the two will be tuned apart.
 * Silent (undemanded) contention keeps the long ring.
 */
#define MXFS_DEMAND_COOL_MS	40
#define MXFS_DEMAND_COOL_JIT_MS	40

enum mxfs_resv_cool_kind {
	MXFS_RESV_COOL_HELD,		/* peer-held, probe was silent */
	MXFS_RESV_COOL_PUBPEND,		/* our own free of it is unpublished */
	MXFS_RESV_COOL_DEMANDED,	/* peer-held, probe carried DEMAND */
};

atomic64_t mxfs_resv_stat_try = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_ok = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_contended = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_cool = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_err = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_exhaust = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_recadv = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_sweeps = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_backoff_ms = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_demand = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_probe_ns = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_probe_max_ns = ATOMIC64_INIT(0);
atomic64_t mxfs_resv_stat_grow = ATOMIC64_INIT(0);	/* 0.23.1: chunk grown on a swept owned AG */

/* per-xfs_dialloc-call reserve state (threaded through try_ag/dialloc_ag) */
struct mxfs_dialloc_resv {
	int	demand;		/* escalated: leave DEMAND on held slots */
	int	contended;	/* candidates skipped for contention, this call */
	int	cool_skips;	/* candidates skipped on cooldown, this call */
	int	probes;		/* probes this AG visit */
	u64	visit_t0;	/* ktime_get_ns() at AG visit start */
	int	budget_exhausted;
	int	swept;		/* a full finobt lap found nothing reservable */
	/*
	 * (D-0351 containment): two-phase candidate validation.
	 * Phase 1 picks + reserves a candidate under the cursors and returns
	 * it WITHOUT touching the trees; the caller drops cursors + AGI,
	 * validates the candidate's platter dinode (authoritative plain read,
	 * pubob store consulted first); phase 2 re-enters with `validated`
	 * set and takes exactly that inode.  `quarantined` counts candidates
	 * skipped because their agino is in pag_disklive_q (this call);
	 * `disklive` counts fresh DISK-LIVE verdicts (this xfs_dialloc).
	 */
	xfs_ino_t validated;
	int	quarantined;
	int	disklive;
	int	restarts;
	/*
	 * D-0946: candidates refused because THIS node's own free of that
	 * number is still unpublished (the platter there still carries our
	 * live predecessor image).  Transient, never quarantined -- and
	 * counted separately from `cool_skips` so the sweep logic can tell
	 * "a peer holds it" from "we owe a write on it".
	 */
	int	pubpend;
	int	pubdrives;
	/*
	 * D-DIALLOC-REPICK-STORM: inode chunks carved by THIS xfs_dialloc call,
	 * across every AG visit and every re-sweep.  The caller's transaction
	 * reserved XFS_IALLOC_SPACE_RES — space for exactly one chunk — and a
	 * roll carries only the remainder forward, so a second carve in the
	 * same call is the reservation overrun that xfs_trans_mod_sb turns
	 * into SHUTDOWN_CORRUPT_INCORE.
	 */
	int	grows;
};

/* the quarantine (pag_disklive_q): exact agino membership, no expiry */
static bool
mxfs_disklive_q_has(
	struct xfs_perag	*pag,
	xfs_agino_t		agino)
{
	return xa_load(&pag->pag_disklive_q, agino) != NULL;
}

static int
mxfs_disklive_q_add(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	uint32_t		disk_gen)
{
	int rc = xa_err(xa_store(&pag->pag_disklive_q, agino,
				 xa_mk_value(disk_gen & 0x7fffffffu), GFP_NOFS));

	if (!rc) {
		spin_lock(&pag->pag_resv_lock);
		pag->pag_disklive_n++;
		spin_unlock(&pag->pag_resv_lock);
	}
	return rc;
}

/*
 * Phase-2 validation of a picked candidate: what would a peer (or we) find
 * at the platter home of `ino`?  Called by xfs_dialloc_try_ag with NO btree
 * cursor and NO AGI buffer held (the AG EX itself is held: no peer can
 * change the number's state meanwhile).  The transaction is clean.
 *   0        the platter image is free — allocate;
 *   -EBUSY   this node holds an open FREE/FREE_PENDING/CHAIN_LIVE obligation
 *            on the number (docs/free-publish.md): its home still carries our
 *            live predecessor image because our own free has not been written
 *            there yet.  TRANSIENT — cooldown, re-pick, and drive the write;
 *            never the mount-lifetime quarantine, which would be a false
 *            corruption verdict and would leak inode space (D-0946);
 *   -EUCLEAN the platter image is LIVE: a crossed FREE-PUBLISH invariant.
 *            Quarantined + loud; the caller re-picks.  The reservation
 *            taken on it stays node-cached (harmless; it also keeps peers'
 *            try-reserve off the same number);
 *   -EIO     the home could not be READ: retried once by the caller, then the
 *            create fails cleanly.  A home that reads cleanly but holds no
 *            inode magic is NOT this case -- see P947-VALIDATE-NOMAGIC.
 */
static void mxfs_resv_cool_add_kind(struct xfs_perag *pag, xfs_agino_t agino,
				    enum mxfs_resv_cool_kind kind);

static int
mxfs_dialloc_validate_candidate(
	struct xfs_perag	*pag,
	xfs_ino_t		ino,
	struct mxfs_dialloc_resv *rs)
{
	struct xfs_mount	*mp = pag_mount(pag);
	extern bool mxfs_pubob_lookup(struct xfs_mount *, uint64_t, uint8_t *,
				      uint32_t *, uint64_t *, uint16_t *);
	uint8_t		okind = 0;
	uint32_t	ogen = 0, dgen = 0;
	uint64_t	oepoch = 0;
	uint16_t	ochain = 0, dmode = 0;
	bool		dmagic = false;
	xfs_agino_t	agino = XFS_INO_TO_AGINO(mp, ino);

	/*
	 * D-0946: AN OPEN OBLIGATION OF OURS IS A REASON TO REFUSE THIS NUMBER,
	 * NOT A REASON TO ALLOW IT.
	 *
	 * This arm used to allow the candidate without reading the platter, on
	 * the grounds that a live image at its home had to be this node's own
	 * committed-but-unpublished free.  That inference is consistent with the
	 * state but is not proof of ownership of it, and downstream nothing else
	 * shares it: the create path's recycle gate (xfs_icache.c) reads the
	 * platter, finds the live dinode, calls it cross-node incoherence and
	 * returns -EFSCORRUPTED on an ALREADY DIRTY transaction — which cancels
	 * the transaction and shuts the whole filesystem down.  Measured three
	 * times on the two-node TCP rig with nothing killed: 32 of 32
	 * P946-VALIDATE-ALLOW lines were via=pubob, every one on a healthy
	 * filesystem, and one of them cost the mount.
	 *
	 * Teaching the recycle gate the exemption instead would move the same
	 * unproven inference downstream, where a false accept silently overwrites
	 * a LIVE inode — strictly worse than the shutdown it replaces.  So the
	 * decisive refusal happens HERE, which is the last point before anything
	 * is dirtied: no btree cursor, no AGI buffer, a clean transaction.
	 *
	 * The refusal is TRANSIENT and must never become the mount-lifetime
	 * DISK-LIVE quarantine: an inode whose only problem is "our own write is
	 * still owed" is not corrupt, and quarantining it would leak inode space,
	 * force needless chunk allocation and manufacture false ENOSPC.  It goes
	 * on the ordinary reservation cooldown (500-1000 ms) so the pick moves on,
	 * and the caller drives the publication so the number comes back.
	 *
	 * Positive whitelist, never `okind != UNLINK`: an UNLINK obligation owes
	 * an nlink=0 image, not a free, so it keeps falling through to the
	 * authoritative platter read, and a kind added later does the same rather
	 * than inheriting a blanket refusal nobody re-examined.
	 */
	if (mxfs_pubob_lookup(mp, ino, &okind, &ogen, &oepoch, &ochain) &&
	    (okind == MXFS_PUBOB_FREE || okind == MXFS_PUBOB_FREE_PENDING ||
	     okind == MXFS_PUBOB_CHAIN_LIVE)) {
		extern int mxfs_dialloc_pubpend_refuse;
		/*
		 * ONE COUNTER PER ARM.  A single shared counter lets whichever
		 * arm runs first spend the whole rate-limit budget, and the
		 * other arm then reads as SILENT while it is in fact running --
		 * which is exactly how an A/B gets reported backwards.  Measured
		 * once already: 33 refusals in round 1 muted every CONTROL-ARM
		 * line for the rest of the run.  Both are module parameters
		 * (dialloc_pubpend_refused / _allowed, xfs_mxfs_dlm.c): a
		 * harness reads the exact count instead of the budgeted lines,
		 * and writing one resets it along with its print budget.
		 */
		int n;

		if (!READ_ONCE(mxfs_dialloc_pubpend_refuse)) {
			/* A/B control arm: the pre-fix inference, which the
			 * recycle gate then contradicts on a dirty transaction */
			n = atomic_inc_return(&mxfs_dialloc_pubpend_allowed);
			if (n <= 32 || (n % 500) == 0)
				mxfs_probe("mxfs: P946-VALIDATE-ALLOW via=pubob ino=%llu agno=%u agino=%u okind=%u ogen=%u oepoch=%llu ochain=%u — CONTROL ARM: allowed WITHOUT reading the platter\n",
					(unsigned long long)ino, pag_agno(pag),
					agino, (unsigned)okind, ogen,
					(unsigned long long)oepoch,
					(unsigned)ochain);
			return 0;
		}
		n = atomic_inc_return(&mxfs_dialloc_pubpend_refused);
		rs->pubpend++;
		mxfs_resv_cool_add_kind(pag, agino, MXFS_RESV_COOL_PUBPEND);
		if (n <= 32 || (n % 500) == 0)
			mxfs_probe("mxfs: P946-VALIDATE-PUBPEND ino=%llu agno=%u agino=%u okind=%u ogen=%u oepoch=%llu ochain=%u n=%d — candidate REFUSED: this node's own free of this number is not on the platter yet, so its home still carries our live predecessor image; transient cooldown, re-picking (no transaction dirtied)\n",
				(unsigned long long)ino, pag_agno(pag), agino,
				(unsigned)okind, ogen,
				(unsigned long long)oepoch, (unsigned)ochain, n);
		return -EBUSY;
	}
	/*
	 * D-0947: A HOME WITH NO INODE MAGIC IS NOT AN UNREADABLE HOME — AND IT
	 * IS NOT AUTOMATICALLY A SAFE ONE EITHER.
	 *
	 * This used to call mxfs_dbg_disk_di_mode_coherent(), whose 0xFFFF means
	 * both "the read failed" and "the read succeeded and there is no dinode
	 * there", and it mapped both to -EIO.  That failed 600 of 600 creates on
	 * a filesystem 7% full with 1% of its inodes used, because the second
	 * case is the ordinary state of every inode in a chunk this mount has
	 * allocated and not destaged: the new cluster is initialised in memory
	 * and logged, not written, so its home still holds whatever preceded it.
	 *
	 * But "no inode magic" does NOT mean "nothing was ever written there".
	 * Measured on this rig: a candidate whose home read cleanly with no magic
	 * held `58 44 44 33` — XDD3, a directory data block, self-identifying at
	 * that very address.  Allocating it let xfs_imap_to_bp read the platter,
	 * fail the inode verifier and shut the filesystem down on a dirty
	 * transaction.  So neither blanket answer is right, and neither can be
	 * reached by inference: the two causes are indistinguishable from the
	 * bytes alone.
	 *
	 * They are trivially distinguishable by ACTION.  Push the log and the
	 * AIL once and read again: an un-destaged chunk of ours now has its
	 * magic and the candidate is good, while a home that still has none
	 * after everything we owe is on the platter is not ours to hand out.
	 * That one is refused transiently — cooldown and re-pick, no create
	 * failed, nothing dirtied — and only a candidate that stays magic-less
	 * across repeated allocations is quarantined as the divergence it is.
	 */
	{
		extern bool mxfs_dbg_validate_nomagic_take(unsigned long long);
		bool injected = false;
		int rrc = mxfs_dbg_disk_di_read_coherent(mp, ino, &dmode, &dgen,
							 &dmagic);

		if (rrc)
			return -EIO;
		/*
		 * 0.84.16, test only: dbg_validate_nomagic_n makes the next N
		 * candidates read as magic-less whatever the platter holds, so
		 * the arm below can be driven on a healthy filesystem — the one
		 * measured way to reach it otherwise is a home that really holds
		 * no dinode, which a healthy carve never leaves behind (the
		 * chunk is FUA-initialised and read back before its ICREATE
		 * record is logged).  0 in production.
		 */
		if (dmagic && mxfs_dbg_validate_nomagic_take(ino)) {
			dmagic = false;
			injected = true;
		}
		if (!dmagic) {
			static atomic_t nomagic_n = ATOMIC_INIT(0);
			int n = atomic_inc_return(&nomagic_n);

			/*
			 * Kick the owed writes and REFUSE, rather than flushing
			 * synchronously and re-reading here.  The re-read would
			 * be the honest test, but it can only be trusted after a
			 * synchronous flush, and this runs under the AG EX where
			 * a synchronous flush is cluster-wide head-of-line
			 * blocking (the D-0946 ruling names it, and its worst
			 * case is this exact workload).  So: start the writes,
			 * put the candidate on the ordinary 500-1000 ms
			 * cooldown, and let the NEXT visit read a home that has
			 * had time to land.  If it was our own un-destaged
			 * cluster it will have its magic by then and allocate
			 * normally; if it was never ours it still will not, and
			 * it keeps being refused.  Same decision, one cooldown
			 * later, with nothing waited on under the grant.
			 */
			mxfs_pubob_flush_owed(mp);
			rs->pubpend++;
			mxfs_resv_cool_add_kind(pag, agino, MXFS_RESV_COOL_PUBPEND);
			if (n <= 16 || (n % 500) == 0 || injected)
				pr_warn("mxfs: P947-VALIDATE-NOMAGIC ino=%llu agno=%u agino=%u n=%d injected=%d — home holds no inode magic; owed writes kicked and the candidate REFUSED transiently, re-picking after the cooldown (no transaction dirtied, nothing waited on under the AG grant)\n",
					(unsigned long long)ino,
					pag_agno(pag), agino, n, injected ? 1 : 0);
			return -EBUSY;
		}
	}
	if (dmode == 0) {
		/*
		 * Recorded ONLY for the numbers already known to have gone wrong
		 * this mount: a candidate the quarantine has seen live before,
		 * now reading free, is the coherent-vs-raw disagreement itself.
		 */
		if (mxfs_disklive_q_has(pag, agino))
			pr_warn("mxfs: P946-VALIDATE-ALLOW via=coherent-free ino=%llu agno=%u agino=%u dgen=%u — the COHERENT platter read says FREE for a number this mount has already quarantined as LIVE\n",
				(unsigned long long)ino, pag_agno(pag), agino,
				dgen);
		return 0;
	}
	rs->disklive++;
	if (mxfs_disklive_q_add(pag, agino, dgen))
		pr_err("mxfs: P-DIALLOC-DISKLIVE-QFULL agno=%u agino=%u — cannot record the quarantine entry; failing this create cleanly\n",
			pag_agno(pag), agino);
	pr_warn("mxfs: P-DIALLOC-DISKLIVE ino=%llu agno=%u agino=%u disk_mode=0%o disk_gen=%u quarantined=%u — inobt says FREE but the platter dinode is LIVE (FREE-PUBLISH crossed on some node); candidate quarantined for the life of this mount, re-picking (no transaction dirtied)\n",
		(unsigned long long)ino, pag_agno(pag), agino, dmode, dgen,
		pag->pag_disklive_n);
	return -EUCLEAN;
}

static bool
mxfs_resv_cool_hot(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	bool			*pubpendp)
{
	unsigned int		k;
	bool			hot = false;

	if (pubpendp)
		*pubpendp = false;
	spin_lock(&pag->pag_resv_lock);
	for (k = 0; k < MXFS_RESV_COOL_N; k++) {
		if (pag->pag_resv_cool[k].agino == agino &&
		    pag->pag_resv_cool[k].until) {
			if (time_before(jiffies, pag->pag_resv_cool[k].until)) {
				hot = true;
				if (pubpendp)
					*pubpendp = pag->pag_resv_cool[k].pubpend;
			} else {
				pag->pag_resv_cool[k].until = 0;	/* expired */
			}
			break;
		}
	}
	spin_unlock(&pag->pag_resv_lock);
	return hot;
}

static void
mxfs_resv_cool_add_kind(
	struct xfs_perag	*pag,
	xfs_agino_t		agino,
	enum mxfs_resv_cool_kind kind)
{
	unsigned int		k;
	bool			pubpend = kind == MXFS_RESV_COOL_PUBPEND;
	unsigned int		ms;
	unsigned long		until;

	switch (kind) {
	case MXFS_RESV_COOL_PUBPEND:
		ms = MXFS_PUBPEND_COOL_MS +
		     get_random_u32_below(MXFS_PUBPEND_COOL_JIT_MS);
		break;
	case MXFS_RESV_COOL_DEMANDED:
		ms = MXFS_DEMAND_COOL_MS +
		     get_random_u32_below(MXFS_DEMAND_COOL_JIT_MS);
		break;
	case MXFS_RESV_COOL_HELD:
	default:
		ms = MXFS_RESV_COOL_MS +
		     get_random_u32_below(MXFS_RESV_COOL_JIT_MS);
		break;
	}
	until = jiffies + msecs_to_jiffies(ms);

	spin_lock(&pag->pag_resv_lock);
	for (k = 0; k < MXFS_RESV_COOL_N; k++) {
		if (pag->pag_resv_cool[k].agino == agino &&
		    pag->pag_resv_cool[k].until) {
			pag->pag_resv_cool[k].until = until;
			pag->pag_resv_cool[k].pubpend = pubpend;
			goto out;
		}
	}
	k = pag->pag_resv_cool_next++ % MXFS_RESV_COOL_N;
	pag->pag_resv_cool[k].agino = agino;
	pag->pag_resv_cool[k].until = until;
	pag->pag_resv_cool[k].pubpend = pubpend;
out:
	spin_unlock(&pag->pag_resv_lock);
}

/*
 * One nonqueued reserve attempt.  0 = reserved; -EAGAIN = held by a peer
 * (skip the candidate); any other error is counted and reported separately
 * (transport/slot trouble is never silently a "skip") but the candidate is
 * still skipped — the allocator must not fail a create on one bad probe.
 */
static int
mxfs_dialloc_try_reserve(
	struct xfs_perag	*pag,
	xfs_ino_t		ino,
	struct mxfs_dialloc_resv *rs)
{
	struct xfs_mount	*mp = pag_mount(pag);
	u64			t0 = ktime_get_ns();
	s64			dt;
	int			rc;

	rs->probes++;
	atomic64_inc(&mxfs_resv_stat_try);
	if (rs->demand)
		atomic64_inc(&mxfs_resv_stat_demand);
	rc = mxfs_v5_dlm_inode_reserve_try(mp->m_mxfs_dlm, ino, rs->demand,
					   NULL);
	dt = (s64)(ktime_get_ns() - t0);
	atomic64_add(dt, &mxfs_resv_stat_probe_ns);
	if (dt > atomic64_read(&mxfs_resv_stat_probe_max_ns))
		atomic64_set(&mxfs_resv_stat_probe_max_ns, dt);
	if (rc == 0) {
		atomic64_inc(&mxfs_resv_stat_ok);
		return 0;
	}
	if (rc == -EAGAIN || rc == -EWOULDBLOCK) {
		atomic64_inc(&mxfs_resv_stat_contended);
		rs->contended++;
		return -EAGAIN;
	}
	atomic64_inc(&mxfs_resv_stat_err);
	rs->contended++;
	mxfs_probe_ratelimited(
	    "mxfs: P-DIALLOC-RESV-ERR ino=%llu agno=%u rc=%d — try-reserve failed for a non-contention reason; candidate skipped\n",
		(unsigned long long)ino, pag_agno(pag), rc);
	return -EAGAIN;
}

/*
 * Pick a reservable free inode out of one inobt/finobt record.  Works on a
 * private copy of ir_free; the on-tree record is untouched until the caller
 * commits the one inode it was handed.  Returns 0 with *offp; -EAGAIN when
 * the record has no reservable candidate (or the visit budget is spent —
 * rs->budget_exhausted tells the caller to stop advancing and return the AG);
 * other errors from the sickness check.
 */
static int
mxfs_dialloc_pick_in_rec(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct xfs_inobt_rec_incore *rec,
	struct mxfs_dialloc_resv *rs,
	int			*offp)
{
	struct xfs_mount	*mp = pag_mount(pag);
	uint64_t		wfree = rec->ir_free;
	uint64_t		holes = 0;
	bool			clustered = mp->m_mxfs_dlm &&
				!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);
	extern int		mxfs_dbg_dialloc_pick_holes;
	extern atomic_t		mxfs_dialloc_holemask_n;
	extern atomic_t		mxfs_dialloc_holepick_n;

	/*
	 * D-0948: a sparse record's free mask has every HOLE bit set (the
	 * carve stamps ir_free = ALL_FREE and puts the missing half in
	 * ir_holemask), so the walk below must never see a hole as a free
	 * inode: the block behind a hole was never carved and belongs to
	 * whatever owns it.  On s572 (0.75.118) this walk took offset 0 of a
	 * record with holemask 0xff; the home was a live directory data
	 * block, the create read XDD3 where it expected an inode cluster,
	 * and the dirty transaction shut the filesystem down.  Upstream's
	 * xfs_inobt_first_free_inode masks with the allocation mask; so does
	 * this now.  The knob keeps the hole-blind walk reachable as the
	 * control arm of an A/B and is 0 in production.
	 */
	if (xfs_inobt_issparse(rec->ir_holemask)) {
		uint64_t alloc = xfs_inobt_irec_to_allocmask(rec);

		holes = wfree & ~alloc;
		if (holes) {
			atomic_inc(&mxfs_dialloc_holemask_n);
			if (!READ_ONCE(mxfs_dbg_dialloc_pick_holes))
				wfree &= alloc;
			mxfs_probe_ratelimited(
			    "mxfs: P-DIALLOC-HOLEMASK agno=%u startino=%u holemask=0x%x count=%u free=0x%llx holes=0x%llx masked=%d comm=%s — sparse inode record: hole bits removed from the candidate walk (0 = control arm, hole-blind)\n",
				pag_agno(pag), rec->ir_startino,
				(unsigned)rec->ir_holemask, (unsigned)rec->ir_count,
				(unsigned long long)rec->ir_free,
				(unsigned long long)holes,
				READ_ONCE(mxfs_dbg_dialloc_pick_holes) ? 0 : 1,
				current->comm);
		}
	}

	while (wfree) {
		int		off = xfs_lowbit64(wfree);
		xfs_agino_t	agino = rec->ir_startino + off;
		xfs_ino_t	ino = xfs_agino_to_ino(pag, agino);
		int		error;

		wfree &= ~XFS_INOBT_MASK(off);
		if (holes & XFS_INOBT_MASK(off)) {
			/* control arm only: the pre-fix pick, counted exactly
			 * in dialloc_holepick_n; the line prints its first
			 * 200 per load. */
			static atomic_t holepick_lines = ATOMIC_INIT(0);

			atomic_inc(&mxfs_dialloc_holepick_n);
			if (atomic_inc_return(&holepick_lines) <= 200)
				mxfs_probe("mxfs: P-DIALLOC-HOLEPICK agno=%u startino=%u off=%d agino=%u ino=%llu holemask=0x%x comm=%s — CONTROL ARM: candidate taken from inside a sparse record's hole (its home block was never carved)\n",
					pag_agno(pag), rec->ir_startino, off,
					agino, (unsigned long long)ino,
					(unsigned)rec->ir_holemask,
					current->comm);
		}

		if (xfs_ag_has_sickness(pag, XFS_SICK_AG_INODES)) {
			error = xfs_dialloc_check_ino(pag, tp, ino);
			if (error)
				return error;
		}
		if (!clustered) {
			*offp = off;
			return 0;
		}
		/* phase 2 — take exactly the validated candidate (its
		 * reservation is already held; no probe, no cooldown check) */
		if (rs->validated != NULLFSINO) {
			if (ino == rs->validated) {
				*offp = off;
				return 0;
			}
			continue;
		}
		if (mxfs_disklive_q_has(pag, agino)) {
			rs->quarantined++;
			continue;
		}
		{
			bool cool_pubpend = false;

			if (mxfs_resv_cool_hot(pag, agino, &cool_pubpend)) {
				/*
				 * A number cooling because WE owe its home a
				 * write is not evidence that this AG is spent.
				 * Tallying it as contention is what made a
				 * healthy AG report 'every free inode is
				 * peer-held' and grow a chunk it did not need.
				 */
				if (cool_pubpend)
					rs->pubpend++;
				else
					rs->cool_skips++;
				atomic64_inc(&mxfs_resv_stat_cool);
				continue;
			}
		}
		if (rs->probes >= MXFS_RESV_PROBES_MAX ||
		    (s64)(ktime_get_ns() - rs->visit_t0) > MXFS_RESV_VISIT_NS) {
			rs->budget_exhausted = 1;
			return -EAGAIN;
		}
		error = mxfs_dialloc_try_reserve(pag, ino, rs);
		if (error == 0) {
			*offp = off;
			return 0;
		}
		/* A demanded refusal has its holder's release in flight: cool
		 * for the release fence, not for the silent ring (see
		 * MXFS_DEMAND_COOL_MS). */
		mxfs_resv_cool_add_kind(pag, agino, rs->demand ?
					MXFS_RESV_COOL_DEMANDED :
					MXFS_RESV_COOL_HELD);
	}
	return -EAGAIN;
}
#else
struct mxfs_dialloc_resv { int unused; xfs_ino_t validated; };
static inline int
mxfs_dialloc_pick_in_rec(struct xfs_perag *pag, struct xfs_trans *tp,
			 struct xfs_inobt_rec_incore *rec,
			 struct mxfs_dialloc_resv *rs, int *offp)
{
	*offp = xfs_inobt_first_free_inode(rec);
	return 0;
}
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
	xfs_ino_t		*inop,
	struct mxfs_dialloc_resv *rs)
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
	/*
	 * 0.23.0: try-reserve rotation within the record.  This
	 * inobt-only path (no finobt) does not advance records on a contended
	 * chunk — it returns the AG (-EAGAIN) and the sweep retries; mkfs_mxfs
	 * always formats a finobt, so xfs_dialloc_ag below is the real path.
	 */
	error = mxfs_dialloc_pick_in_rec(pag, tp, &rec, rs, &offset);
	if (error)
		goto error0;
	ASSERT(offset >= 0);
	ASSERT(offset < XFS_INODES_PER_CHUNK);
	ASSERT((XFS_AGINO_TO_OFFSET(mp, rec.ir_startino) %
				   XFS_INODES_PER_CHUNK) == 0);
	ino = xfs_agino_to_ino(pag, rec.ir_startino + offset);

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
	mxfs_agifc_mod(pag, agbp, "dialloc_ag_inobt", -1);

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
			mxfs_probe("mxfs: P-DIAG-NEAR-LE-GETREC agno=%u pagino=%u i=%d\n",
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
		/* P72-INSTR: fire-only-on-corruption — is the finobt
		 * leaf STALE vs disk (read-coherency) or on-disk garbage? */
		{
			struct xfs_perag *p72_pag = to_perag(lcur->bc_group);
			struct xfs_buf *p72_lb = lcur->bc_levels[0].bp;
			int p72_d = p72_lb ? mxfs_ag_buf_disk_differs(p72_lb) : -99;
			int p72_pin = p72_lb ? atomic_read(&p72_lb->b_pin_count) : -1;
			int p72_dirty = (p72_lb && p72_lb->b_log_item &&
				test_bit(XFS_LI_DIRTY, &p72_lb->b_log_item->bli_item.li_flags)) ? 1 : 0;
			mxfs_probe("mxfs: P72-INSTR finobt-near-fail agno=%u i=%d j=%d pagino=%u pag_gen=%llu cached=%d holders=%d "
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
				mxfs_probe("mxfs: P-DIAG-NEWINO-HINT agno=%u newino=%u i=%d\n",
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
		/* P-DIAG: the finobt says this AG has free inodes (agi
		 * freecount>0 got us here) but the finobt B-tree itself has NO
		 * record at all (GE 0 returns nothing).  finobt buffer is stale
		 * vs AGI, or empty/torn. */
		{
			struct xfs_perag *dp = to_perag(cur->bc_group);
			struct xfs_buf *lb = cur->bc_levels[0].bp;
			mxfs_probe("mxfs: P-DIAG-NEWINO-FIRST agno=%u i=%d agi_freecnt=%u "
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
		mxfs_probe("mxfs: P-DIAG-NEWINO-GETREC agno=%u i=%d\n",
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
		/* P-DIAG: finobt selected startino %llu but the INOBT has
		 * NO matching record (i=%d) — inobt cached buffer is STALE vs
		 * finobt (cross-tree desync). */
		{
			struct xfs_perag *dp = to_perag(cur->bc_group);
			struct xfs_buf *lb = cur->bc_levels[0].bp;
			mxfs_probe("mxfs: P-DIAG-UI-LOOKUP agno=%u startino=%llu i=%d "
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
		mxfs_probe("mxfs: P-DIAG-UI-GETREC agno=%u startino=%llu i=%d\n",
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
		/* P-DIAG: the inobt record for this chunk DISAGREES with
		 * the finobt record after applying the same alloc — the two
		 * btrees are out of sync.  Dump both so we can see which side is
		 * stale (cached-buffer coherency vs torn write). */
		{
			struct xfs_perag *dp = to_perag(cur->bc_group);
			struct xfs_buf *lb = cur->bc_levels[0].bp;
			mxfs_probe("mxfs: P-DIAG-UI-MISMATCH agno=%u startino=%llu offset=%d "
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
	xfs_ino_t		*inop,
	struct mxfs_dialloc_resv *rs,
	bool			pick_only)
{
	struct xfs_mount		*mp = tp->t_mountp;
	struct xfs_agi			*agi = agbp->b_addr;
	xfs_agnumber_t			pagno = XFS_INO_TO_AGNO(mp, parent);
	xfs_agino_t			pagino = XFS_INO_TO_AGINO(mp, parent);
	struct xfs_btree_cur		*cur;	/* finobt cursor */
	struct xfs_btree_cur		*icur;	/* inobt cursor */
	struct xfs_inobt_rec_incore	rec;
	xfs_ino_t			ino;
	xfs_agino_t			start_rec;
	xfs_agino_t			cursor = NULLAGINO;
	int				error;
	int				offset;
	int				i;

	if (!xfs_has_finobt(mp))
		return xfs_dialloc_ag_inobt(pag, tp, agbp, parent, inop, rs);

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
	 *
	 * 0.23.0: a previous visit that ran out of probe budget on
	 * this AG left a continuation cursor — resume there instead of
	 * re-probing the same (peer-held) first-free candidates.
	 */
#ifdef __KERNEL__
	spin_lock(&pag->pag_resv_lock);
	cursor = pag->pag_resv_cursor;
	spin_unlock(&pag->pag_resv_lock);
	/* phase 2: start at the validated candidate's chunk record */
	if (rs->validated != NULLFSINO)
		cursor = XFS_INO_TO_AGINO(mp, rs->validated) &
			 ~((xfs_agino_t)XFS_INODES_PER_CHUNK - 1);
#endif
	if (cursor != NULLAGINO) {
		error = xfs_inobt_lookup(cur, cursor, XFS_LOOKUP_GE, &i);
		if (error)
			goto error_cur;
		if (i == 1) {
			error = xfs_inobt_get_rec(cur, &rec, &i);
			if (error)
				goto error_cur;
		}
		if (i != 1)
			cursor = NULLAGINO;	/* cursor past the end: normal pick */
	}
	if (cursor == NULLAGINO) {
		if (pag_agno(pag) == pagno)
			error = xfs_dialloc_ag_finobt_near(pagino, &cur, &rec);
		else
			error = xfs_dialloc_ag_finobt_newino(agi, cur, &rec);
		if (error)
			goto error_cur;
	}

	/*
	 * 0.23.0: candidate rotation.  Try the free inodes of this
	 * record in order; a record with no reservable inode advances to the
	 * next finobt record (wrapping once) — "first free" is not a right,
	 * a peer's just-freed, still-held inode is simply not ours to take
	 * yet.  Bounded per visit by probes/time; on exhaustion hand the AG
	 * back (caller releases AGI + AG through the canonical unlock) and
	 * remember where we were.
	 */
	start_rec = rec.ir_startino;
	for (;;) {
		error = mxfs_dialloc_pick_in_rec(pag, tp, &rec, rs, &offset);
		if (error == 0)
			break;
		if (error != -EAGAIN)
			goto error_cur;
#ifdef __KERNEL__
		if (rs->budget_exhausted) {
			spin_lock(&pag->pag_resv_lock);
			pag->pag_resv_cursor = rec.ir_startino;
			spin_unlock(&pag->pag_resv_lock);
			atomic64_inc(&mxfs_resv_stat_exhaust);
			mxfs_probe_ratelimited(
			    "mxfs: P-DIALLOC-RESV-EXHAUST agno=%u rec=%u probes=%d contended=%d cool=%d demand=%d — visit budget spent on peer-held candidates; AG returned, cursor kept\n",
				pag_agno(pag), rec.ir_startino, rs->probes,
				rs->contended, rs->cool_skips, rs->demand);
			goto error_cur;
		}
		atomic64_inc(&mxfs_resv_stat_recadv);
#endif
		/* advance; wrap once at the end of the finobt */
		error = xfs_btree_increment(cur, 0, &i);
		if (error)
			goto error_cur;
		if (i == 0) {
			error = xfs_inobt_lookup(cur, 0, XFS_LOOKUP_GE, &i);
			if (error)
				goto error_cur;
			if (i == 0) {
				error = -EAGAIN;
				goto error_cur;
			}
		}
		error = xfs_inobt_get_rec(cur, &rec, &i);
		if (error)
			goto error_cur;
		if (XFS_IS_CORRUPT(mp, i != 1)) {
			xfs_btree_mark_sick(cur);
			error = -EFSCORRUPTED;
			goto error_cur;
		}
		if (rec.ir_startino == start_rec) {
			/* full lap: nothing reservable right now */
#ifdef __KERNEL__
			spin_lock(&pag->pag_resv_lock);
			pag->pag_resv_cursor = NULLAGINO;
			spin_unlock(&pag->pag_resv_lock);
			atomic64_inc(&mxfs_resv_stat_exhaust);
			/*
			 * swept is the vote "this lap found no usable candidate",
			 * whatever refused them — a peer holding the number, or
			 * our own cooldown on it.  xfs_dialloc_try_ag answers it
			 * with ONE carve per allocation (mxfs_dialloc_carve_gate);
			 * that bound, not this vote, is what keeps the create's
			 * reservation whole (D-DIALLOC-REPICK-STORM).  Casting the
			 * vote only for peer contention was tried (0.87.23) and
			 * hung the create instead: with the refused number the
			 * AG's sole free inode nothing carved, and the sweep
			 * backed off forever with the parent directory locked.
			 */
			rs->swept = 1;
			mxfs_probe_ratelimited(
			    "mxfs: P-DIALLOC-RESV-SWEPT agno=%u probes=%d contended=%d cool=%d pubpend=%d demand=%d swept=%d — every free inode in this AG is peer-held or cooling; AG returned\n",
				pag_agno(pag), rs->probes, rs->contended,
				rs->cool_skips, rs->pubpend, rs->demand,
				rs->swept);
#endif
			error = -EAGAIN;
			goto error_cur;
		}
	}
#ifdef __KERNEL__
	spin_lock(&pag->pag_resv_lock);
	pag->pag_resv_cursor = NULLAGINO;
	spin_unlock(&pag->pag_resv_lock);
#endif
	ASSERT(offset >= 0);
	ASSERT(offset < XFS_INODES_PER_CHUNK);
	ASSERT((XFS_AGINO_TO_OFFSET(mp, rec.ir_startino) %
				   XFS_INODES_PER_CHUNK) == 0);
	ino = xfs_agino_to_ino(pag, rec.ir_startino + offset);

	/*
	 * (D-0351 containment) phase 1: hand the reserved candidate
	 * back UNMODIFIED — no tree update, transaction still clean — so the
	 * caller can validate its platter image with the cursor and the AGI
	 * released (design-consult: no platter I/O under the AGI/btree nesting).
	 */
	if (pick_only) {
		xfs_btree_del_cursor(cur, XFS_BTREE_NOERROR);
		*inop = ino;
		return 0;
	}

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
	if (rec.ir_freecount) {
		error = xfs_inobt_update(cur, &rec);
	} else {
		error = xfs_btree_delete(cur, &i);
		/* 0.89.9: the allocation-coverage witness — an EXISTING
		 * partial chunk became full (partial→full) */
		if (!error)
			atomic64_inc(&pag->pag_mxfs_wit_fino_del);
	}
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
	mxfs_agifc_mod(pag, agbp, "dialloc_ag", -1);

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

#ifdef __KERNEL__
/*
 * (D-0351 containment, design-consult ruling
 * d0351-dialloc-containment-two-phase).  Phase 1: pick + reserve a
 * candidate under the cursors, trees untouched (pick_only).  Drop the AGI,
 * validate the candidate's platter image (plain LUN read; the pubob store
 * first), re-take the AGI.  A LIVE image is quarantined for the mount and the
 * pick restarts (bounded); a free image makes phase 2 take exactly that inode
 * (rs->validated).  Only the finobt allocator is two-phased: an MXFS volume
 * always carries a finobt (mkfs writes it), so the inobt-only path is never
 * taken in the cluster.  On return *agbpp == NULL means the AGI re-read
 * failed and nothing is held in the transaction.
 */
static int
mxfs_dialloc_two_phase(
	struct xfs_perag	*pag,
	struct xfs_trans	**tpp,
	struct xfs_buf		**agbpp,
	xfs_ino_t		parent,
	xfs_ino_t		*inop,
	struct mxfs_dialloc_resv *rs)
{
	struct xfs_mount	*mp = (*tpp)->t_mountp;
	extern int		mxfs_dialloc_validate;
	int			eio_retry = 0;
	int			error;

	rs->validated = NULLFSINO;
	if (!mp->m_mxfs_dlm || !xfs_has_finobt(mp) ||
	    !READ_ONCE(mxfs_dialloc_validate))
		return xfs_dialloc_ag(pag, *tpp, *agbpp, parent, inop, rs, false);
	/*
	 * THE VALIDATOR IS GATED ON DYNAMIC MEMBERSHIP, WHICH IS NOT THE
	 * QUESTION IT NEEDS ANSWERED.
	 *
	 * Everything below is the D-0351/D-0946 containment: read the picked
	 * candidate's platter home before anything is dirtied, and refuse a
	 * number whose home still carries a live dinode.  It was gated on
	 * mxfs_v5_dlm_is_single_node() alone -- dynamic membership -- so the
	 * sole survivor of a peer's death or departure stops validating at
	 * exactly the moment the departed peer's residue is on the platter and
	 * nobody is left to publish it.  At the same instant
	 * mxfs_ag_inode_owned() opens the departed peer's AGs to this node's
	 * allocator, so the survivor starts picking numbers out of the AGs it
	 * has just stopped checking.
	 *
	 * Nothing is changed here by default.  P951-VALIDATE-OFF-SOLE makes the
	 * unvalidated sole-survivor path VISIBLE (it has never been counted),
	 * and dialloc_validate_sole=1 keeps the validator running for a sole
	 * survivor so a run can say whether it would have refused anything.
	 * A refusal in that arm is the evidence a fix would rest on.
	 */
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		extern int	mxfs_dialloc_validate_sole;
		extern bool	mxfs_v5_dlm_sole_survivor(struct mxfs_v5_dlm *);
		bool		sole = mxfs_v5_dlm_sole_survivor(mp->m_mxfs_dlm);

		if (!sole || !READ_ONCE(mxfs_dialloc_validate_sole)) {
			if (sole) {
				static atomic_t	p951n = ATOMIC_INIT(0);
				int		n = atomic_inc_return(&p951n);

				if (n <= 40)
					mxfs_probe("mxfs: P951-VALIDATE-OFF-SOLE agno=%u n=%d — a SOLE SURVIVOR is picking an inode with the D-0351/D-0946 platter validation OFF, because the gate tests membership NOW instead of whether this volume has ever had another node\n",
						pag_agno(pag), n);
			}
			return xfs_dialloc_ag(pag, *tpp, *agbpp, parent, inop,
					      rs, false);
		}
	}

	for (;;) {
		xfs_ino_t	cand = NULLFSINO;
		int		vrc;

		error = xfs_dialloc_ag(pag, *tpp, *agbpp, parent, &cand, rs,
				       true);
		if (error)
			return error;
		xfs_trans_brelse(*tpp, *agbpp);
		*agbpp = NULL;
		vrc = mxfs_dialloc_validate_candidate(pag, cand, rs);
		error = xfs_ialloc_read_agi(pag, *tpp, 0, agbpp);
		if (error) {
			*agbpp = NULL;
			return error;
		}
		/*
		 * 0.75.45 (D-DIALLOC-TWO-PHASE-AGI-RELEASE-LOCAL-RACER-EMPTY-
		 * FINOBT-SPURIOUS-EFSCORRUPTED-0919): while the AGI was released
		 * for the platter read, a concurrent LOCAL create in this AG may
		 * have taken its last free inode — possibly our validated
		 * candidate.  The AG EX keeps peers out, not our own tasks.  The
		 * finobt is then legitimately empty, and both phase 1 and phase 2
		 * would end in xfs_dialloc_ag_finobt_near, whose near-search
		 * reports 'no record on either side' as corruption: EUCLEAN to
		 * the caller, finobt marked sick, 'run xfs_repair' in the log,
		 * on a healthy filesystem (measured 131 of 3200 creates with four
		 * racers, 0 of 3200 with the two-phase off, 2/tcp 0.75.44).
		 * The caller already knows how to handle an AG with no free
		 * inode: hand it back as swept so it grows a chunk or moves on.
		 */
		if (!pag->pagi_freecount) {
			pr_warn_ratelimited("mxfs: P-DIALLOC-P2-EMPTY agno=%u cand=%llu vrc=%d restarts=%d — a local racer took the AG's last free inode while the AGI was released for validation; AG returned as swept (grow or next AG), no corruption\n",
				pag_agno(pag), (unsigned long long)cand, vrc,
				rs->restarts);
			rs->swept = 1;
			return -EAGAIN;
		}
		if (vrc == 0) {
			rs->validated = cand;
			error = xfs_dialloc_ag(pag, *tpp, *agbpp, parent, inop,
					       rs, false);
			rs->validated = NULLFSINO;
			if (error != -EAGAIN)
				return error;
			/* phase 2 could not take the validated inode: never
			 * fall back to an unvalidated pick — restart phase 1 */
			pr_warn_ratelimited("mxfs: P-DIALLOC-VALIDATED-LOST ino=%llu agno=%u — validated candidate not takeable in phase 2; re-picking\n",
				(unsigned long long)cand, pag_agno(pag));
		} else if (vrc == -EIO) {
			if (eio_retry++ < 1)
				continue;
			mxfs_probe_ratelimited("mxfs: P-DIALLOC-VALIDATE-EIO ino=%llu agno=%u — candidate home unreadable twice; failing the create cleanly\n",
				(unsigned long long)cand, pag_agno(pag));
			return -EIO;
		} else if (vrc == -EBUSY) {
			/*
			 * D-0946 PROGRESS RULE.  Refusing a number whose own free
			 * is unpublished is only half a fix: the inobt says free,
			 * every candidate is refused, and nothing makes the write
			 * happen — the allocation would starve behind work only
			 * this node can do.  After a bounded number of refusals in
			 * one allocation, stop re-picking and drive the write.
			 *
			 * Here is the one place it is safe to do so: the AGI and
			 * the cursors are dropped, the transaction is clean, and
			 * the AG EX is held — which is not a hazard but the very
			 * thing that sanctions a publication write.  Driving it
			 * with the AGI held would deadlock against the publisher.
			 */
			if (rs->pubpend >= MXFS_PUBPEND_DRIVE_AT &&
			    rs->pubdrives < MXFS_PUBPEND_DRIVE_MAX) {
				rs->pubdrives++;
				mxfs_pubob_drive_publication(mp, cand,
							     MXFS_PUBPEND_DRIVE_MS);
			}
		}
		if (++rs->restarts > 64) {
			/*
			 * Distinguish the two exhaustions: a storm of LIVE
			 * platter images is a repair-needing corruption verdict,
			 * while a storm of unpublished-free refusals is this node
			 * owing itself writes.  The second must not be reported as
			 * corruption — hand it back as -EAGAIN so the caller's
			 * sweep backs off and re-sweeps (never ENOSPC, never
			 * -EUCLEAN), with the publication drive already attempted.
			 */
			if (rs->pubpend && !rs->disklive && !rs->quarantined) {
				pr_warn("mxfs: P946-DIALLOC-PUBPEND-STORM agno=%u restarts=%d pubpend=%d drives=%d — every candidate in this AG is a number whose own free this node has not published; backing off, no corruption verdict\n",
					pag_agno(pag), rs->restarts, rs->pubpend,
					rs->pubdrives);
				/*
				 * swept: the AG has no usable candidate for this
				 * allocation, and xfs_dialloc_try_ag may answer with
				 * a fresh chunk — ONCE.  Measured before the carve
				 * gate (D-DIALLOC-REPICK-STORM, 0.87.22): this vote
				 * re-entered the carve arm on every re-sweep of one
				 * create with the same transaction; 24 chunks were
				 * carved against a reservation that pays for one,
				 * and xfs_trans_mod_sb shut the filesystem down at
				 * blk_res=5 blk_res_used=8.  The bound lives in
				 * mxfs_dialloc_carve_gate, not here: withholding the
				 * vote hangs a create whose only free numbers are
				 * refused for good.
				 */
				rs->swept = 1;
				return -EAGAIN;
			}
			pr_err("mxfs: P-DIALLOC-DISKLIVE-STORM agno=%u restarts=%d pubpend=%d — more than 64 rejected candidates in one allocation; failing the create cleanly\n",
				pag_agno(pag), rs->restarts, rs->pubpend);
			return -EUCLEAN;
		}
		rs->probes = 0;
		rs->budget_exhausted = 0;
		rs->visit_t0 = ktime_get_ns();
	}
}
#endif

/*
 * D-DIALLOC-REPICK-STORM: ONE INODE-CHUNK CARVE PER xfs_dialloc CALL.
 *
 * The caller's transaction reserved XFS_IALLOC_SPACE_RES — space for exactly
 * one chunk — and the rest of its reservation belongs to the directory entry
 * and parent pointer the create still has to write; the allocator cannot see
 * that split, so the only honest bound is the count.  Upstream holds this
 * implicitly (after a carve xfs_dialloc_ag cannot fail with -EAGAIN); MXFS's
 * candidate refusals broke it, and xfs_trans_roll carries only the remainder
 * forward, so every extra carve spent 8 blocks of somebody else's reservation
 * until xfs_trans_mod_sb shut the filesystem down.  Measured 0.87.22: 24
 * carves in one create, blk_res 189 -> 5, then the shutdown.
 *
 * Returns true when this call may carve now; false hands the AG back as
 * -EAGAIN so the sweep backs off the way it does for any other transient
 * refusal, with nothing dirtied.  The credit is spent by the caller only once
 * xfs_ialloc_ag_alloc has succeeded (before the roll): a carve that found no
 * room allocated nothing and leaves the credit for the next AG, while a
 * carve that landed is spent whether or not its roll then fails.
 * P-DIALLOC-GROW-RES prints every carve's reservation state (bounded) so a
 * lap can show the bound holding.
 */
static bool
mxfs_dialloc_carve_gate(
	struct xfs_perag	*pag,
	struct xfs_trans	*tp,
	struct mxfs_dialloc_resv *rs,
	const char		*arm)
{
#ifdef __KERNEL__
	static atomic_t		n_probe = ATOMIC_INIT(0);
	static atomic_t		n_bound = ATOMIC_INIT(0);
	unsigned int		left = tp->t_blk_res > tp->t_blk_res_used ?
				       tp->t_blk_res - tp->t_blk_res_used : 0;
	int			n;

	if (rs->grows >= 1) {
		n = atomic_inc_return(&n_bound);
		if (n <= 32 || (n % 1000) == 0)
			mxfs_probe("mxfs: P-DIALLOC-CARVE-BOUND agno=%u arm=%s grows=%d blk_res=%u blk_res_used=%u left=%u restarts=%d pubpend=%d contended=%d cool=%d comm=%s — this allocation already carved the one chunk its reservation pays for; AG handed back, no carve\n",
				pag_agno(pag), arm, rs->grows, tp->t_blk_res,
				tp->t_blk_res_used, left, rs->restarts,
				rs->pubpend, rs->contended, rs->cool_skips,
				current->comm);
		return false;
	}
	n = atomic_inc_return(&n_probe);
	if (left < M_IGEO(tp->t_mountp)->ialloc_blks || n <= 8 ||
	    (n % 1000) == 0)
		mxfs_probe("mxfs: P-DIALLOC-GROW-RES agno=%u arm=%s grows=%d blk_res=%u blk_res_used=%u left=%u ialloc_blks=%u restarts=%d pubpend=%d comm=%s%s\n",
			pag_agno(pag), arm, rs->grows + 1, tp->t_blk_res,
			tp->t_blk_res_used, left,
			M_IGEO(tp->t_mountp)->ialloc_blks, rs->restarts,
			rs->pubpend, current->comm,
			left < M_IGEO(tp->t_mountp)->ialloc_blks ?
			" — the reservation left cannot pay for this chunk" : "");
#endif
	return true;
}

static int
xfs_dialloc_try_ag(
	struct xfs_perag	*pag,
	struct xfs_trans	**tpp,
	xfs_ino_t		parent,
	xfs_ino_t		*new_ino,
	bool			ok_alloc,
	int			flags,
	struct mxfs_dialloc_resv *rs)
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
	mxfs_agifc_audit(pag, *tpp, agbp, "try_ag-entry");

	if (!pag->pagi_freecount) {
		if (!ok_alloc) {
			error = -EAGAIN;
			goto out_release;
		}

		if (!mxfs_dialloc_carve_gate(pag, *tpp, rs, "empty")) {
			error = -EAGAIN;
			goto out_release;
		}
		error = xfs_ialloc_ag_alloc(pag, *tpp, agbp);
		if (error < 0)
			goto out_release;
		rs->grows++;

		/*
		 * We successfully allocated space for an inode cluster in this
		 * AG.  Roll the transaction so that we can allocate one of the
		 * new inodes.
		 */
		ASSERT(pag->pagi_freecount > 0);
		error = xfs_dialloc_roll(tpp, agbp);
		if (error)
			goto out_release;
		mxfs_agifc_audit(pag, *tpp, agbp, "grow-post");
	}

	/* Allocate an inode in the found AG */
#ifdef __KERNEL__
	rs->probes = 0;			/* 0.23.0: per-visit probe budget */
	rs->budget_exhausted = 0;
	rs->visit_t0 = ktime_get_ns();
	/*
	 * swept is THIS visit's vote, never an earlier AG's: a lap that
	 * left it set in one AG and a pick that returned -EAGAIN without
	 * voting in the next would otherwise carve in the second AG on the
	 * first AG's evidence.
	 */
	rs->swept = 0;
	error = mxfs_dialloc_two_phase(pag, tpp, &agbp, parent, &ino, rs);
	if (!agbp)
		goto out_dlm;		/* AGI re-read failed: nothing held */
#else
	error = xfs_dialloc_ag(pag, *tpp, agbp, parent, &ino, rs, false);
#endif
#ifdef __KERNEL__
	/*
	 * 0.23.1: every free inode in this AG is held by a peer
	 * (its just-freed, noino-cached inodes) but the AG itself has room:
	 * GROW it — allocate a fresh chunk (unheld inode numbers) and retry
	 * once — instead of returning -EAGAIN and letting the sweep spill
	 * this node's creates into other nodes' AGs.  Same sequence as the
	 * pagi_freecount==0 branch above; the transaction is still clean.
	 */
	if (error == -EAGAIN && rs->swept && ok_alloc && !xfs_is_shutdown(mp) &&
	    mxfs_dialloc_carve_gate(pag, *tpp, rs, "swept")) {
		rs->swept = 0;
		error = xfs_ialloc_ag_alloc(pag, *tpp, agbp);
		if (error < 0)
			goto out_release;
		rs->grows++;
		error = xfs_dialloc_roll(tpp, agbp);
		if (error)
			goto out_release;
		atomic64_inc(&mxfs_resv_stat_grow);
		mxfs_probe_ratelimited("mxfs: P-DIALLOC-RESV-GROW agno=%u — all free inodes peer-held; grew a fresh chunk in the owned AG instead of spilling\n",
			pag_agno(pag));
		rs->probes = 0;
		rs->budget_exhausted = 0;
		rs->visit_t0 = ktime_get_ns();
		/* the pick may still land on an old record: validate again */
		error = mxfs_dialloc_two_phase(pag, tpp, &agbp, parent, &ino, rs);
		if (!agbp)
			goto out_dlm;
	}
	/* clean containment failures — the transaction is untouched,
	 * release the AGI + AG now (same contract as the -EAGAIN skip) */
	if (error == -EUCLEAN || error == -EIO)
		goto out_release;
#endif
	if (!error)
		mxfs_agifc_audit(pag, *tpp, agbp, "alloc-post");
	if (!error)
		*new_ino = ino;
	/*
	 * INSTRUMENTED DETECTOR (P-IALLOC-DBLALLOC): we just
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
			mxfs_probe_ratelimited(
				"mxfs: P-IALLOC-DBLALLOC ino=%llu agno=%u carved-FREE-from-inobt but coherent-disk mode=0%o gen=%u is LIVE — inobt stale at alloc (same-chunk double-alloc)\n",
				(unsigned long long)ino,
				(unsigned)XFS_INO_TO_AGNO(mp, ino),
				(unsigned)cmode, cgen);
	}
	}
	/*
	 * MXFS (474 leg A unwind): a reserve-contended skip
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
	 * MXFS node-affine regular-file allocation (architectural fix
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
	/*
	 * 0.23.1: fewer AGs than configured nodes (the agcount<nodes
	 * geometry, e.g. 25 AGs / 32 slots).  With L > agcount the slots >=
	 * agcount owned NOTHING and ran every allocation in the RELAXED pass,
	 * wandering into any AG that momentarily returned -EAGAIN — seeding
	 * cross-node sharing of nominally exclusive AGs (measured lap 5: six
	 * exclusive nodes allocating in test7's AG 16 -> the AGI unlinked-
	 * bucket cross-node shutdown).  Fold the stride to agcount so the
	 * ownership map is the same deterministic slot%agcount affinity that
	 * xfs_dialloc_pick_ag uses: every AG has 1-2 fixed owners, nobody
	 * floats.  Unchanged when agcount >= L (the supported geometry).
	 */
	if (mp->m_maxagi && L > mp->m_maxagi)
		L = mp->m_maxagi;
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
	 * MXFS (design-consult ruling): bounded jittered re-sweeps before
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
	struct mxfs_dialloc_resv rs = { 0 };

	rs.validated = NULLFSINO;
	/*
	 * MXFS 0.75.31 (D-AGMASK-QUARANTINE-DIR-CREATE-EIO-WHEN-INODE-ROTOR-
	 * PICKS-QUARANTINED-AG-0914): under a filesystem-wide quarantine no
	 * AG can host a new inode; answer EIO here rather than sweep every AG
	 * into the gate's refusal and report the sweep as ENOSPC.
	 */
	if (unlikely(READ_ONCE(mp->m_mxfs_quar_fswide)))
		return -EIO;
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
		/*
		 * MXFS 0.75.31 (D-0914): an AG inside a quarantined victim
		 * domain is unusable for the life of the mount.  Measured on
		 * the 2-node TCP rig (AG-mask verdict quarantining AG 1, AG 0
		 * spared): the sole survivor's directory rotor pointed at AG 1,
		 * xfs_dialloc_try_ag's AG acquire was refused by the quarantine
		 * gate (P240-QUAR-AG-EIO), and the EIO — not -EAGAIN — ended
		 * the sweep, so a mkdir in the untouched root failed EIO once
		 * per rotor lap.  Skip such an AG the way a full one is skipped;
		 * the gate stays as the last defence for an explicit in-domain
		 * object.
		 */
		if (unlikely(mxfs_quarantine_covers_agno(mp, pag_agno(pag))))
			continue;
		if (xfs_dialloc_good_ag(pag, *tpp, mode, flags, ok_alloc)) {
			error = xfs_dialloc_try_ag(pag, tpp, parent,
					&ino, ok_alloc, flags, &rs);
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
#ifdef __KERNEL__
		/*
		 * MXFS / 0.23.0-0.23.1 (design-consult ruling): a full
		 * failed sweep that SAW contention (peer-held or cooling
		 * candidates, a spent visit budget, a swept AG) is transient
		 * cluster contention, not exhaustion — it must never become
		 * ENOSPC and (0.23.1) it must never RELAX the ownership
		 * partition either: wandering into other nodes' AGs turned
		 * exclusive AGs into shared ones (measured lap 5).  Back off
		 * OUTSIDE every lock (nothing is held here): randomized
		 * 5-20 ms, doubling per failed sweep, capped at 200 ms; escalate
		 * to DEMAND so each later probe leaves a sticky revoke on the
		 * holder's slot — a lazily-cached/noino holder is then told to
		 * let go, which bounds the loop by the holder's release fence.
		 * A sweep with ZERO contention observed is a genuinely full
		 * partition: relax ownership, then ENOSPC as before.
		 */
		if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)
		    && (rs.contended || rs.cool_skips || rs.budget_exhausted ||
			rs.swept || rs.pubpend)) {
			unsigned int shift = min(resv_sweeps, 5);
			unsigned int base = 5u << shift;	/* 5..160 ms */
			unsigned int ms = min(base, 200u) +
				get_random_u32_below(min(base, 200u));

			resv_sweeps++;
			rs.demand = 1;
			atomic64_inc(&mxfs_resv_stat_sweeps);
			atomic64_add(ms, &mxfs_resv_stat_backoff_ms);
			if (resv_sweeps == 1 || (resv_sweeps & 15) == 0)
				mxfs_probe_ratelimited(
				    "mxfs: P-DIALLOC-SWEEP-RETRY sweep=%d start_agno=%u contended=%d cool=%d exhausted=%d swept=%d pubpend=%d relaxed=%d backoff_ms=%u — all AG passes came up empty under cluster contention; re-sweeping with DEMAND, never ENOSPC\n",
					resv_sweeps, start_agno, rs.contended,
					rs.cool_skips, rs.budget_exhausted,
					rs.swept, rs.pubpend,
					partition_relaxed ? 1 : 0, ms);
			msleep(ms);
			rs.contended = 0;
			rs.cool_skips = 0;
			rs.budget_exhausted = 0;
			rs.swept = 0;
			rs.pubpend = 0;
			rs.pubdrives = 0;
			flags = XFS_ALLOC_FLAG_TRYLOCK;
			if (low_space)
				ok_alloc = false;
			if (xfs_is_shutdown(mp))
				return -EFSCORRUPTED;
			goto retry;
		}
#endif
		if (!partition_relaxed) {
			/*
			 * Owned partition exhausted (TRYLOCK + blocking passes
			 * found nothing in our AG stride, with no cluster
			 * contention observed).  Relax ownership and scan ALL
			 * AGs to avoid a false ENOSPC.  Rare — only when this
			 * node's whole stride is genuinely full.
			 */
			partition_relaxed = true;
			/* 0.89.10: the allocation-coverage witness records that
			 * the partition was dropped (xfs_mount.h) */
			atomic64_inc(&mp->m_mxfs_wit_relaxed);
			flags = XFS_ALLOC_FLAG_TRYLOCK;
			goto retry;
		}
#ifdef __KERNEL__
		/* (D-0351 containment, design-consult): every remaining free
		 * inode is a quarantined DISK-LIVE number — that is corruption
		 * needing repair, never ENOSPC.  Clean failure, no shutdown. */
		if (rs.quarantined || rs.disklive) {
			pr_err("mxfs: P-DIALLOC-ALL-QUARANTINED start_agno=%u quarantined=%d disklive=%d — no allocatable inode left that is not a DISK-LIVE quarantine member; create fails -EUCLEAN (repair needed)\n",
				start_agno, rs.quarantined, rs.disklive);
			return -EUCLEAN;
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
		/* (vergate mixed_build, fresh 4-AG loop fs): the very
		 * first create after a clean mount was rejected here for ino
		 * 131 with parent 128.  Print every input of the verdict so the
		 * rejecting sub-check is named, not guessed. */
		{
			xfs_agnumber_t	vagno = XFS_INO_TO_AGNO(mp, ino);
			xfs_agino_t	vagino = XFS_INO_TO_AGINO(mp, ino);
			xfs_agino_t	vfirst = 0, vlast = 0;

			if (vagno < mp->m_sb.sb_agcount)
				xfs_agino_range(mp, vagno, &vfirst, &vlast);
			xfs_alert(mp, "P-DIALLOC-VERIFY ino=%llu parent=%llu agno=%u agino=%u agcount=%u agino_range=[%u,%u] roundtrip=%llu sb_inum=%d verify_ino=%d rbmino=%llu rsumino=%llu has_quota=%d uquotino=%llu gquotino=%llu pquotino=%llu agblocks=%u agblklog=%u inopblog=%u",
				(unsigned long long)ino, (unsigned long long)parent,
				vagno, vagino, mp->m_sb.sb_agcount, vfirst, vlast,
				(unsigned long long)XFS_AGINO_TO_INO(mp, vagno, vagino),
				xfs_is_sb_inum(mp, ino) ? 1 : 0,
				xfs_verify_ino(mp, ino) ? 1 : 0,
				(unsigned long long)mp->m_sb.sb_rbmino,
				(unsigned long long)mp->m_sb.sb_rsumino,
				xfs_has_quota(mp) ? 1 : 0,
				(unsigned long long)mp->m_sb.sb_uquotino,
				(unsigned long long)mp->m_sb.sb_gquotino,
				(unsigned long long)mp->m_sb.sb_pquotino,
				mp->m_sb.sb_agblocks, mp->m_sb.sb_agblklog,
				mp->m_sb.sb_inopblog);
		}
		xfs_agno_mark_sick(mp, XFS_INO_TO_AGNO(mp, ino),
				XFS_SICK_AG_INOBT);
		return -EFSCORRUPTED;
	}

	*new_ino = ino;
	/* gate this per-allocation diagnostic (fires on every
	 * create) behind mxfs.instr — default off for perf. */
	{
		extern int mxfs_instr_enabled;
		if (unlikely(mxfs_instr_enabled))
			mxfs_pal_log(MXFS_LOG_DEBUG,
				"mxfs: P9-INSTR dialloc PICK ino=%llu agno=%u parent=%llu",
				(unsigned long long)ino,
				(unsigned int)XFS_INO_TO_AGNO(mp, ino),
				(unsigned long long)parent);
	}
	/* ALWAYS-ON double-allocation tracer.  P-RELOAD-TYPEFLIP
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
			mxfs_pal_log(MXFS_LOG_DEBUG,
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
 * MAY THIS MOUNT DELETE A FULLY-FREE INODE CHUNK AND RETURN ITS BLOCKS?
 *
 * Upstream always deletes.  MXFS must not on a clustered volume: the blocks
 * re-enter the AG free pool, a directory reallocates them, and its data lands
 * on top of an inode cluster some node still believes in — the cluster then
 * fails its verifier on the next read and the filesystem shuts down.  That is
 * not a hypothetical: a create was killed reading `58 44 44 33` (XDD3, a dir3
 * data block carrying its own address) at the home of an inode the allocator
 * had just handed out.
 *
 * The test used to be "is this mount single-node right now", and
 * mxfs_v5_dlm_is_single_node() is DYNAMIC MEMBERSHIP — the sole survivor of a
 * peer's death or departure answers yes, and so resumed deleting chunks
 * exactly when a departed peer's view of them was least trustworthy.  Measured
 * on 0.75.124, in ONE lap: 187 chunks deleted and their blocks returned to the
 * free pool by a sole survivor, essentially every chunk a 12000-file workload
 * had carved (187 x P103-CHUNKFREE-SOLE, unbudgeted).
 *
 * The second attempt asked "has this volume had another node DURING THIS
 * MOUNT" (mxfs_v5_dlm_sole_survivor()).  That closed the within-mount case and
 * was verified on the rig, and it is still the wrong question — the scope is a
 * mount and the residue is on a volume.  See the body for why no membership
 * predicate can answer this one and what the guard does instead.
 */
static bool
mxfs_inode_chunk_may_delete(struct xfs_mount *mp)
{
	/*
	 * AND THEN THE MEMBERSHIP TEST WENT AWAY ENTIRELY, BECAUSE NO FORM OF
	 * IT CAN ANSWER THE QUESTION.
	 *
	 * The first fix moved this from mxfs_v5_dlm_is_single_node() ("am I
	 * alone right now") to mxfs_v5_dlm_sole_survivor() ("has this mount had
	 * a peer, and am I alone now"), which closed the within-mount case and
	 * was verified on the rig.  It is still not enough.  sole_survivor()
	 * rests on ever_multi, a PER-MOUNT in-core bool with no durable backing
	 * (dlm/v5_mount.c:536, assigned in exactly one place at :17338).  So the
	 * moment every node unmounts and one mounts again alone, ever_multi is
	 * false, the predicate is false, and this guard is back to upstream
	 * behaviour on a volume whose platter demonstrably carries a second
	 * writer's residue.  Nothing was repaired in the interval; only the
	 * in-core flag that remembered the peer was discarded.
	 *
	 * The durable fact the guard actually needs -- "has any other node ever
	 * written this volume" -- is not recorded anywhere that survives a clean
	 * shutdown.  Both candidate sources are cleared on the way out: a
	 * departing node's disklock slot is zeroed, and the committed MEPOCH
	 * record whose member_mask names its peers lives in that same per-node
	 * heartbeat sector.  After a full clean shutdown the volume looks, to
	 * every structure on it, exactly like one that has never been clustered.
	 *
	 * So the question is unanswerable and the guard must fail closed.  This
	 * is a shared-LUN filesystem: another node may mount at any moment, and
	 * the only proof of exclusivity that would justify the optimization
	 * cannot be obtained.  A clustered volume therefore KEEPS fully-free
	 * inode chunks, always.
	 *
	 * What that costs, precisely, and why it is the right side to be wrong
	 * on: the chunk's blocks stay committed to inode space rather than
	 * returning to the AG free pool.  Its inodes stay free and reusable, so
	 * no inode is leaked and a later create reuses them -- it is the same
	 * trade every multi-node mount already makes, now made unconditionally.
	 * The failure it prevents is not a space inefficiency: it is a directory
	 * data block allocated on top of a live inode cluster, the verifier
	 * failing on the next read, and the filesystem shutting down.  Measured,
	 * not hypothetical -- 187 chunks freed by a sole survivor in one lap, and
	 * a create killed reading `58 44 44 33` (XDD3, a dir3 data block carrying
	 * its own address) at the home of an inode the allocator had just handed
	 * out.
	 *
	 * AND THE COST IS BOUNDED BY THE FILESYSTEM'S OWN GEOMETRY, which is the
	 * argument that makes "never delete" safe rather than merely conservative.
	 * Inode space cannot grow without limit: xfs_ialloc_ag_alloc() refuses to
	 * carve a new chunk once icount + ialloc_inos > igeo->maxicount, and
	 * maxicount is sb_imax_pct of sb_dblocks (xfs_ialloc.c:5184) -- 25% by
	 * default, which on this rig's 50 G volume is 25991808 inodes over
	 * 3248976 of its 12995925 blocks, exactly 25.00%.  So the worst case is
	 * a quarter of the volume committed to inode space, which is the ceiling
	 * upstream XFS already sets and every multi-node mount already lives
	 * with.
	 *
	 * It also CONVERGES rather than diverging: a kept chunk's inodes stay
	 * free, so the allocator reuses them instead of carving more.  Churn
	 * re-fills the chunks it emptied.  What it does NOT do is return their
	 * blocks to the data pool, and that is the whole trade.
	 *
	 * P103-CHUNKFREE-SOLE must now be UNREACHABLE on any clustered mount.
	 * If it ever prints again, this predicate has regressed.
	 */
	return !mp->m_mxfs_dlm;		/* only a non-clustered mount may delete */
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

	/* 0.89.9: the allocation-coverage witness — one chunk's blocks are
	 * handed to the deferred free below (a failure there cancels a dirty
	 * transaction, which shuts the filesystem down) */
	atomic64_inc(&pag->pag_mxfs_wit_releases);

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

	ASSERT(agi->agi_magicnum == cpu_to_be32(MXFS_AGI_MAGIC));
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
	 * P-DIFREE-DBL (instrumented probe): in multi-node mode, detect the inobt
	 * double-free (the inode being freed is ALREADY marked free in this
	 * node's inobt record).  Upstream this is only an ASSERT (no-op in
	 * production) and then blindly ++freecount, corrupting agi_freecount
	 * and tripping EFSCORRUPTED in finobt cross-check / check_agi_freecount.
	 * Log it so we can confirm this is the xfs_inactive_ifree -117 root.
	 */
	if (rec.ir_free & XFS_INOBT_MASK(off)) {
		struct xfs_agi *dbg_agi = agbp->b_addr;
		mxfs_probe_ratelimited(
			"mxfs: P-DIFREE-DBL agno=%u agino=%u startino=%u off=%d ir_free=0x%llx freecount=%d agi_freecount=%u multinode=%d — inode ALREADY free in inobt (double-free)\n",
			(unsigned)pag_agno(pag), (unsigned)agino,
			(unsigned)rec.ir_startino, off,
			(unsigned long long)rec.ir_free, (int)rec.ir_freecount,
			(unsigned)be32_to_cpu(dbg_agi->agi_freecount),
			(int)(mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)));
		/*
		 * (round-5 ino 134 autopsy): in multi-node
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
	 * — INODE-CHUNK-KEEP in multi-node mode (ikeep
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
	    mxfs_inode_chunk_may_delete(mp)) {
		/*
		 * instrumented DISCRIMINATOR (P103-CHUNKFREE): a fully-free
		 * inode chunk is being deleted and its blocks deferred-freed.
		 * If a peer concurrently drove the same chunk all-free (stale
		 * in-core inobt rec), both nodes free the same chunk blocks =>
		 * bnobt double-free (xfs_alloc.c:2244).  Log the chunk's start
		 * block + len so it can be correlated against the FREE-AG-EXTENT
		 * -FAIL bno at the shutdown.  (It said "multi-node only" for its
		 * whole life, which is what made it unreachable — see below.)
		 */
		/*
		 * (D-0948): THIS PROBE WAS UNREACHABLE FOR ITS WHOLE
		 * LIFE, AND THAT IS WHY THIS PATH HAS NEVER BEEN MEASURED.
		 *
		 * The branch it sits in requires NOT-multi-node (see the guard
		 * above); the probe then asked for multi-node before printing.
		 * The two conditions are complements, so it could never fire.
		 * Every chunk deletion this mount has ever done was silent.
		 *
		 * It matters now because is_single_node() is DYNAMIC MEMBERSHIP,
		 * not configuration: a two-node cluster whose peer dies or
		 * departs becomes single-node, and this branch then resumes the
		 * upstream behaviour the guard exists to prevent — deleting a
		 * fully-free inode chunk and returning its blocks to the AG free
		 * pool, where a directory can immediately reallocate them.  The
		 * guard's own comment above names the consequence: dir data
		 * written over an inode cluster, failing the cluster's verifier
		 * on the next read.  That is D-0948's captured chain exactly.
		 *
		 * So print on EVERY deletion on a clustered mount, and say
		 * whether this node is a SOLE SURVIVOR — single-node now, but
		 * multi-node earlier in this mount — because that is the case
		 * the keep-the-chunk guard was written for and does not cover.
		 */
		if (pag_mount(pag)->m_mxfs_dlm) {
			extern bool mxfs_v5_dlm_sole_survivor(
					struct mxfs_v5_dlm *);
			struct xfs_agi *dbg_agi = agbp->b_addr;
			bool sole = mxfs_v5_dlm_sole_survivor(
					pag_mount(pag)->m_mxfs_dlm);

			if (sole)
				xfs_alert(mp,
"MXFS: P103-CHUNKFREE-SOLE agno=%u chunk_agbno=%u ialloc_blks=%u startino=%u — a fully-free inode chunk is being DELETED and its blocks returned to the AG free pool by a SOLE SURVIVOR (single-node now, multi-node earlier this mount). Those blocks can be reallocated to directory data while a peer's cached or replayable state still treats them as an inode chunk",
					(unsigned)pag_agno(pag),
					(unsigned)XFS_AGINO_TO_AGBNO(mp, rec.ir_startino),
					(unsigned)M_IGEO(mp)->ialloc_blks,
					(unsigned)rec.ir_startino);
			mxfs_probe_ratelimited(
				"mxfs: P103-CHUNKFREE sole=%d agno=%u chunk_agbno=%u ialloc_blks=%u startino=%u freecount=%d agi_freecount=%u pagi_freecount=%u agi_count=%u holemask=0x%x\n",
				sole ? 1 : 0,
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
		mxfs_agifc_mod(pag, agbp, "difree_inobt", 1);
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
		/* 0.89.9: the allocation-coverage witness — an EXISTING full
		 * chunk gained a free inode (full→partial) */
		atomic64_inc(&pag->pag_mxfs_wit_fino_ins);

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
		/* (D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372): the last
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
	 * — keep the finobt record in sync with the
	 * INODE-CHUNK-KEEP gate in xfs_difree_inobt: in multi-node mode the
	 * chunk is never deleted from the inobt, so the all-free finobt record
	 * must be retained (updated) rather than deleted.
	 */
	if (rec.ir_free == XFS_INOBT_ALL_FREE &&
	    mp->m_sb.sb_inopblock <= XFS_INODES_PER_CHUNK &&
	    mxfs_inode_chunk_may_delete(mp)) {
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
	mxfs_agifc_audit(pag, tp, agbp, "difree-entry");

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
	mxfs_agifc_audit(pag, tp, agbp, "difree-post");

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
	    rec.ir_startino + M_IGEO(mp)->ialloc_inos <= agino) {
		if (flags & XFS_IGET_UNTRUSTED)
			mxfs_probe_ratelimited(
				"mxfs: P-IMAP-UNTRUSTED-NOREC agno=%u agino=%u rec_start=%u — untrusted iget: inobt (read unlocked) has no chunk for it\n",
				pag_agno(pag), agino, rec.ir_startino);
		return -EINVAL;
	}

	/*
	 * for untrusted inodes check it is allocated first
	 *
	 * on MXFS this inobt read is NOT under the AG DLM lock, so a
	 * peer's allocation of the number is invisible here until this node
	 * next takes the AG and refreshes the AGI/inobt buffers.  Name the
	 * refusal: a validated on-disk reference (dir-sharding manifest,
	 * handle, bulkstat) that lands here is a coherency question, not a
	 * garbage number.
	 */
	if ((flags & XFS_IGET_UNTRUSTED) &&
	    (rec.ir_free & XFS_INOBT_MASK(agino - rec.ir_startino))) {
		mxfs_probe_ratelimited(
			"mxfs: P-IMAP-UNTRUSTED-FREE agno=%u agino=%u rec_start=%u free=0x%llx freecount=%u — untrusted iget: inobt (read unlocked) says free\n",
			pag_agno(pag), agino, rec.ir_startino,
			(unsigned long long)rec.ir_free, rec.ir_freecount);
		return -EINVAL;
	}

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

	ASSERT(agi->agi_magicnum == cpu_to_be32(MXFS_AGI_MAGIC));
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
/* AGI-CRC diagnostic: 0=off. When 1, every AGI write logs its
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
	mxfs_probe("mxfs: P30-AGI-%s daddr=%lld stored_crc=0x%08x fp=0x%08x seqno=%u len=%u count=%u free=%u newino=0x%llx lsn=0x%llx comm=%s realns=%llu\n",
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
		/* AGI CRC read failure — the dir_reuse 8/tcp shutdown.
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
	.magic = { cpu_to_be32(MXFS_AGI_MAGIC), cpu_to_be32(MXFS_AGI_MAGIC) },
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

	/* FUA-re-read a stale cached AGI (inobt roots / free-inode
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
	 * tenure is stamped at MODIFY time now (mxfs_ag_meta_track),
	 * not at read time.  The iunlink INSERT that logs the AGI stamps it
	 * current and keeps the committed unlinked-list head tenure-guarded
	 * (preserves the AGI fix), while a read-only AGI stays
	 * prior-tenure so a stale cache-hit is refreshed via the gen-based
	 * cold-read rather than re-stamped this-node-authoritative.
	 */
	if (tp)
		xfs_trans_buf_set_type(tp, *agibpp, XFS_BLFT_AGI_BUF);

	/*
	 * MXFS (D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399,
	 * in-core arm): a fresh AG-DLM tenure clears XFS_AGSTATE_AGI_INIT so
	 * the in-core summary is rebuilt from the re-read AGI — but upstream
	 * rebuilds it only in xfs_ialloc_read_agi, while xfs_iunlink,
	 * xfs_iunlink_remove and xfs_difree read the AGI through THIS function.
	 * When one of those is the tenure's first AGI user, pagi_freecount
	 * stays at the previous tenure's value (measured E4/E5 on 0.23.11:
	 * 39-41 P-AGIFC-MISMATCH per run, every one agi==ibt==fin with pagi
	 * off by the peer's net delta, agi_btenure=0 = first read of the
	 * tenure; xfs_difree then bumps the stale base) until the next
	 * xfs_ialloc_read_agi rebuilds it.  Rebuild it on every first read
	 * instead: every AGI reader then sees a summary consistent with the
	 * buffer it holds, and the audit has no lazy-init window to report.
	 */
	if (!xfs_perag_initialised_agi(pag)) {
		struct xfs_agi	*agi = (*agibpp)->b_addr;

		pag->pagi_freecount = be32_to_cpu(agi->agi_freecount);
		pag->pagi_count = be32_to_cpu(agi->agi_count);
		set_bit(XFS_AGSTATE_AGI_INIT, &pag->pag_opstate);
	}

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
