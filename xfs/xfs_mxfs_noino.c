// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- BASTs for inodes not in core
 */
#define MXFS_TU_ID 18	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

static int mxfs_noino_agwait_inflight( struct xfs_mount *mp, xfs_agnumber_t agno);

static DEFINE_HASHTABLE(mxfs_noino_inflight_ht, 8);
static DEFINE_SPINLOCK(mxfs_noino_inflight_lock);

/*
 * Returns true if (mp,ino) was newly inserted (caller should queue/perform the
 * release); false if a release for this inode is already in flight (drop this
 * BAST — an in-flight work will handle the current slot state, or the peer
 * re-BASTs after it completes).  On alloc failure returns true (degrade to
 * no-dedup for this BAST rather than drop it).
 */
bool
mxfs_noino_inflight_try_add(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_noino_inflight *e;
	unsigned long flags;

	spin_lock_irqsave(&mxfs_noino_inflight_lock, flags);
	hash_for_each_possible(mxfs_noino_inflight_ht, e, hnode, ino) {
		if (e->mp == mp && e->ino == ino) {
			spin_unlock_irqrestore(&mxfs_noino_inflight_lock, flags);
			return false;
		}
	}
	e = kmalloc(sizeof(*e), GFP_ATOMIC);
	if (e) {
		e->mp = mp;
		e->ino = ino;
		hash_add(mxfs_noino_inflight_ht, &e->hnode, ino);
	}
	spin_unlock_irqrestore(&mxfs_noino_inflight_lock, flags);
	return true;
}

void
mxfs_noino_inflight_remove(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_noino_inflight *e;
	unsigned long flags;

	spin_lock_irqsave(&mxfs_noino_inflight_lock, flags);
	hash_for_each_possible(mxfs_noino_inflight_ht, e, hnode, ino) {
		if (e->mp == mp && e->ino == ino) {
			hash_del(&e->hnode);
			spin_unlock_irqrestore(&mxfs_noino_inflight_lock, flags);
			kfree(e);
			return;
		}
	}
	spin_unlock_irqrestore(&mxfs_noino_inflight_lock, flags);
}

/* is a no-inode async release in flight for (mp,ino)?
 * Used by the slow-path acquire to serialize a FRESH local tenure behind
 * a pending release of the PRIOR tenure — otherwise the release's final
 * CAS strips the fresh grant's slot bit (the mkdir-storm double-EX root;
 * see mxfs_noino_bast_work.rel_gen comment). */
bool
mxfs_noino_inflight_contains(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_noino_inflight *e;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&mxfs_noino_inflight_lock, flags);
	hash_for_each_possible(mxfs_noino_inflight_ht, e, hnode, ino) {
		if (e->mp == mp && e->ino == ino) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&mxfs_noino_inflight_lock, flags);
	return found;
}

/*
 * coalesced release-side device flush.  Equivalent to
 * blkdev_issue_flush(bdev) for the caller (its already-submitted writes are on
 * the platter when this returns) but concurrent callers share one device flush.
 * Correctness: a release takes a ticket AFTER its writes are submitted, then
 * either observes that a completed flush already covered its ticket, or issues a
 * flush itself.  blkdev_issue_flush persists everything submitted before it
 * returns, so the ticket it covers (snapshot, taken before issuing) is a safe
 * lower bound.  May over-flush (never under-flush) under races.
 */
void
mxfs_release_coalesced_flush(
	struct xfs_mount	*mp)
{
	struct block_device	*bdev;
	long long		seq, snap;

	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return;
	bdev = mp->m_ddev_targp->bt_bdev;

	seq = atomic64_inc_return(&mp->m_mxfs_flush_req);
	if (atomic64_read(&mp->m_mxfs_flush_done) >= seq)
		return;	/* a flush already persisted our writes */

	mutex_lock(&mp->m_mxfs_flush_lock);
	if (atomic64_read(&mp->m_mxfs_flush_done) >= seq) {
		mutex_unlock(&mp->m_mxfs_flush_lock);
		return;	/* coalesced: someone flushed while we waited */
	}
	snap = atomic64_read(&mp->m_mxfs_flush_req);
	blkdev_issue_flush(bdev);
	/* the coalesced engine is the main release-path
	 * flush - advance the platter-coherence epoch (m_mxfs_flush_epoch). */
	atomic64_inc(&mp->m_mxfs_flush_epoch);
	/* This flush covered every write submitted before it returned, i.e. at
	 * least every ticket up to `snap`.  Advance done (never backwards). */
	if (atomic64_read(&mp->m_mxfs_flush_done) < snap)
		atomic64_set(&mp->m_mxfs_flush_done, snap);
	mutex_unlock(&mp->m_mxfs_flush_lock);
}

static void
mxfs_noino_dump_ail_min(
	struct xfs_mount	*mp,
	uint64_t		ino)
{
	static atomic_t		cap = ATOMIC_INIT(0);
	struct xfs_ail		*ailp = mp->m_ail;
	struct xfs_log_item	*lip;

	if (atomic_inc_return(&cap) > 24)
		return;
	spin_lock(&ailp->ail_lock);
	lip = xfs_ail_min(ailp);
	if (!lip) {
		spin_unlock(&ailp->ail_lock);
		mxfs_probe("mxfs: P-AILMIN ino=%llu — AIL empty at dump\n",
			(unsigned long long)ino);
		return;
	}
	if (lip->li_type == XFS_LI_BUF) {
		struct xfs_buf_log_item *bip =
			container_of(lip, struct xfs_buf_log_item, bli_item);
		struct xfs_buf *bp = bip->bli_buf;

		mxfs_probe("mxfs: P-AILMIN ino=%llu BUF lsn=0x%llx daddr=%lld len=%u bflags=0x%x liflags=0x%lx pin=%d ops=%s\n",
			(unsigned long long)ino,
			(unsigned long long)lip->li_lsn,
			(long long)bp->b_maps[0].bm_bn, bp->b_length,
			bp->b_flags, lip->li_flags,
			atomic_read(&bp->b_pin_count),
			bp->b_ops ? bp->b_ops->name : "none");
		mxfs_buf_diag_dump("P-AILMIN-BUF", ino, bp);
	} else if (lip->li_type == XFS_LI_INODE) {
		struct xfs_inode_log_item *iip =
			container_of(lip, struct xfs_inode_log_item, ili_item);
		struct xfs_inode *tip = iip->ili_inode;

		/*
		 * (0.23.4 test31, D-474): the frozen min was an INODE
		 * item in XFS_LI_FLUSHING (liflags 0x21 = IN_AIL|FLUSHING, NOT
		 * FAILED) for 23 s.  xfsaild never pushes a FLUSHING item, so
		 * the P129 branch probes are blind to it; name the item's own
		 * flush state and dump its cluster buffer (the only thing that
		 * can still complete it).
		 */
		mxfs_probe("mxfs: P-AILMIN ino=%llu INODE lsn=0x%llx tgt_ino=%llu liflags=0x%lx fields=0x%x last=0x%x flush_lsn=0x%llx iflags=0x%lx dlm_mode=%d ipin=%d nlink=%u mode=0%o\n",
			(unsigned long long)ino,
			(unsigned long long)lip->li_lsn,
			(unsigned long long)(tip ? tip->i_ino : 0),
			lip->li_flags, iip->ili_fields, iip->ili_last_fields,
			(unsigned long long)iip->ili_flush_lsn,
			tip ? tip->i_flags : 0UL,
			tip ? (int)tip->i_dlm_mode : -1,
			tip ? xfs_ipincount(tip) : -1,
			tip ? VFS_I(tip)->i_nlink : 0,
			tip ? VFS_I(tip)->i_mode : 0);
		mxfs_buf_diag_dump("P-AILMIN-IBUF", ino, lip->li_buf);
	} else if (lip->li_type == XFS_LI_EFI) {
		/*
		 * an EFI at the AIL min is an extent-free DEFER
		 * CHAIN still in flight (no iop_push — it leaves the AIL
		 * only when its EFD commits, which needs the AGF of each
		 * extent's AG).  Name the AGs so the freeze can be matched
		 * to a local blocking AG wait (P1-AGWAIT / agwait_inflight).
		 */
		struct xfs_efi_log_item *efip =
			container_of(lip, struct xfs_efi_log_item, efi_item);
		unsigned int nx = efip->efi_format.efi_nextents;
		xfs_agnumber_t a0 = nx ? XFS_FSB_TO_AGNO(mp,
				efip->efi_format.efi_extents[0].ext_start) :
				NULLAGNUMBER;
		int wait0 = (a0 != NULLAGNUMBER) ?
			mxfs_noino_agwait_inflight(mp, a0) : -1;

		mxfs_probe("mxfs: P-AILMIN ino=%llu EFI lsn=0x%llx nextents=%u ag0=%u agwait_inflight=%d liflags=0x%lx — extent-free intent: EFD pending on that AG's lock\n",
			(unsigned long long)ino,
			(unsigned long long)lip->li_lsn, nx, a0, wait0,
			lip->li_flags);
	} else {
		mxfs_probe("mxfs: P-AILMIN ino=%llu type=0x%x intent=%d lsn=0x%llx liflags=0x%lx\n",
			(unsigned long long)ino, lip->li_type,
			xlog_item_is_intent(lip) ? 1 : 0,
			(unsigned long long)lip->li_lsn, lip->li_flags);
	}
	spin_unlock(&ailp->ail_lock);
}

/*
 * (D-474 convoy-aware fence): classify a FROZEN AIL min.  Returns
 * true when the freeze is attributable to a LOCAL task blocked in the per-AG
 * CAW acquire — i.e. the item cannot land until that bounded wait ends, so
 * the fence must keep waiting rather than shut the node down:
 *   EFI        -> an extent's AG has agwait_inflight > 0 (exact: the EFD
 *                 commits when xfs_extent_free_finish_item gets that AGF);
 *   BUF/INODE  -> some local blocking AG wait is in flight (the owner that
 *                 holds the buffer/ILOCK across the wait cannot be named
 *                 cheaply; the fence's 45-try hard wall still bounds it).
 * *agno_out names the attributed AG (NULLAGNUMBER when none), *wait_ms the
 * age of that AG's oldest in-flight wait episode.  Done under ail_lock; no
 * item pointer escapes it.
 */
static int
mxfs_noino_agwait_inflight(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	struct xfs_perag	*pag;
	int			n;

	if (agno == NULLAGNUMBER || agno >= mp->m_sb.sb_agcount)
		return 0;
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return 0;
	n = atomic_read(&pag->pag_mxfs_agwait_inflight);
	xfs_perag_put(pag);
	return n;
}

static xfs_agnumber_t
mxfs_noino_any_agwait(
	struct xfs_mount	*mp,
	u64			*since_ns)
{
	xfs_agnumber_t		agno;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag *pag = xfs_perag_get(mp, agno);

		if (!pag)
			continue;
		if (atomic_read(&pag->pag_mxfs_agwait_inflight) > 0) {
			*since_ns = READ_ONCE(pag->pag_mxfs_agwait_since_ns);
			xfs_perag_put(pag);
			return agno;
		}
		xfs_perag_put(pag);
	}
	return NULLAGNUMBER;
}

static bool
mxfs_noino_freeze_is_convoy(
	struct xfs_mount	*mp,
	xfs_agnumber_t		*agno_out,
	unsigned int		*item_type_out,
	u64			*wait_ms_out)
{
	struct xfs_ail		*ailp = mp->m_ail;
	struct xfs_log_item	*lip;
	xfs_agnumber_t		item_ag = NULLAGNUMBER;
	xfs_agnumber_t		ags[8];
	unsigned int		nags = 0, i;
	unsigned int		type = 0;
	u64			since = 0;
	bool			convoy = false;

	*agno_out = NULLAGNUMBER;
	*item_type_out = 0;
	*wait_ms_out = 0;

	spin_lock(&ailp->ail_lock);
	lip = xfs_ail_min(ailp);
	if (lip) {
		type = lip->li_type;
		if (lip->li_type == XFS_LI_EFI) {
			struct xfs_efi_log_item *efip =
				container_of(lip, struct xfs_efi_log_item,
					     efi_item);
			unsigned int nx = efip->efi_format.efi_nextents;

			for (i = 0; i < nx && nags < ARRAY_SIZE(ags); i++)
				ags[nags++] = XFS_FSB_TO_AGNO(mp,
					efip->efi_format.efi_extents[i].ext_start);
		} else if (lip->li_type == XFS_LI_BUF) {
			struct xfs_buf_log_item *bip =
				container_of(lip, struct xfs_buf_log_item,
					     bli_item);
			item_ag = xfs_daddr_to_agno(mp,
					bip->bli_buf->b_maps[0].bm_bn);
		} else if (lip->li_type == XFS_LI_INODE) {
			struct xfs_inode_log_item *iip =
				container_of(lip, struct xfs_inode_log_item,
					     ili_item);
			if (iip->ili_inode)
				item_ag = XFS_INO_TO_AGNO(mp,
						iip->ili_inode->i_ino);
		}
	}
	spin_unlock(&ailp->ail_lock);
	*item_type_out = type;
	if (!lip)
		return false;

	if (type == XFS_LI_EFI) {
		for (i = 0; i < nags; i++) {
			struct xfs_perag *pag;

			if (ags[i] >= mp->m_sb.sb_agcount)
				continue;
			pag = xfs_perag_get(mp, ags[i]);
			if (!pag)
				continue;
			if (atomic_read(&pag->pag_mxfs_agwait_inflight) > 0) {
				since = READ_ONCE(pag->pag_mxfs_agwait_since_ns);
				*agno_out = ags[i];
				convoy = true;
			}
			xfs_perag_put(pag);
			if (convoy)
				break;
		}
	} else {
		xfs_agnumber_t wag = mxfs_noino_any_agwait(mp, &since);

		if (wag != NULLAGNUMBER) {
			*agno_out = wag;
			convoy = true;
		} else {
			*agno_out = item_ag;
		}
	}
	if (convoy && since)
		*wait_ms_out = (ktime_get_ns() - since) / 1000000;
	return convoy;
}

/*
 * stall repair: land the node's own committed-but-
 * unwritable buffers.  Invariant #1's contract ("everything this node
 * committed before the release is on disk") INCLUDES fresh inode-cluster
 * buffers sitting on pag_mxfs_alloc_buflist — committed icreate state that
 * xfsaild structurally cannot write (FLUSHING dead-end above).  The AG
 * release path drains them as a mandatory pre-unlock step; the noino
 * fence must too, or the AIL min freezes at their BLI and the fence can
 * never complete (run70: 9-node collapse; and the un-landed cluster init
 * is exactly what peers then mis-read — run69 test18's EFSBADCRC inode
 * cluster still holding prior-tenant file data).  Bounded: agcount
 * iterations, only non-empty lists pay; drain itself submits sync +
 * device-flushes (mxfs_dlm_ag_drain_alloc_buflist).
 */
static void
mxfs_noino_drain_mxfs_buflists(
	struct xfs_mount	*mp,
	uint64_t		ino)
{
	xfs_agnumber_t		agno;
	unsigned int		drained_ags = 0;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag *pag = xfs_perag_get(mp, agno);

		if (!pag)
			continue;
		if (!list_empty_careful(&pag->pag_mxfs_alloc_buflist)) {
			mxfs_dlm_ag_drain_alloc_buflist(mp, pag);
			drained_ags++;
		}
		xfs_perag_put(pag);
	}
	pr_warn("mxfs: P-NOINO-LISTDRAIN ino=%llu ags=%u — fence stalled; drained mxfs alloc buflists (xfsaild cannot write _XBF_MXFS_ALLOC_QUEUED bufs)\n",
		(unsigned long long)ino, drained_ags);
}

bool
mxfs_noino_drain_fence(
	struct xfs_mount	*mp,
	uint64_t		ino,
	int			landed)
{
	xfs_lsn_t		last_min = 0;
	int			stall = 0;
	int			convoy_stalls = 0;
	xfs_agnumber_t		cv_ag = NULLAGNUMBER;
	unsigned int		cv_type = 0;
	u64			cv_wait_ms = 0;
	int			try;
	bool			armed_here = false;

	for (try = 0; try < MXFS_NOINO_MAX_TRIES; try++) {
		xfs_lsn_t target = 0;
		xfs_lsn_t ail_max;
		xfs_lsn_t min_now;

		xfs_log_force(mp, XFS_LOG_SYNC);
		/* FIX-12b skip arm: a completed noino drain already covers
		 * everything now in the AIL (see loop comment below). */
		ail_max = xfs_ail_max_lsn(mp->m_ail);
		if (ail_max == 0 ||
		    XFS_LSN_CMP(ail_max, (xfs_lsn_t)atomic64_read(
				&mp->m_mxfs_noino_drained_lsn)) <= 0) {
			/* FIX-16: the skip arm does no device flush; if the
			 * land scan wrote, cover those writes before the
			 * unlock hands the platter to a FUA reader. */
			if (landed > 0)
				mxfs_release_coalesced_flush(mp);
			if (armed_here)
				mxfs_ailstuck_probe_fence_disarm();
			return true;
		}
		if (xfs_ail_push_upto_sync_bounded(mp->m_ail, 2000,
						   &target)) {
			s64 old;

			/* flush BEFORE publishing the marker: a racer that
			 * skips on the marker must find its writes already
			 * device-flush-covered. */
			mxfs_release_coalesced_flush(mp);
			old = atomic64_read(&mp->m_mxfs_noino_drained_lsn);
			while (XFS_LSN_CMP((xfs_lsn_t)old, target) < 0 &&
			       !atomic64_try_cmpxchg(
				       &mp->m_mxfs_noino_drained_lsn,
				       &old, (s64)target))
				;
			if (armed_here)
				mxfs_ailstuck_probe_fence_disarm();
			return true;
		}
		if (xfs_is_shutdown(mp))
			return false;	/* already down: stop retry spam */
		min_now = xfs_ail_min_lsn(mp->m_ail);
		if (min_now != last_min) {
			stall = 0;
			last_min = min_now;
			/* freeze broke: disarm now so a later new freeze in
			 * this same fence re-arms with a fresh odumps budget */
			if (armed_here) {
				mxfs_ailstuck_probe_fence_disarm();
				armed_here = false;
			}
		} else if (mxfs_noino_freeze_is_convoy(mp, &cv_ag, &cv_type,
						       &cv_wait_ms)) {
			/*
			 * (D-474, design-consult ruling): the frozen
			 * min is attributable to a LOCAL task blocked in the
			 * bounded per-AG CAW acquire (measured at 25 AGs: an
			 * EFI whose EFD needs the shared AG a peer held 13 s;
			 * every fence on the node froze on it and the 8-stall
			 * budget shut the node down).  A convoy is not a
			 * wedge: do not charge the stall budget.  The
			 * MXFS_NOINO_MAX_TRIES hard wall still bounds the
			 * whole fence, so an unrelated or never-ending wait
			 * cannot suppress a real freeze forever.
			 */
			convoy_stalls++;
			if (convoy_stalls == 1 || (convoy_stalls % 4) == 0)
				pr_warn("mxfs: P-NOINO-CONVOY ino=%llu try=%d min=0x%llx item=0x%x ag=%u agwait_ms=%llu frozen=%d chargeable=%d — AIL min frozen behind a local blocking AG wait; not charged as a wedge\n",
					(unsigned long long)ino, try,
					(unsigned long long)min_now, cv_type,
					cv_ag, (unsigned long long)cv_wait_ms,
					convoy_stalls, stall);
			if (convoy_stalls == 2)
				mxfs_noino_dump_ail_min(mp, ino);
		} else {
			stall++;
			/* Frozen min: name the item (proof), then land the
			 * node's own alloc-buflist buffers (repair — the
			 * FLUSHING dead-end class xfsaild cannot write).
			 * Only wedge if the min stays frozen even after the
			 * repair had two further pushes to show effect. */
			if (stall == 2) {
				/* incident474: the fence wedged and shut the
				 * node down without ever arming the AIL-stuck
				 * probes (they self-latch only after 30s inside
				 * xfs_ail_push_all_sync, a path this fence never
				 * takes).  Latch them here so the remaining
				 * bounded pushes name WHY the frozen item's
				 * cluster flush is skipped (P129-CLSKIP incl.
				 * ILOCK owner) instead of dying silent.
				 * Fence-scoped: a recovered fence disarms on
				 * its success return (— the benign
				 * LISTDRAIN-repairable class was permanently
				 * latching the fleet); DRAIN-STUCK/shutdown
				 * exits keep the latch for the post-mortem. */
				if (!armed_here) {
					mxfs_ailstuck_probe_fence_arm();
					armed_here = true;
				}
				mxfs_noino_dump_ail_min(mp, ino);
			}
			if (stall == 3)
				mxfs_noino_drain_mxfs_buflists(mp, ino);
			if (stall >= MXFS_NOINO_STALL_TRIES) {
				pr_warn("mxfs: P-NOINO-DRAIN-STUCK ino=%llu try=%d — AIL min frozen at 0x%llx across %d bounded pushes (post-listdrain) convoy_stalls=%d\n",
					(unsigned long long)ino, try,
					(unsigned long long)min_now, stall,
					convoy_stalls);
				return false;
			}
		}
		if ((try % 5) == 4)
			pr_warn("mxfs: P-NOINO-DRAIN-RETRY ino=%llu try=%d min=0x%llx stall=%d convoy=%d — pre-release AIL target not yet landed\n",
				(unsigned long long)ino, try,
				(unsigned long long)min_now, stall, convoy_stalls);
	}
	pr_warn("mxfs: P-NOINO-DRAIN-STUCK ino=%llu — hard cap %d tries exceeded (AIL advancing or convoy-frozen but never caught the snapshot target) convoy_stalls=%d last_ag=%u agwait_ms=%llu\n",
		(unsigned long long)ino, MXFS_NOINO_MAX_TRIES, convoy_stalls,
		cv_ag, (unsigned long long)cv_wait_ms);
	return false;
}

void
mxfs_dlm_noino_bast_work_fn(
	struct work_struct	*work)
{
	struct mxfs_noino_bast_work *w =
		container_of(work, struct mxfs_noino_bast_work, work);
	struct xfs_mount	*mp = w->mp;
	uint64_t		ino = w->ino;
	bool			drained = false;
	int			landed;

	/* FIX-16: land committed-never-written dir blocks
	 * owned by this ino FIRST — they are mxfs-seq-tracked (no BLI in the
	 * AIL), so the LSN fence below cannot see them (run89 r6: unlock
	 * handed the peer a pre-add platter while lseq=168 wseq=0 sat in
	 * core; peer readdir=758/800). */
	landed = mxfs_dir_noino_land_scan(mp, ino, true);

	/*
	 * FIX-12 (PROVEN BY INSTRUMENT, run81 r5): the old drain here
	 * pushed only XFS_INO_TO_AGNO(ino) — but a shared dir's data blocks
	 * are allocated AG-AFFINELY BY EACH WRITER, so they span AGs (node8's
	 * bno5@48144232 lived in a peer-allocated AG; the single-AG push never
	 * touched it, the unlock handed EX with 46 committed adds unlanded,
	 * and the cluster durably lost them off the stale platter).  This
	 * path also fires for IN-CORE inodes that xfs_iget(INCORE)
	 * transiently refuses (-EAGAIN: IRECLAIMABLE after the verify-phase
	 * drop_caches — the round-7 noino=170 storm), where the live dir
	 * state is very much ours to land.  No extent map => the only safe
	 * fence is "everything this node committed before the release is on
	 * disk": LSN-targeted whole-AIL push.  Later commits don't extend
	 * the target, so foreground load cannot livelock it.  P3B policy on
	 * failure: NEVER unlock undrained — retry, then shutdown (fence +
	 * journal replay beats a silent cluster-wide lost update).
	 *
	 * retry policy is PROGRESS-BASED now — see
	 * mxfs_noino_drain_fence above.  "Slow under a 32-node convoy" is
	 * not a wedge; only a frozen AIL min (or the ~90s hard wall) is.
	 */
	drained = mxfs_noino_drain_fence(mp, ino, landed);
	if (!drained && !xfs_is_shutdown(mp)) {
		pr_warn("mxfs: P-NOINO-RELFENCE-WEDGE ino=%llu — shutdown (un-durable no-inode lock NOT released)\n",
			(unsigned long long)ino);
		xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		if (mxfs_noino_bast_dedup)
			mxfs_noino_inflight_remove(mp, ino);
		kfree(w);
		return;
	}

	/*
	 * storm-2 refinement: the grant-gen anchor alone is
	 * NOT sufficient — grant_meta buckets are collision-LOSSY, so under
	 * a 32-node churn the anchor (and the unlock's own seq re-check)
	 * frequently degrade to 0/unconditional (guard fired 0× while
	 * P135-HELD-MISS stayed at 15,622/3min).  The robust tenure truth is
	 * IN CORE: this work fn only exists because the inode was NOT in
	 * core at BAST time; if it is BACK in core with a granted mode now,
	 * a local re-acquire won a new tenure during our drain fence — the
	 * slot bit is THE NEW TENURE'S, not ours to clear (test30's mkdir
	 * EX stripped 4ms after grant → double sf_to_block → durable dirent
	 * loss).  Skip; the live tenure's own BAST handling serves the peer.
	 */
	{
		struct xfs_inode *live_ip = NULL;

		if (!xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &live_ip) &&
		    live_ip) {
			bool live_held =
				live_ip->i_dlm_mode != MXFS_LOCK_NL;

			xfs_irele(live_ip);
			if (live_held) {
				static atomic_t p_noino_live_cap =
					ATOMIC_INIT(0);

				if (atomic_inc_return(&p_noino_live_cap) <= 200)
					pr_warn("mxfs: P-NOINO-LIVE-SKIP ino=%llu — inode re-instantiated with a granted mode during the drain fence; release skipped (live tenure owns the slot)\n",
						(unsigned long long)ino);
				if (mxfs_noino_bast_dedup)
					mxfs_noino_inflight_remove(mp, ino);
				kfree(w);
				return;
			}
		}
	}
	mxfs_dlm_publish_unpublished(mp, ino, NULLAGNUMBER);
	{
		int ug_rc = mxfs_v5_dlm_inode_unlock_gen(mp->m_mxfs_dlm, ino,
							 w->rel_gen);

		if (ug_rc == -ESTALE) {
			static atomic_t p_noino_stale_cap = ATOMIC_INIT(0);

			if (atomic_inc_return(&p_noino_stale_cap) <= 200)
				pr_warn("mxfs: P-NOINO-STALE-RELEASE ino=%llu rel_gen=%u — local re-acquire owns a newer tenure; release refused (fresh grant preserved)\n",
					(unsigned long long)ino, w->rel_gen);
		}
	}
	if (mxfs_noino_bast_dedup)
		mxfs_noino_inflight_remove(mp, ino);
	kfree(w);
}
int mxfs_noino_lifecycle_max_ms = 60000;
module_param_named(noino_lifecycle_max_ms, mxfs_noino_lifecycle_max_ms, int, 0644);
MODULE_PARM_DESC(noino_lifecycle_max_ms,
	"bound on how long a no-inode BAST is requeued behind a local lifecycle op before it falls through to the fence (default 60000)");
static DEFINE_HASHTABLE(mxfs_noino_lc_ht, 6);
static DEFINE_SPINLOCK(mxfs_noino_lc_lock);

static void
mxfs_noino_lc_work_fn(
	struct work_struct	*work)
{
	struct mxfs_noino_lc_work *w =
		container_of(to_delayed_work(work), struct mxfs_noino_lc_work, dw);
	struct xfs_mount	*mp = w->mp;
	uint64_t		ino = w->ino;
	uint8_t			mode = w->mode;
	unsigned long		fl, st;
	unsigned int		nl;
	enum xfs_ino_lifecycle	lc;
	u64			age_ms;
	unsigned long		flags;
	bool			requeue;

	lc = xfs_icache_ino_lifecycle(mp, ino, &fl, &nl, &st);
	age_ms = (ktime_get_ns() - w->first_ns) / 1000000;
	requeue = mxfs_noino_lifecycle_requeue &&
		  (lc == XFS_ILC_INEW || lc == XFS_ILC_IRECLAIM ||
		   lc == XFS_ILC_INACTIVATING || lc == XFS_ILC_NEED_INACTIVE ||
		   lc == XFS_ILC_VFS_TEARDOWN) &&
		  age_ms < (u64)mxfs_noino_lifecycle_max_ms &&
		  !xfs_is_shutdown(mp);
	if (requeue) {
		w->n++;
		if (lc == XFS_ILC_NEED_INACTIVE)
			xfs_inodegc_push(mp);
		queue_delayed_work(mp->m_mxfs_inode_bast_wq, &w->dw,
				   msecs_to_jiffies(20));
		return;
	}
	spin_lock_irqsave(&mxfs_noino_lc_lock, flags);
	hash_del(&w->hnode);
	spin_unlock_irqrestore(&mxfs_noino_lc_lock, flags);
	if (age_ms >= (u64)mxfs_noino_lifecycle_max_ms) {
		atomic64_inc(&mxfs_noino_lifecycle_timeouts);
		pr_warn("mxfs: P-NOINO-LIFECYCLE-TIMEOUT ino=%llu class=%s iflags=0x%lx nlink=%u age_ms=%llu requeues=%u — local lifecycle op still running; falling through to the fence\n",
			(unsigned long long)ino, xfs_ino_lifecycle_name(lc), fl,
			nl, (unsigned long long)age_ms, w->n);
	} else {
		static atomic_t p_lcdone_n = ATOMIC_INIT(0);

		if ((unsigned)atomic_inc_return(&p_lcdone_n) <= 64)
			mxfs_probe("mxfs: P-NOINO-LIFECYCLE-DONE ino=%llu class=%s age_ms=%llu requeues=%u — lifecycle op finished; re-driving the BAST\n",
				(unsigned long long)ino,
				xfs_ino_lifecycle_name(lc),
				(unsigned long long)age_ms, w->n);
	}
	/* re-drive; a fresh transient state may requeue again (new bound),
	 * a timed-out one must not. */
	__mxfs_dlm_bast_notify(mp, ino, mode,
			       age_ms < (u64)mxfs_noino_lifecycle_max_ms);
	kfree(w);
}

/* Returns true when the BAST was parked behind the lifecycle op (caller must
 * return without fencing); false when the caller should proceed as before. */
bool
mxfs_noino_lifecycle_park(
	struct xfs_mount	*mp,
	uint64_t		ino,
	uint8_t			requested_mode,
	enum xfs_ino_lifecycle	lc)
{
	struct mxfs_noino_lc_work *w, *e;
	unsigned long		flags;

	if (!mp->m_mxfs_inode_bast_wq)
		return false;
	w = kzalloc(sizeof(*w), GFP_ATOMIC);
	if (!w)
		return false;
	w->mp = mp;
	w->ino = ino;
	w->mode = requested_mode;
	w->first_ns = ktime_get_ns();
	INIT_DELAYED_WORK(&w->dw, mxfs_noino_lc_work_fn);
	spin_lock_irqsave(&mxfs_noino_lc_lock, flags);
	hash_for_each_possible(mxfs_noino_lc_ht, e, hnode, ino) {
		if (e->mp == mp && e->ino == ino) {
			/* already parked: drop this duplicate BAST (the peer
			 * re-BASTs while our bit stays set; the parked work
			 * re-drives when the lifecycle op finishes). */
			spin_unlock_irqrestore(&mxfs_noino_lc_lock, flags);
			kfree(w);
			return true;
		}
	}
	hash_add(mxfs_noino_lc_ht, &w->hnode, ino);
	spin_unlock_irqrestore(&mxfs_noino_lc_lock, flags);
	atomic64_inc(&mxfs_noino_lifecycle_requeued);
	if (lc == XFS_ILC_NEED_INACTIVE)
		xfs_inodegc_push(mp);
	queue_delayed_work(mp->m_mxfs_inode_bast_wq, &w->dw,
			   msecs_to_jiffies(20));
	return true;
}

void
mxfs_dlm_bast_notify(
	void		*data,
	uint64_t	ino,
	uint8_t		requested_mode)
{
	__mxfs_dlm_bast_notify(data, ino, requested_mode, true);
}
