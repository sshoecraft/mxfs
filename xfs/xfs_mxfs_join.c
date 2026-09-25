// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- peer join and orphan/unlinked-bucket sweeps
 */
#define MXFS_TU_ID 32	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

int
mxfs_dlm_peer_joined_flush(
	void	*data)
{
	struct xfs_mount	*mp = (struct xfs_mount *)data;
	int			error = 0;
	unsigned int		round;

	if (!mp)
		return -EINVAL;

	mxfs_pal_log(MXFS_LOG_DEBUG,
		"mxfs: peer joined — flushing XFS dirty state before "
		"single→multi transition");

	/*
	 * v0.3.126: same async-CIL-callback race as the inode bast
	 * fix.  log_force(SYNC) returns when log write completes, but
	 * xlog_cil_committed adds BLI to AIL asynchronously.  Single
	 * log_force+ail_push could miss in-flight items.  msleep+double
	 * gives the async work time to fire.  Peer_joined fires once at
	 * cluster formation; cost is irrelevant.
	 *
	 * item 2/5: the invalidation that follows can come back
	 * -EBUSY, and proceeding on that is the bug design review flagged — it declares
	 * the node's cached views gone while a writeback that will overwrite
	 * a peer's content is still pending.  The flush round is exactly the
	 * remedy (destage the retained content, then the next walk can drop
	 * it), so repeat it rather than proceed.
	 */
	for (round = 0; round < MXFS_INVAL_FLUSH_ROUNDS; round++) {
		if (xfs_is_shutdown(mp))
			return -EIO;

		xfs_log_force(mp, XFS_LOG_SYNC);
		xfs_ail_push_all_sync(mp->m_ail);
		mxfs_blkdev_flush_epoch(mp);

		msleep(20);
		xfs_log_force(mp, XFS_LOG_SYNC);
		xfs_ail_push_all_sync(mp->m_ail);
		mxfs_blkdev_flush_epoch(mp);

		error = mxfs_dlm_invalidate_cached_views(mp);
		if (!error)
			return 0;

		xfs_warn(mp,
			"mxfs: cached-view invalidation still incomplete after "
			"flush round %u/%u — retrying the destage",
			round + 1, MXFS_INVAL_FLUSH_ROUNDS);
	}

	/*
	 * Could not destage our own committed content in %d rounds.  Leaving
	 * the AGs cached means we take the cached fast path while the on-disk
	 * slot may carry no grant for us, and declaring them uncached means
	 * our pending writeback lands on top of a peer.  Neither is allowed,
	 * so the answer is "not yet": every caller keeps the peer unadmitted
	 * (the join worker retries the whole transition, the foreign-replay
	 * paths re-arm the reap) and nothing proceeds on a cached view.
	 *
	 * 0.83.4 (D-0959): this used to force-shutdown the filesystem.
	 * Measured (s584c, 2 nodes/TCP): against a live local workload the
	 * rounds never converge -- the workload re-dirties the AGs faster
	 * than they are destaged -- and the shutdown lost every unsynced
	 * byte the node held (all appended data in 32 files, the entries of
	 * 34 directories) two milliseconds before its membership line.  A
	 * join preparation that has not finished is not a corruption; a
	 * shutdown on it is the data loss it claimed to prevent.
	 */
	xfs_warn(mp,
		"P232-INVAL-STUCK: cached-view invalidation did not complete "
		"in %d flush rounds (%d) — the peer stays unadmitted; the "
		"transition will be retried",
		MXFS_INVAL_FLUSH_ROUNDS, error);
	return error;
}

/*
 * 0.83.4 (D-0959): PREPARE half of the single-to-multi transition, run on
 * the DLM's join worker.
 *
 * A mount that has never had a peer modifies everything at NL with no
 * grant, so at the moment its first peer can take a grant nothing at any
 * DLM master represents its dirty state: no BAST can ever land it, the
 * newcomer reads the platter's older image, and whichever side flushes
 * last reverts the other (or the logged-directory-at-NL rule refuses the
 * incumbent's image and it never lands at all).  The destage rounds above
 * were this node's answer, and they race the node's own workload.
 *
 * On a mounted filesystem the transition therefore runs under a KERNEL
 * FREEZE: freeze_super blocks every new writer and page fault, writes back
 * every dirty page (sync_filesystem -- the destage rounds never touched
 * file data), then quiesces the log (xfs_fs_freeze: log force, AIL push to
 * empty, cover).  With nothing dirty and nothing able to dirty, the
 * cached-view walk drops every view this node holds, and the freeze is
 * HELD until the caller has installed the two-node view and set the sticky
 * ever_multi bit (mxfs_dlm_join_commit thaws) -- so the first modification
 * after the flip already takes a real grant.  The newcomer, for its part,
 * takes no grant of any mode until this node's beacon carries the installed
 * view (dlm.c, the settle gate), which cannot happen before this returns 0.
 *
 * The superblock is frozen only once it is born: a peer sighted while this
 * node's own mount is still in progress (the newcomer's side of every
 * join) has nothing of the user's to write back, freeze_super would block
 * on s_umount until the mount finished, and the incumbent's gate would
 * wait on this node's beacon for the whole of that mount.  That side keeps
 * the destage rounds, which cannot fail on a mount that has modified
 * nothing -- and if they do, the answer is still "not yet".
 *
 * Returns 0 with the freeze (if any) held; any other value with nothing
 * held, and the caller must not install the view.
 */
/*
 * TEST ONLY: hold this many ms between join_prepare's cached-view drop and
 * its return (the join worker installs the view after it), widening the
 * window in which a lone node's tenure can end with the tenure-end bmbt
 * eviction skipped.  0 (default) = off.
 */
static unsigned int mxfs_dbg_join_flip_delay_ms;
module_param_named(dbg_join_flip_delay_ms, mxfs_dbg_join_flip_delay_ms,
		   uint, 0644);
MODULE_PARM_DESC(dbg_join_flip_delay_ms,
	"TEST: ms to hold between the join's cached-view drop and the view flip (0 = off)");

/*
 * Count the clean cached extent-tree (bmbt) blocks whose owner inode holds
 * no grant here: not in core, or in core at NL.  Such a block outlived the
 * tenure that read it, which is exactly what the tenure-end eviction exists
 * to prevent — a peer can free and reuse its address.  Read-only; the walk
 * reads the owner under the same RCU hash walk the eviction uses.
 */
static unsigned int
mxfs_dlm_count_orphan_bmbt(
	struct xfs_mount	*mp,
	unsigned int		*seen)
{
	xfs_agnumber_t		agno;
	unsigned int		orphans = 0;

	*seen = 0;
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			xfs_ino_t		owner;
			struct xfs_perag	*opag;
			struct xfs_inode	*oip = NULL;
			bool			granted = false;

			if (IS_ERR(bp))
				continue;
			if (bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr ||
			    (bp->b_flags & XBF_READ) ||
			    !(bp->b_flags & XBF_DONE))
				continue;
			(*seen)++;
			owner = be64_to_cpu(((struct xfs_btree_block *)
					     bp->b_addr)->bb_u.l.bb_owner);
			if (!owner ||
			    XFS_INO_TO_AGNO(mp, owner) >= mp->m_sb.sb_agcount)
				continue;
			opag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, owner));
			if (opag) {
				oip = radix_tree_lookup(&opag->pag_ici_root,
						XFS_INO_TO_AGINO(mp, owner));
				if (oip && READ_ONCE(oip->i_ino) == owner &&
				    READ_ONCE(oip->i_dlm_mode) != MXFS_LOCK_NL)
					granted = true;
				xfs_perag_put(opag);
			}
			if (!granted) {
				orphans++;
				if (orphans <= 8)
					pr_warn("mxfs: P-JOIN-BMBT-ORPHAN daddr=%lld owner=%llu incore=%d — clean cached extent-tree block whose owner holds no grant here\n",
						(long long)xfs_buf_daddr(bp),
						(unsigned long long)owner,
						oip ? 1 : 0);
			}
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}
	return orphans;
}

int
mxfs_dlm_join_prepare(
	void	*data)
{
	struct xfs_mount	*mp = (struct xfs_mount *)data;
	struct super_block	*sb;
	int			error;
	unsigned int		walk;

	if (!mp)
		return -EINVAL;
	if (xfs_is_shutdown(mp))
		return -EIO;
	sb = mp->m_super;
	if (!sb || !(sb->s_flags & SB_BORN))
		return mxfs_dlm_peer_joined_flush(mp);

	mxfs_pal_log(MXFS_LOG_DEBUG,
		"mxfs: P-JOIN-FREEZE — peer sighted; freezing this mount for the "
		"single→multi transition (data + log written back, cached views "
		"dropped, view installed, then thaw)");
	error = mxfs_freeze_super(sb, FREEZE_HOLDER_KERNEL);
	if (error) {
		xfs_warn(mp,
			"mxfs: P-JOIN-FREEZE-FAIL freeze_super rc=%d — the peer stays "
			"unadmitted; the transition will be retried", error);
		return error;
	}
	mp->m_mxfs_join_frozen = true;

	/*
	 * Frozen: the AIL is empty and the log covered.  The walk can still
	 * meet a reader holding a buffer lock (freeze stops writers, not
	 * readers), so it is repeated briefly rather than declared complete
	 * over a retained buffer.
	 */
	for (walk = 0; walk < 50; walk++) {
		if (xfs_is_shutdown(mp)) {
			error = -EIO;
			break;
		}
		error = mxfs_dlm_invalidate_cached_views(mp);
		if (!error) {
			unsigned int	dly = READ_ONCE(mxfs_dbg_join_flip_delay_ms);

			if (dly) {
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: P-JOIN-FLIP-DELAY ms=%u — TEST: holding between the cached-view drop and the view flip",
					dly);
				msleep(dly);
			}
			return 0;
		}
		msleep(10);
	}
	xfs_warn(mp,
		"mxfs: P-JOIN-FREEZE-INVAL-INCOMPLETE rc=%d after %u walks under "
		"freeze — thawing; the peer stays unadmitted and the transition "
		"will be retried", error, walk);
	mxfs_dlm_join_commit(mp);
	return error ? error : -EBUSY;
}

/*
 * 0.83.4 (D-0959): COMMIT half -- release the freeze mxfs_dlm_join_prepare
 * holds.  Called by the join worker once the view is installed, and by
 * prepare itself on its own failure.  Idempotent.
 */
void
mxfs_dlm_join_commit(
	void	*data)
{
	struct xfs_mount	*mp = (struct xfs_mount *)data;
	int			error;

	if (!mp || !mp->m_mxfs_join_frozen)
		return;
	{
		unsigned int	seen = 0;
		unsigned int	orph = mxfs_dlm_count_orphan_bmbt(mp, &seen);

		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: P-JOIN-BMBT-CENSUS single=%d bmbt_cached=%u orphans=%u — clean cached extent-tree blocks at the join commit, and how many have an owner holding no grant",
			mp->m_mxfs_dlm ?
				(int)mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) : -1,
			seen, orph);
	}
	mp->m_mxfs_join_frozen = false;
	error = mxfs_thaw_super(mp->m_super, FREEZE_HOLDER_KERNEL);
	if (error)
		xfs_warn(mp,
			"mxfs: P-JOIN-THAW-FAIL thaw_super rc=%d after the "
			"single→multi transition", error);
	else
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: P-JOIN-THAW — single→multi transition installed; "
			"mount thawed, every modification now takes a grant");
}

static int
mxfs_orphan_collect_fn(
	struct xfs_mount		*mp,
	struct xfs_trans		*tp,
	xfs_agnumber_t			agno,
	const struct xfs_inobt_rec_incore *irec,
	void				*data)
{
	extern int xfs_imap(struct xfs_perag *, struct xfs_trans *,
			    xfs_ino_t, struct xfs_imap *, uint);
	struct mxfs_orphan_scan_ctx *ctx = data;
	struct xfs_perag	*pag;
	int			i;

	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return 0;
	for (i = 0; i < XFS_INODES_PER_CHUNK; i++) {
		struct xfs_imap		imap;
		struct xfs_buf		*bp;
		struct xfs_dinode	*dip;
		xfs_ino_t		ino;

		if (irec->ir_free & XFS_INOBT_MASK(i))
			continue;
		if (irec->ir_holemask &
		    (1U << (i / XFS_INODES_PER_HOLEMASK_BIT)))
			continue;
		ino = xfs_agino_to_ino(pag, irec->ir_startino + i);
		/* Disk-truth filter: only allocated zombies (mode set,
		 * nlink 0) become candidates; everything else is skipped
		 * without an iget. */
		memset(&imap, 0, sizeof(imap));
		if (xfs_imap(pag, NULL, ino, &imap, 0))
			continue;
		if (xfs_imap_to_bp(mp, NULL, &imap, &bp))
			continue;
		dip = xfs_buf_offset(bp, imap.im_boffset);
		if (dip->di_mode != 0 && dip->di_nlink == 0) {
			if (ctx->n >= MXFS_ORPHAN_MAX_CAND) {
				ctx->overflow = true;
				xfs_buf_relse(bp);
				xfs_perag_put(pag);
				return -ECANCELED;
			}
			ctx->cand[ctx->n++] = ino;
		}
		xfs_buf_relse(bp);
	}
	xfs_perag_put(pag);
	return 0;
}

/* Is `target` on ANY of its AG's 64 unlinked bucket chains?  Bounded raw
 * walk; anomalies (cycle-length overrun) report MEMBER = fail-safe skip
 * (the next recovery trigger rescans). */
static int
mxfs_orphan_on_any_bucket(
	struct xfs_perag	*pag,
	xfs_agino_t		target,
	bool			*member)
{
	extern int xfs_imap(struct xfs_perag *, struct xfs_trans *,
			    xfs_ino_t, struct xfs_imap *, uint);
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_buf		*agibp;
	struct xfs_agi		*agi;
	xfs_agino_t		heads[XFS_AGI_UNLINKED_BUCKETS];
	int			b, error;

	*member = false;
	error = xfs_read_agi(pag, NULL, 0, &agibp);
	if (error)
		return error;
	agi = agibp->b_addr;
	for (b = 0; b < XFS_AGI_UNLINKED_BUCKETS; b++)
		heads[b] = be32_to_cpu(agi->agi_unlinked[b]);
	xfs_buf_relse(agibp);

	for (b = 0; b < XFS_AGI_UNLINKED_BUCKETS && !*member; b++) {
		xfs_agino_t	agino = heads[b];
		unsigned int	steps = 0;

		while (agino != NULLAGINO) {
			struct xfs_imap		imap;
			struct xfs_buf		*bp;
			struct xfs_dinode	*dip;

			if (agino == target) {
				*member = true;
				break;
			}
			if (steps++ > 100000) {
				*member = true;	/* anomaly: fail safe */
				break;
			}
			memset(&imap, 0, sizeof(imap));
			error = xfs_imap(pag, NULL,
					 xfs_agino_to_ino(pag, agino),
					 &imap, 0);
			if (error)
				return error;
			error = xfs_imap_to_bp(mp, NULL, &imap, &bp);
			if (error)
				return error;
			dip = xfs_buf_offset(bp, imap.im_boffset);
			agino = be32_to_cpu(dip->di_next_unlinked);
			xfs_buf_relse(bp);
		}
	}
	return 0;
}

int
mxfs_orphan_scan(
	struct xfs_mount	*mp)
{
	struct mxfs_orphan_scan_ctx ctx = { };
	unsigned int		i, adopted = 0, member = 0, changed = 0;
	unsigned int		member_own_reloaded = 0;
	int			error;

	if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
		return -EAGAIN;
	ctx.cand = kvmalloc_array(MXFS_ORPHAN_MAX_CAND, sizeof(xfs_ino_t),
				  GFP_NOFS);
	if (!ctx.cand)
		return -ENOMEM;
	error = xfs_inobt_walk(mp, NULL, 0, 0, mxfs_orphan_collect_fn, 64,
			       &ctx);
	if (error == -ECANCELED)
		error = 0;
	if (error) {
		kvfree(ctx.cand);
		return error;
	}
	if (ctx.overflow)
		pr_warn("mxfs: P98-ORPHAN-OVERFLOW cand>%u — scan truncated, rerun at next recovery\n",
			MXFS_ORPHAN_MAX_CAND);

	for (i = 0; i < ctx.n; i++) {
		xfs_ino_t		ino = ctx.cand[i];
		struct xfs_perag	*pag;
		struct xfs_inode	*ip = NULL;
		struct xfs_trans	*tp = NULL;
		bool			memb = false;
		bool			ag_locked = false;

		if (xfs_is_shutdown(mp))
			break;
		pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ino));
		if (!pag)
			continue;
		/*
		 * (D-ORPHAN-SCAN-IGET-BUCKETED-ZOMBIE-…-0525, design-consult
		 * ruling): NEVER instantiate a bucket member.  The membership
		 * walk is a raw AGI/dinode read and needs no in-core inode,
		 * so run it BEFORE the iget, under this AG's DLM EX (the
		 * cluster-wide serialization of every insert/remove in the
		 * AG — a lockless prewalk would only narrow the window).  A
		 * member belongs to its bucket's owner: a live peer's
		 * open-unlinked file, or a dead/unclaimed slot's zombie that
		 * the elected sweeper reaps with the chain state stamped.
		 * The iget+irele this scan used to do queued inodegc on a
		 * copy with NO chain state; xfs_ifree then removed through
		 * the computed legacy bucket and shut the lone survivor down
		 * (chain 99 peerloss, ino 132).
		 */
		if (mxfs_ag_dlm_lock(mp, pag)) {
			xfs_perag_put(pag);
			changed++;
			continue;
		}
		error = mxfs_orphan_on_any_bucket(pag,
				XFS_INO_TO_AGINO(mp, ino), &memb);
		mxfs_ag_dlm_unlock(mp, pag);
		if (error || memb) {
			member++;
			xfs_perag_put(pag);
			continue;
		}
		if (xfs_iget(mp, NULL, ino, XFS_IGET_UNTRUSTED, 0, &ip)) {
			xfs_perag_put(pag);
			changed++;
			continue;
		}
		/* Reservation before locks; ilock EX runs the DLM acquire —
		 * after this a mid-unlink live peer has completed AND
		 * drained (Invariant 1), so the re-verify below reads the
		 * settled truth. */
		if (xfs_trans_alloc(mp, &M_RES(mp)->tr_link, 0, 0, 0, &tp)) {
			xfs_irele(ip);
			xfs_perag_put(pag);
			continue;
		}
		xfs_ilock(ip, XFS_ILOCK_EXCL);
		/* (design review hazard: lockless walk vs concurrent splice):
		 * the 64-bucket membership walk reads LIVE nodes' chains, so
		 * hold this AG's DLM EX across walk + adopt commit — remote
		 * AGI/chain splices in this AG are excluded and prior ones
		 * drained coherent (Invariant 1).  ILOCK->AG order matches
		 * the alloc paths; xfs_iunlink's own AGI access nests via
		 * pag_dlm_holders. */
		if (mxfs_ag_dlm_lock(mp, pag)) {
			changed++;	/* transient; next trigger rescans */
			goto next_cancel;
		}
		ag_locked = true;
		if (VFS_I(ip)->i_mode == 0 || VFS_I(ip)->i_nlink != 0) {
			changed++;
			goto next_cancel;
		}
		error = mxfs_orphan_on_any_bucket(pag,
				XFS_INO_TO_AGINO(mp, ino), &memb);
		if (error || memb) {
			/*
			 * (D-0525): the prewalk said bucketless and
			 * this re-verify under ILOCK + AG EX says member — a
			 * peer inserted it in between (or the walk failed).
			 * We already hold an in-core copy whose irele will
			 * queue inodegc, and we are NOT its bucket's owner:
			 * mark it so xfs_inactive skips the destructive
			 * inactivation and leaves a clean reclaimable shell
			 * for the legitimate sweeper to recycle.  If the
			 * member is on OUR OWN slot bucket (it is ours),
			 * stamp the bucket and reload the chain instead, so
			 * the inodegc that follows removes it structurally
			 * (the upstream contract for a non-recovery iget).
			 */
			short fb = -1;

			if (!error &&
			    mxfs_iunlink_find_bucket(pag, tp,
					XFS_INO_TO_AGINO(mp, ino), &fb) == 0 &&
			    fb >= 0 &&
			    fb == (short)(mp->m_mxfs_node_slot %
					  XFS_AGI_UNLINKED_BUCKETS) &&
			    mp->m_mxfs_dlm) {
				ip->i_unlinked_bucket = fb;
				if (xfs_inode_reload_unlinked_bucket(tp, ip))
					xfs_iflags_set(ip, MXFS_IF_FOREIGN_ZOMBIE);
				else
					member_own_reloaded++;
			} else {
				xfs_iflags_set(ip, MXFS_IF_FOREIGN_ZOMBIE);
			}
			pr_warn("mxfs: P98-ORPHAN-MEMBER-LATE ino=%llu bucket=%d own_slot=%u foreign_zombie=%d rc=%d — member found after iget; inactivation %s\n",
				(unsigned long long)ino, (int)fb,
				mp->m_mxfs_node_slot,
				xfs_iflags_test(ip, MXFS_IF_FOREIGN_ZOMBIE) ? 1 : 0,
				error,
				xfs_iflags_test(ip, MXFS_IF_FOREIGN_ZOMBIE) ?
					"suppressed (owner sweeps it)" :
					"proceeds with the chain reloaded");
			member++;
			goto next_cancel;
		}
		/* Bucketless zombie under our EX: adopt onto OUR slot
		 * bucket (i_unlinked_bucket = -1 lets the standard
		 * multi-node stamping pick it). */
		ip->i_unlinked_bucket = -1;
		xfs_trans_ijoin(tp, ip, 0);
		error = xfs_iunlink(tp, ip);
		if (error) {
			pr_warn("mxfs: P98-ORPHAN-ADOPT-FAIL ino=%llu rc=%d\n",
				(unsigned long long)ino, error);
			goto next_cancel;
		}
		error = xfs_trans_commit(tp);
		tp = NULL;
		if (!error) {
			adopted++;
			pr_warn("mxfs: P98-ORPHAN-ADOPT ino=%llu gen=%u bucket=%d — bucketless zombie adopted for reap\n",
				(unsigned long long)ino,
				VFS_I(ip)->i_generation,
				(int)ip->i_unlinked_bucket);
			mxfs_defer_reap_add_mode(mp, ino,
						 VFS_I(ip)->i_generation,
						 ip->i_unlinked_bucket,
						 MXFS_REAP_ADOPTED);
		}
		mxfs_ag_dlm_unlock(mp, pag);
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		xfs_irele(ip);
		xfs_perag_put(pag);
		continue;
next_cancel:
		if (tp)
			xfs_trans_cancel(tp);
		if (ag_locked)
			mxfs_ag_dlm_unlock(mp, pag);
		xfs_iunlock(ip, XFS_ILOCK_EXCL);
		xfs_irele(ip);
		xfs_perag_put(pag);
	}
	kvfree(ctx.cand);
	if (ctx.n || adopted)
		pr_warn("mxfs: P98-ORPHAN-SCAN-DONE cand=%u adopted=%u bucketed=%u changed=%u own_reloaded=%u\n",
			ctx.n, adopted, member, changed, member_own_reloaded);
	return 0;
}

/*
 * (D-TWO-VICTIM-DEATH-SECOND-SLICE-REPLAY-NOT-STARTED-0514) instrumented
 * instrumentation.  Hypothesis H1: the foreign-replay work item finished
 * victim A, entered the inline tail sweep of A's bucket, and that sweep
 * blocked on a DLM acquire for a resource held by victim B (dead 62 s,
 * still undetected, grants on the wire); B's death notify then set its bit
 * and queue_work()ed the SAME work_struct, which cannot run a second
 * instance while the first sits in the sweep — B's replay (the only thing
 * that purges B's grants) waits behind the sweep that waits for it.
 *   - P97-SWEEP-STEP: every sweep step that took >= 1 s, naming the AG and
 *     the step (read_agi / iget / inodegc_flush) — wait provenance.
 *   - dbg_sweep_hold_ms (TEST ONLY): after P97-SWEEP-START the sweep parks
 *     until a NEW dead slot appears (or the budget expires), then holds a
 *     further dbg_sweep_hold_ms so the log shows whether the second
 *     victim's replay can start while the sweep is inside the work item.
 */
static int mxfs_dbg_sweep_hold_ms;
module_param_named(dbg_sweep_hold_ms, mxfs_dbg_sweep_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_sweep_hold_ms,
	"Fault injection (D-0514): park the survivor bucket sweep after SWEEP-START until a new dead slot is notified, then hold this many ms more (0=off default)");

static void
mxfs_sweep_step_report(
	struct xfs_perag	*pag,
	int			bucket,
	const char		*step,
	unsigned long		t0,
	int			rc)
{
	unsigned int		ms = jiffies_to_msecs(jiffies - t0);

	if (ms >= 1000)
		mxfs_probe("mxfs: P97-SWEEP-STEP agno=%u bucket=%d step=%s ms=%u rc=%d dead_slots=0x%llx — sweep step waited on a DLM acquire (D-0514 provenance)\n",
			pag_agno(pag), bucket, step, ms, rc,
			(unsigned long long)pag_mount(pag)->m_mxfs_foreign_dead_slots[0]);
}

static int
mxfs_survivor_sweep_bucket_ag(
	struct xfs_perag	*pag,
	int			bucket)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_buf		*agibp;
	struct xfs_agi		*agi;
	xfs_agino_t		agino;
	int			error;
	int			walked = 0;
	unsigned long		t0 = jiffies;

	error = xfs_read_agi(pag, NULL, 0, &agibp);
	mxfs_sweep_step_report(pag, bucket, "read_agi", t0, error);
	if (error)
		return error;
	agi = agibp->b_addr;
	agino = be32_to_cpu(agi->agi_unlinked[bucket]);
	xfs_buf_relse(agibp);

	while (agino != NULLAGINO) {
		struct xfs_inode	*ip;
		xfs_agino_t		next;

		t0 = jiffies;
		error = xfs_iget(mp, NULL, xfs_agino_to_ino(pag, agino),
				 XFS_IGET_UNTRUSTED, 0, &ip);
		mxfs_sweep_step_report(pag, bucket, "iget", t0, error);
		if (error) {
			pr_warn("mxfs: P97-SWEEP-IGET-FAIL agno=%u bucket=%d agino=0x%x rc=%d — sweep pass aborted, stays pending\n",
				pag_agno(pag), bucket, agino, error);
			return error;
		}
		next = ip->i_next_unlinked;
		/*
		 * v2 (PROVEN by the first unlinker_death run): setting
		 * MXFS_IF_LOCAL_UNLINK here is NOT durable — any later inode
		 * reload strips it (clear-on-reload), and the
		 * retirement inactivation then B4-skips with local_unlink=0
		 * (INACT-SKIP-STALE, ino=132 leaked).  Authority must be
		 * re-derived at every free attempt: enqueue a FREER reap
		 * entry instead; the worker re-restores LOCAL_UNLINK+bucket
		 * on a fresh iget under its generation check each retry.
		 */
		/* v3 (PROVEN, run 2): the cached copy's nlink can be
		 * STALE-HIGH here — this node may never have observed the
		 * dead peer's droplink (opener==survivor shape read
		 * nlink=1 and skipped the enqueue; the close-time RETIRE
		 * entry then had no authority and B4 leaked the zombie).
		 * Chain membership IS the on-disk truth: every inode on
		 * the bucket is a zombie by construction.  Enqueue
		 * unconditionally; the worker makes nlink coherent before
		 * deciding. */
		mxfs_defer_reap_add_mode(mp, ip->i_ino,
					 VFS_I(ip)->i_generation,
					 (int16_t)bucket,
					 MXFS_REAP_ADOPTED);
		walked++;
		xfs_irele(ip);
		t0 = jiffies;
		error = xfs_inodegc_flush(mp);
		mxfs_sweep_step_report(pag, bucket, "inodegc_flush", t0, error);
		if (error)
			return error;
		agino = next;
	}
	if (walked)
		pr_warn("mxfs: P97-SWEEP-AG agno=%u bucket=%d walked=%d — dead-slot zombies re-driven through inactivation\n",
			pag_agno(pag), bucket, walked);
	return 0;
}

int
mxfs_survivor_sweep_slot(
	struct xfs_mount	*mp,
	unsigned int		dead_slot)
{
	struct xfs_perag	*pag = NULL;
	int			bucket = (int)(dead_slot %
					       XFS_AGI_UNLINKED_BUCKETS);
	int			error = 0;

	if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
		return -EAGAIN;
	mxfs_probe("mxfs: P97-SWEEP-START slot=%u bucket=%d inv=%d dead_slots=0x%llx — elected survivor adopting dead slot's unlinked bucket\n",
		dead_slot, bucket, atomic_read(&mxfs_freplay_work_inv),
		(unsigned long long)mp->m_mxfs_foreign_dead_slots[0]);
	if (unlikely(mxfs_dbg_sweep_hold_ms > 0)) {
		/* D-0514 TEST ONLY: park until a NEW dead slot is
		 * notified (budget 4 x hold), then hold dbg_sweep_hold_ms more
		 * so the trail shows whether that slot's replay can start
		 * while this sweep occupies the work item. */
		int waited = 0, held = 0;

		while (bitmap_empty(mp->m_mxfs_foreign_dead_slots, 64) &&
		       waited < 4 * mxfs_dbg_sweep_hold_ms) {
			msleep(100);
			waited += 100;
		}
		mxfs_probe("mxfs: P-DBG-SWEEP-HOLD slot=%u waited_ms=%d dead_slots=0x%llx inv=%d — TEST: sweep parked inside its work item; holding %d ms more\n",
			dead_slot, waited,
			(unsigned long long)mp->m_mxfs_foreign_dead_slots[0],
			atomic_read(&mxfs_freplay_work_inv),
			mxfs_dbg_sweep_hold_ms);
		while (held < mxfs_dbg_sweep_hold_ms) {
			msleep(500);
			held += 500;
		}
		mxfs_probe("mxfs: P-DBG-SWEEP-HOLD-END slot=%u dead_slots=0x%llx inv=%d\n",
			dead_slot,
			(unsigned long long)mp->m_mxfs_foreign_dead_slots[0],
			atomic_read(&mxfs_freplay_work_inv));
	}
	while ((pag = xfs_perag_next(mp, pag))) {
		int err2 = mxfs_survivor_sweep_bucket_ag(pag, bucket);

		if (err2 && !error)
			error = err2;
	}
	mxfs_probe("mxfs: P97-SWEEP-DONE slot=%u bucket=%d rc=%d\n",
		dead_slot, bucket, error);
	/* the bucket sweep only covers zombies the dead node managed
	 * to bucket.  A partial pre-death destage can leave BUCKETLESS
	 * zombies (D-DESTAGE-TEAR-BUCKETLESS-ORPHAN) — scan and adopt them
	 * now.  A scan failure keeps the slot pending so the reap worker
	 * retries both. */
	if (!error)
		error = mxfs_orphan_scan(mp);
	return error;
}

/*
 * OWN-bucket rescan.  Residue on OUR slot's bucket that no reap
 * entry tracks: prior-incarnation zombies after a reclaim-style remount,
 * offline chk_mxfs orphan repairs that landed on our bucket, or an entry
 * lost to P87-REAP-ADD-ENOMEM.  The sweep enqueues every chain member
 * (deduped in mxfs_defer_reap_add_mode); open-tracking gates still defer
 * anything genuinely open.
 */
int
mxfs_own_bucket_rescan(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;
	int			slot, bucket, error = 0;

	if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp) || !mp->m_mxfs_dlm)
		return -EAGAIN;
	slot = mxfs_v5_dlm_local_slot(mp->m_mxfs_dlm);
	if (slot < 0)
		return -EAGAIN;
	bucket = slot % XFS_AGI_UNLINKED_BUCKETS;
	while ((pag = xfs_perag_next(mp, pag))) {
		int err2 = mxfs_survivor_sweep_bucket_ag(pag, bucket);

		if (err2 && !error)
			error = err2;
	}
	if (!error)
		mxfs_probe("mxfs: P96-OWN-RESCAN slot=%d bucket=%d — own-bucket residue re-driven\n",
			slot, bucket);
	return error;
}

static bool
mxfs_bucket_nonempty(
	struct xfs_mount	*mp,
	int			bucket)
{
	struct xfs_perag	*pag = NULL;
	bool			nonempty = false;

	while ((pag = xfs_perag_next(mp, pag))) {
		struct xfs_buf	*agibp;

		if (!nonempty &&
		    xfs_read_agi(pag, NULL, 0, &agibp) == 0) {
			struct xfs_agi *agi = agibp->b_addr;

			if (be32_to_cpu(agi->agi_unlinked[bucket]) !=
			    NULLAGINO)
				nonempty = true;
			xfs_buf_relse(agibp);
		}
	}
	return nonempty;
}

/*
 * guarded UNCLAIMED-bucket pass (review-ruled closure of the
 * D-DESTAGE-TEAR orphan family's cold side).  A non-empty bucket whose
 * slot nobody claims has no owner to reap it: offline chk repairs land on
 * agino%64, a survivor can die after its sweep retired the dead slot but
 * before its reap entries drained, and a shrunk cluster never re-claims
 * old slots.  For each such bucket: take the on-disk recovery GUARD (the
 * cluster-visible exclusion against a joiner claiming the slot mid-sweep;
 * the CAS is also the election between concurrent scanners), re-drive the
 * bucket through the standard sweep, release.  A guard holder that dies
 * leaves a stale guard: claimable again, and the next trigger (mount
 * settle / recovery batch) or the new claimant's own-bucket rescan redoes
 * the idempotent work.  Then one orphan scan for BUCKETLESS zombies with
 * no death event to trigger the survivor-side scan (full-cluster crash).
 */
/*
 * Test-only race widener (0.11.356): hold the recovery guard for this many
 * ms after P99-UBSWEEP-START before sweeping, refreshing the guard every
 * 500ms so it stays visibly LIVE.  Lets a harness mount a joiner (must skip
 * the guarded slot) or kill the holder (peer must detect abandonment by
 * no-movement) inside a window that is otherwise ~100ms.  Default 0 = off.
 */
static int mxfs_ubsweep_hold_ms;
module_param_named(ubsweep_hold_ms, mxfs_ubsweep_hold_ms, int, 0644);
MODULE_PARM_DESC(ubsweep_hold_ms,
	"debug: hold recovery guard N ms (refreshing) before unclaimed-bucket sweep (default 0)");

/*
 * Test-only stall (0.11.358): after the hold, STOP refreshing for this many
 * ms, then proceed to the sweep as if nothing happened — the paused-holder-
 * resumes scenario.  A peer that probes during the stall sees frozen
 * timestamps, judges the guard abandoned, and reclaims it; the resumed
 * holder's first per-AG guard_refresh then CAS-fails (P99-GUARD-LOST) and
 * the sweep aborts having mutated nothing.  Default 0 = off.
 */
static int mxfs_ubsweep_stall_ms;
module_param_named(ubsweep_stall_ms, mxfs_ubsweep_stall_ms, int, 0644);
MODULE_PARM_DESC(ubsweep_stall_ms,
	"debug: after hold, stall N ms WITHOUT refreshing before sweeping (default 0)");

int
mxfs_unclaimed_bucket_scan(
	struct xfs_mount	*mp)
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	int			b, my, rc = 0;

	if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp) || !dlm)
		return -EAGAIN;
	my = mxfs_v5_dlm_local_slot(dlm);
	if (my < 0)
		return -EAGAIN;

	for (b = 0; b < XFS_AGI_UNLINKED_BUCKETS; b++) {
		struct xfs_perag *pag = NULL;
		int		src = 0;

		if (xfs_is_shutdown(mp))
			return -EAGAIN;
		if (b == my)
			continue;
		if (mxfs_v5_dlm_slot_unclaimed(dlm, b) != 1)
			continue;
		if (!mxfs_bucket_nonempty(mp, b))
			continue;
		if (mxfs_v5_dlm_guard_slot(dlm, b))
			continue;	/* lost the race / busy: not ours */
		mxfs_probe("mxfs: P99-UBSWEEP-START slot=%d — sweeping unclaimed slot's bucket under recovery guard\n",
			b);
		if (mxfs_ubsweep_hold_ms > 0) {
			int held = 0;

			mxfs_probe("mxfs: P99-UBSWEEP-HOLD slot=%d ms=%d — debug guard hold\n",
				b, mxfs_ubsweep_hold_ms);
			while (held < mxfs_ubsweep_hold_ms && !src &&
			       !xfs_is_shutdown(mp)) {
				mxfs_pal_sleep_ms(500);
				held += 500;
				if (mxfs_v5_dlm_guard_refresh(dlm))
					src = -ESTALE;
			}
		}
		if (mxfs_ubsweep_stall_ms > 0 && !src) {
			int stalled = 0;

			pr_warn("mxfs: P99-UBSWEEP-STALL slot=%d ms=%d — debug: holder stalls, no refresh\n",
				b, mxfs_ubsweep_stall_ms);
			while (stalled < mxfs_ubsweep_stall_ms &&
			       !xfs_is_shutdown(mp)) {
				mxfs_pal_sleep_ms(500);
				stalled += 500;
			}
		}
		while ((pag = xfs_perag_next(mp, pag))) {
			/* the refresh is not only our own liveness
			 * check — it is what makes this guard's timestamp MOVE,
			 * which is the only cross-node-sound way for a peer to
			 * tell a live sweeper from a dead one (see
			 * hb_guard_abandoned; these clocks are per-node
			 * uptimes and cannot be compared directly).  Refresh
			 * every AG so a peer sampling ~3 refresh intervals
			 * apart always sees movement while we are alive. */
			if (!src && mxfs_v5_dlm_guard_refresh(dlm))
				src = -ESTALE;	/* guard lost: stop enqueuing */
			if (!src) {
				int e2 = mxfs_survivor_sweep_bucket_ag(pag, b);

				if (e2)
					src = e2;
			}
		}
		mxfs_v5_dlm_unguard_slot(dlm);
		mxfs_probe("mxfs: P99-UBSWEEP-DONE slot=%d rc=%d\n", b, src);
		if (src && !rc)
			rc = src;
	}
	if (!rc)
		rc = mxfs_orphan_scan(mp);
	return rc;
}
