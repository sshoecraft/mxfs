// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_inode_item.h"
#include "xfs_mxfs_dlm.h"	/* sess19: mxfs_note_fork_tear tripwire */
#include "../../dlm/v5_mount.h"	/* sess33: P234 single-node gate */

#include <linux/iversion.h>

/*
 * Add a locked inode to the transaction.
 *
 * The inode must be locked, and it cannot be associated with any transaction.
 * If lock_flags is non-zero the inode will be unlocked on transaction commit.
 */
void
xfs_trans_ijoin(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	uint			lock_flags)
{
	struct xfs_inode_log_item *iip;

	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	if (ip->i_itemp == NULL)
		xfs_inode_item_init(ip, ip->i_mount);
	iip = ip->i_itemp;

	ASSERT(iip->ili_lock_flags == 0);
	iip->ili_lock_flags = lock_flags;
	ASSERT(!xfs_iflags_test(ip, XFS_ISTALE));

	/* Reset the per-tx dirty context and add the item to the tx. */
	iip->ili_dirty_flags = 0;
	xfs_trans_add_item(tp, &iip->ili_item);
}

/*
 * Transactional inode timestamp update. Requires the inode to be locked and
 * joined to the transaction supplied. Relies on the transaction subsystem to
 * track dirty state and update/writeback the inode accordingly.
 */
void
xfs_trans_ichgtime(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	int			flags)
{
	struct inode		*inode = VFS_I(ip);
	struct timespec64	tv;

	ASSERT(tp);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);

	/* If the mtime changes, then ctime must also change */
	ASSERT(flags & XFS_ICHGTIME_CHG);

	tv = inode_set_ctime_current(inode);
	if (flags & XFS_ICHGTIME_MOD)
		inode_set_mtime_to_ts(inode, tv);
	if (flags & XFS_ICHGTIME_ACCESS)
		inode_set_atime_to_ts(inode, tv);
	if (flags & XFS_ICHGTIME_CREATE)
		ip->i_crtime = tv;
}

/*
 * This is called to mark the fields indicated in fieldmask as needing to be
 * logged when the transaction is committed.  The inode must already be
 * associated with the given transaction. All we do here is record where the
 * inode was dirtied and mark the transaction and inode log item dirty;
 * everything else is done in the ->precommit log item operation after the
 * changes in the transaction have been completed.
 */
void
xfs_trans_log_inode(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	uint			flags)
{
	struct xfs_inode_log_item *iip = ip->i_itemp;
	struct inode		*inode = VFS_I(ip);

	ASSERT(iip);
	xfs_assert_ilocked(ip, XFS_ILOCK_EXCL);
	ASSERT(!xfs_iflags_test(ip, XFS_ISTALE));

	/*
	 * sess14 (ccloop c7ee71c6) D3 residual — publication obligation,
	 * wiring step 1 of 4 (design + remaining steps at xfs_inode.h's
	 * i_mxfs_pub_pending_seq block; rationale in ccmemory sess14-J).
	 * Every logged inode-core change creates an obligation to land that
	 * change at the home location before the DLM grant is handed off.
	 * This is the single chokepoint for "a change was committed" and is
	 * deliberately independent of ili_fields / XFS_LI_DIRTY / AIL
	 * membership — those all read clean while a committed change sits in
	 * the log, which is exactly how the release drain came to print
	 * "flushed=1 wrote=0 rerr=-11" and then release the grant, durably
	 * losing peers' dirents (tests/logs/firstcc_205730).
	 * We hold ILOCK_EXCL here (asserted above), so a plain increment is
	 * safe.  Counter only — nothing consumes it until step 3 gates the
	 * drain's success return on pending == durable.
	 */
	/*
	 * sess382 (D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380): NOT for
	 * the release drain's own gated re-log.  That re-log re-logs the SAME
	 * in-core core purely to get it flushed after a fence abandoned the
	 * previous attempt (P146V-UNLANDED); it represents no new committed
	 * change, so counting it as a new obligation is simply wrong — and it
	 * is what made the obligation UNCLOSEABLE: every retry pushed pending
	 * past whatever the eventual flush could stamp, so flush_seq < pending
	 * held permanently, the state read as cls=UNCOPIED forever, and the
	 * defer episode wedged the mount.  MEASURED (injected fence, ino 132):
	 * pending ran 6 -> 730 while flush stayed frozen at 6.
	 *
	 * i_mxfs_pipe_relog is the existing marker for exactly this caller —
	 * set around the re-log in mxfs_dlm_bast_process and already consulted
	 * by the P234 authority probe below as "the pipeline's own gated
	 * re-log".  Nothing else sets it.
	 */
	if (!(mxfs_relog_holds_obligation && READ_ONCE(ip->i_mxfs_pipe_relog)))
		ip->i_mxfs_pub_pending_seq++;

	/*
	 * sess32 P230: this mutation is being logged under an ILOCK that was
	 * acquired through ilock_try's atomic-context DLM BYPASS — no tenure,
	 * no DEMOTING gate, invisible to the release pipeline.  If this ever
	 * fires, the bypass arm must refuse EX (see P229 in xfs_mxfs_dlm.c).
	 */
	if (unlikely(READ_ONCE(ip->i_mxfs_atomic_bypass_ns))) {
		static atomic_t p230_n = ATOMIC_INIT(0);
		int p230 = atomic_inc_return(&p230_n);

		if (p230 <= 200)
			pr_warn("mxfs: P230-LOG-UNDER-ATOMIC-BYPASS ino=%llu pend=%llu age_us=%llu comm=%s n=%d — inode logged under a DLM-bypassed atomic trylock grant\n",
				(unsigned long long)ip->i_ino,
				(unsigned long long)ip->i_mxfs_pub_pending_seq,
				(unsigned long long)((ktime_get_ns() -
					ip->i_mxfs_atomic_bypass_ns) / 1000),
				current->comm, p230);
		WRITE_ONCE(ip->i_mxfs_atomic_bypass_ns, 0);
	}

	/*
	 * sess33 P234 — SOURCE counter for GPT's D-RELEASE-BARRIER closure
	 * criterion 3 ("inodegc dirty-at-NL" generalized): a publication
	 * obligation is being created RIGHT NOW; under what cluster authority?
	 * Every correct multinode mutator holds this inode's DLM grant at EX
	 * (xfs_ilock admission).  A stamp at NL means a mutation is being
	 * committed with NO tenure — the release pipeline will never see or
	 * land it (the orphan/inodegc hazard class, also any future
	 * authority-bypass regression).  A stamp at PR/CR means publishing
	 * under a shared grant.  Legit-looking firers to attribute before
	 * judging: the release drain's own clean-but-unlanded re-log (P146V,
	 * comm=kworker) and never-DLM-covered internal inodes (ino names
	 * them).  Counters ride the P220 release-barrier dump.
	 */
	if (ip->i_mount->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm)) {
		uint8_t p234_m = READ_ONCE(ip->i_dlm_mode);

		/*
		 * sess33 refinement (RULE 4, attributed on the 289 board):
		 * i_dlm_mode alone is the WRONG authority sensor during a
		 * BAST drain — drain site 2 clears it to NL while the
		 * on-disk mirror grant is still ours, and the FIX-25/26/27
		 * nested admissions (ioend conversion, writeback submitter)
		 * legitimately mutate in that window.  Every such admit is
		 * counted in i_dlm_ex_holders, and ANY local EX holder pins
		 * the wire grant (the P15 holders-recheck aborts + re-arms
		 * the release, whose re-drain lands these commits before any
		 * handoff).  Authorized therefore = mode EX, or a live local
		 * EX holder census, or the pipeline's own gated re-log.  The
		 * true bypasses (atomic ilock_try, ILOCK-nowait) inc neither
		 * and stay caught.
		 */
		if (unlikely(p234_m != MXFS_LOCK_EX &&
			     READ_ONCE(ip->i_dlm_ex_holders) == 0 &&
			     !READ_ONCE(ip->i_mxfs_pipe_relog))) {
			extern atomic64_t mxfs_lognoex_nl, mxfs_lognoex_pr;
			static atomic_t p234_n = ATOMIC_INIT(0);
			int p234;

			if (p234_m == MXFS_LOCK_NL)
				atomic64_inc(&mxfs_lognoex_nl);
			else
				atomic64_inc(&mxfs_lognoex_pr);
			p234 = atomic_inc_return(&p234_n);
			if (p234 <= 200)
				pr_warn("mxfs: P234-LOG-NOEX ino=%llu mode=%u flags=0x%x pend=%llu nlink=%u isdir=%d comm=%s caller=%pS n=%d\n",
					(unsigned long long)ip->i_ino,
					p234_m, flags,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					VFS_I(ip)->i_nlink,
					S_ISDIR(VFS_I(ip)->i_mode) ? 1 : 0,
					current->comm,
					__builtin_return_address(0), p234);
		}
	}

	/*
	 * sess19 TORN-FORK TRIPWIRE (dossier at mxfs_note_fork_tear).  This is
	 * the step that turns a half-rebuilt LOCAL fork into a dirty log item
	 * the AIL will try to flush forever, so it is the right place to name
	 * the producer with a stack.
	 */
	mxfs_note_fork_tear(ip, "trans_log_inode");

	/* sess2 (a9a03929) P2G-LOGWHO: name whoever logs a REGULAR file's
	 * core during the rm-phase window (P2D-DRAINWHY shows every rm-target
	 * inode dirty-in-AIL with fields=0x1 at its own release, re-appearing
	 * per inode after the shared cluster buffer was already flushed —
	 * some path keeps re-logging them).  Fires for REG inodes only, with
	 * the caller so the logging site is named in one run. */
	if (unlikely(S_ISREG(VFS_I(ip)->i_mode)) && ip->i_mount &&
	    ip->i_mount->m_mxfs_dlm)
		pr_warn_ratelimited("mxfs: P2G-LOGWHO ino=%llu flags=0x%x dlm_state=%u comm=%s caller=%pS\n",
			(unsigned long long)ip->i_ino, flags,
			ip->i_dlm_state, current->comm,
			__builtin_return_address(0));

	tp->t_flags |= XFS_TRANS_DIRTY;

	/*
	 * sess17b (ccloop 4eef1f39, Gemini DLM-epoch lineage guard): bind this
	 * dirtying to the current EX tenure.  Modifications only happen while we
	 * hold the inode EX (multinode write authority), so i_mxfs_ex_grant_seq is
	 * the epoch of the tenure under which this change was made.  If we later
	 * yield EX and re-acquire it (bumping ex_grant_seq), this dirty_seq will no
	 * longer match and the flush path (xfs_iflush_int) treats the in-core image
	 * as a stale ghost rather than clobbering a peer's live on-disk inode.
	 * Memory-only, under ILOCK_EXCL.
	 */
	ip->i_mxfs_dirty_seq = ip->i_mxfs_ex_grant_seq;
	/* sess22 P197: wall clock of this dirtying, so a probe can test P6's
	 * "modified under the CURRENT tenure" claim against the tenure's own
	 * acquire timestamp.  See xfs_inode.h i_mxfs_dirty_ns. */
	ip->i_mxfs_dirty_ns = ktime_get_ns();

	/*
	 * First time we log the inode in a transaction, bump the inode change
	 * counter if it is configured for this to occur. While we have the
	 * inode locked exclusively for metadata modification, we can usually
	 * avoid setting XFS_ILOG_CORE if no one has queried the value since
	 * the last time it was incremented. If we have XFS_ILOG_CORE already
	 * set however, then go ahead and bump the i_version counter
	 * unconditionally.
	 */
	/*
	 * sess382 (GPT ruling 2, Q1): the release drain's own gated re-log must
	 * not advance the LOGICAL VERSION either.  Same argument as the
	 * pending_seq suppression above, on the counter that matters more:
	 * di_changecount is MXFS's cross-node freshness stamp, compared by
	 * P-RELOAD-IDENTICAL, P3-REFUSE-OLDER, P189-RELOG-BEHIND-DISK and the
	 * epoch gates.  A re-log is a new PUBLICATION ATTEMPT, not a new logical
	 * modification — "a repeated publication of version 10 should still
	 * contain changecount 10; incrementing it to 11 would falsely claim a
	 * modification occurred."
	 *
	 * Left unsuppressed, a re-log storm walks our in-core version past the
	 * platter's purely from our own repair attempts, and the inode then
	 * looks strictly AHEAD of home — which is exactly the state
	 * P34F-RELOAD-SELFAHEAD-SKIP refuses to adopt over, so the repair
	 * defeats the recovery that would have resolved it.  Self-inflicted,
	 * and the same shape as the pending_seq runaway.
	 *
	 * SAFE BY CONSTRUCTION: the re-log site logs XFS_ILOG_CORE on an
	 * otherwise untouched in-core inode and never calls xfs_trans_ichgtime,
	 * so the only mutation it would make to the persisted image IS this
	 * bump.  i_mxfs_pipe_relog has exactly one setter (the re-log in
	 * mxfs_dlm_bast_process).  The XFS_LI_DIRTY transition itself still
	 * runs — the item must still become dirty so the re-log can be flushed.
	 *
	 * A/B lever: mxfs.relog_holds_version=0 restores the pre-fix bumping.
	 */
	if (!test_and_set_bit(XFS_LI_DIRTY, &iip->ili_item.li_flags)) {
		if (!(mxfs_relog_holds_version &&
		      READ_ONCE(ip->i_mxfs_pipe_relog)) &&
		    IS_I_VERSION(inode) &&
		    inode_maybe_inc_iversion(inode, flags & XFS_ILOG_CORE))
			flags |= XFS_ILOG_IVERSION;
	}

	/*
	 * sess6 (ccloop 46efd8b6) RULE-4 PROVEN (run 112803Z, test12 i!=1):
	 * on a multi-node MXFS mount di_changecount is the cross-node reload
	 * freshness stamp (P-RELOAD-IDENTICAL / P3-REFUSE-OLDER / epoch
	 * gates compare it to decide whether a peer modified the inode since
	 * our in-core state loaded).  The upstream bump above fires only on
	 * the log item's clean->dirty TRANSITION — under a storm the item
	 * never leaves the AIL between EX tenures, so a whole tenure of dir
	 * ops (measured: 20 bmbt-leaf rewrites, nx 13->28) left cc frozen at
	 * 1124 cluster-wide, the identical-skip kept a peer's stale loaded
	 * iext across a count-invariant bmbt left-edge resize, and the next
	 * shrink died at xfs_bmap_del_extent_real i!=1.  Force one bump per
	 * CORE-logging transaction (ili_dirty_flags is the per-tx
	 * accumulator, consumed at precommit) so cc is a true modification
	 * counter under MXFS; single-node/non-MXFS keeps upstream laziness.
	 */
	if ((flags & XFS_ILOG_CORE) &&
	    !(iip->ili_dirty_flags & (XFS_ILOG_CORE | XFS_ILOG_IVERSION)) &&
	    !(flags & XFS_ILOG_IVERSION) &&
	    /* sess382 Q1: the forced bump is the OTHER half of the same
	     * suppression — see the block above.  Missing it here would leave
	     * the drain's re-log inflating cc through the MXFS path even after
	     * the upstream path was fixed. */
	    !(mxfs_relog_holds_version && READ_ONCE(ip->i_mxfs_pipe_relog)) &&
	    ip->i_mount && ip->i_mount->m_mxfs_dlm &&
	    IS_I_VERSION(inode)) {
		inode_inc_iversion(inode);
		flags |= XFS_ILOG_IVERSION;
	}

	iip->ili_dirty_flags |= flags;
}

int
xfs_trans_roll_inode(
	struct xfs_trans	**tpp,
	struct xfs_inode	*ip)
{
	int			error;

	xfs_trans_log_inode(*tpp, ip, XFS_ILOG_CORE);
	error = xfs_trans_roll(tpp);
	if (!error)
		xfs_trans_ijoin(*tpp, ip, 0);
	return error;
}
