// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
 * Copyright (c) 2008 Dave Chinner
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_trace.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_buf.h"
#include "xfs_buf_item.h"
#include "xfs_inode.h"
#include "xfs_inode_item.h"

/* mxfs log-wedge diagnostic gate (defined in xfs_mxfs_dlm.c, module param mxfs.instr) */
extern int mxfs_instr_enabled;

/* sess129: latched ON by the P128-AILSTUCK dump; see xfs_trans_priv.h. */
atomic_t mxfs_ailstuck_probe = ATOMIC_INIT(0);

#ifdef DEBUG
/*
 * Check that the list is sorted as it should be.
 *
 * Called with the ail lock held, but we don't want to assert fail with it
 * held otherwise we'll lock everything up and won't be able to debug the
 * cause. Hence we sample and check the state under the AIL lock and return if
 * everything is fine, otherwise we drop the lock and run the ASSERT checks.
 * Asserts may not be fatal, so pick the lock back up and continue onwards.
 */
STATIC void
xfs_ail_check(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
	__must_hold(&ailp->ail_lock)
{
	struct xfs_log_item	*prev_lip;
	struct xfs_log_item	*next_lip;
	xfs_lsn_t		prev_lsn = NULLCOMMITLSN;
	xfs_lsn_t		next_lsn = NULLCOMMITLSN;
	xfs_lsn_t		lsn;
	bool			in_ail;


	if (list_empty(&ailp->ail_head))
		return;

	/*
	 * Sample then check the next and previous entries are valid.
	 */
	in_ail = test_bit(XFS_LI_IN_AIL, &lip->li_flags);
	prev_lip = list_entry(lip->li_ail.prev, struct xfs_log_item, li_ail);
	if (&prev_lip->li_ail != &ailp->ail_head)
		prev_lsn = prev_lip->li_lsn;
	next_lip = list_entry(lip->li_ail.next, struct xfs_log_item, li_ail);
	if (&next_lip->li_ail != &ailp->ail_head)
		next_lsn = next_lip->li_lsn;
	lsn = lip->li_lsn;

	if (in_ail &&
	    (prev_lsn == NULLCOMMITLSN || XFS_LSN_CMP(prev_lsn, lsn) <= 0) &&
	    (next_lsn == NULLCOMMITLSN || XFS_LSN_CMP(next_lsn, lsn) >= 0))
		return;

	spin_unlock(&ailp->ail_lock);
	ASSERT(in_ail);
	ASSERT(prev_lsn == NULLCOMMITLSN || XFS_LSN_CMP(prev_lsn, lsn) <= 0);
	ASSERT(next_lsn == NULLCOMMITLSN || XFS_LSN_CMP(next_lsn, lsn) >= 0);
	spin_lock(&ailp->ail_lock);
}
#else /* !DEBUG */
#define	xfs_ail_check(a,l)
#endif /* DEBUG */

/*
 * Return a pointer to the last item in the AIL.  If the AIL is empty, then
 * return NULL.
 */
static struct xfs_log_item *
xfs_ail_max(
	struct xfs_ail  *ailp)
{
	if (list_empty(&ailp->ail_head))
		return NULL;

	return list_entry(ailp->ail_head.prev, struct xfs_log_item, li_ail);
}

/*
 * Return a pointer to the item which follows the given item in the AIL.  If
 * the given item is the last item in the list, then return NULL.
 */
static struct xfs_log_item *
xfs_ail_next(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	if (lip->li_ail.next == &ailp->ail_head)
		return NULL;

	return list_first_entry(&lip->li_ail, struct xfs_log_item, li_ail);
}

/*
 * This is called by the log manager code to determine the LSN of the tail of
 * the log.  This is exactly the LSN of the first item in the AIL.  If the AIL
 * is empty, then this function returns 0.
 *
 * We need the AIL lock in order to get a coherent read of the lsn of the last
 * item in the AIL.
 */
static xfs_lsn_t
__xfs_ail_min_lsn(
	struct xfs_ail		*ailp)
{
	struct xfs_log_item	*lip = xfs_ail_min(ailp);

	if (lip)
		return lip->li_lsn;
	return 0;
}

xfs_lsn_t
xfs_ail_min_lsn(
	struct xfs_ail		*ailp)
{
	xfs_lsn_t		lsn;

	spin_lock(&ailp->ail_lock);
	lsn = __xfs_ail_min_lsn(ailp);
	spin_unlock(&ailp->ail_lock);

	return lsn;
}

/*
 * sess6(ccloop) FIX-12b: lsn of the LAST (newest) item in the AIL, 0 when
 * empty.  Lets the no-inode BAST release skip its whole-AIL fence when the
 * newest AIL item is already at-or-below the last fully-drained target (the
 * inode-reuse churn fires hundreds of noino releases per round; only the
 * first after new commits needs to push).
 */
xfs_lsn_t
xfs_ail_max_lsn(
	struct xfs_ail		*ailp)
{
	struct xfs_log_item	*lip;
	xfs_lsn_t		lsn = 0;

	spin_lock(&ailp->ail_lock);
	lip = xfs_ail_max(ailp);
	if (lip)
		lsn = lip->li_lsn;
	spin_unlock(&ailp->ail_lock);

	return lsn;
}

/*
 * The cursor keeps track of where our current traversal is up to by tracking
 * the next item in the list for us. However, for this to be safe, removing an
 * object from the AIL needs to invalidate any cursor that points to it. hence
 * the traversal cursor needs to be linked to the struct xfs_ail so that
 * deletion can search all the active cursors for invalidation.
 */
STATIC void
xfs_trans_ail_cursor_init(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur)
{
	cur->item = NULL;
	list_add_tail(&cur->list, &ailp->ail_cursors);
}

/*
 * Get the next item in the traversal and advance the cursor.  If the cursor
 * was invalidated (indicated by a lip of 1), restart the traversal.
 */
struct xfs_log_item *
xfs_trans_ail_cursor_next(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur)
{
	struct xfs_log_item	*lip = cur->item;

	if ((uintptr_t)lip & 1)
		lip = xfs_ail_min(ailp);
	if (lip)
		cur->item = xfs_ail_next(ailp, lip);
	return lip;
}

/*
 * When the traversal is complete, we need to remove the cursor from the list
 * of traversing cursors.
 */
void
xfs_trans_ail_cursor_done(
	struct xfs_ail_cursor	*cur)
{
	cur->item = NULL;
	list_del_init(&cur->list);
}

/*
 * Invalidate any cursor that is pointing to this item. This is called when an
 * item is removed from the AIL. Any cursor pointing to this object is now
 * invalid and the traversal needs to be terminated so it doesn't reference a
 * freed object. We set the low bit of the cursor item pointer so we can
 * distinguish between an invalidation and the end of the list when getting the
 * next item from the cursor.
 */
STATIC void
xfs_trans_ail_cursor_clear(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	struct xfs_ail_cursor	*cur;

	list_for_each_entry(cur, &ailp->ail_cursors, list) {
		if (cur->item == lip)
			cur->item = (struct xfs_log_item *)
					((uintptr_t)cur->item | 1);
	}
}

/*
 * Find the first item in the AIL with the given @lsn by searching in ascending
 * LSN order and initialise the cursor to point to the next item for a
 * ascending traversal.  Pass a @lsn of zero to initialise the cursor to the
 * first item in the AIL. Returns NULL if the list is empty.
 */
struct xfs_log_item *
xfs_trans_ail_cursor_first(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	xfs_lsn_t		lsn)
{
	struct xfs_log_item	*lip;

	xfs_trans_ail_cursor_init(ailp, cur);

	if (lsn == 0) {
		lip = xfs_ail_min(ailp);
		goto out;
	}

	list_for_each_entry(lip, &ailp->ail_head, li_ail) {
		if (XFS_LSN_CMP(lip->li_lsn, lsn) >= 0)
			goto out;
	}
	return NULL;

out:
	if (lip)
		cur->item = xfs_ail_next(ailp, lip);
	return lip;
}

static struct xfs_log_item *
__xfs_trans_ail_cursor_last(
	struct xfs_ail		*ailp,
	xfs_lsn_t		lsn)
{
	struct xfs_log_item	*lip;

	list_for_each_entry_reverse(lip, &ailp->ail_head, li_ail) {
		if (XFS_LSN_CMP(lip->li_lsn, lsn) <= 0)
			return lip;
	}
	return NULL;
}

/*
 * Find the last item in the AIL with the given @lsn by searching in descending
 * LSN order and initialise the cursor to point to that item.  If there is no
 * item with the value of @lsn, then it sets the cursor to the last item with an
 * LSN lower than @lsn.  Returns NULL if the list is empty.
 */
struct xfs_log_item *
xfs_trans_ail_cursor_last(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	xfs_lsn_t		lsn)
{
	xfs_trans_ail_cursor_init(ailp, cur);
	cur->item = __xfs_trans_ail_cursor_last(ailp, lsn);
	return cur->item;
}

/*
 * Splice the log item list into the AIL at the given LSN. We splice to the
 * tail of the given LSN to maintain insert order for push traversals. The
 * cursor is optional, allowing repeated updates to the same LSN to avoid
 * repeated traversals.  This should not be called with an empty list.
 */
static void
xfs_ail_splice(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	struct list_head	*list,
	xfs_lsn_t		lsn)
{
	struct xfs_log_item	*lip;

	ASSERT(!list_empty(list));

	/*
	 * Use the cursor to determine the insertion point if one is
	 * provided.  If not, or if the one we got is not valid,
	 * find the place in the AIL where the items belong.
	 */
	lip = cur ? cur->item : NULL;
	if (!lip || (uintptr_t)lip & 1)
		lip = __xfs_trans_ail_cursor_last(ailp, lsn);

	/*
	 * If a cursor is provided, we know we're processing the AIL
	 * in lsn order, and future items to be spliced in will
	 * follow the last one being inserted now.  Update the
	 * cursor to point to that last item, now while we have a
	 * reliable pointer to it.
	 */
	if (cur)
		cur->item = list_entry(list->prev, struct xfs_log_item, li_ail);

	/*
	 * Finally perform the splice.  Unless the AIL was empty,
	 * lip points to the item in the AIL _after_ which the new
	 * items should go.  If lip is null the AIL was empty, so
	 * the new items go at the head of the AIL.
	 */
	if (lip)
		list_splice(list, &lip->li_ail);
	else
		list_splice(list, &ailp->ail_head);
}

/*
 * Delete the given item from the AIL.
 */
static void
xfs_ail_delete(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	xfs_ail_check(ailp, lip);
	list_del(&lip->li_ail);
	xfs_trans_ail_cursor_clear(ailp, lip);
}

/*
 * Requeue a failed buffer for writeback.
 *
 * We clear the log item failed state here as well, but we have to be careful
 * about reference counts because the only active reference counts on the buffer
 * may be the failed log items. Hence if we clear the log item failed state
 * before queuing the buffer for IO we can release all active references to
 * the buffer and free it, leading to use after free problems in
 * xfs_buf_delwri_queue. It makes no difference to the buffer or log items which
 * order we process them in - the buffer is locked, and we own the buffer list
 * so nothing on them is going to change while we are performing this action.
 *
 * Hence we can safely queue the buffer for IO before we clear the failed log
 * item state, therefore  always having an active reference to the buffer and
 * avoiding the transient zero-reference state that leads to use-after-free.
 */
static inline int
xfsaild_resubmit_item(
	struct xfs_log_item	*lip,
	struct list_head	*buffer_list)
{
	struct xfs_buf		*bp = lip->li_buf;

	if (!xfs_buf_trylock(bp))
		return XFS_ITEM_LOCKED;

	if (!xfs_buf_delwri_queue(bp, buffer_list)) {
		xfs_buf_unlock(bp);
		return XFS_ITEM_FLUSHING;
	}

	/* protected by ail_lock */
	list_for_each_entry(lip, &bp->b_li_list, li_bio_list)
		clear_bit(XFS_LI_FAILED, &lip->li_flags);
	xfs_buf_unlock(bp);
	return XFS_ITEM_SUCCESS;
}

static inline uint
xfsaild_push_item(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	/*
	 * If log item pinning is enabled, skip the push and track the item as
	 * pinned. This can help induce head-behind-tail conditions.
	 */
	if (XFS_TEST_ERROR(ailp->ail_log->l_mp, XFS_ERRTAG_LOG_ITEM_PIN))
		return XFS_ITEM_PINNED;

	/*
	 * Consider the item pinned if a push callback is not defined so the
	 * caller will force the log. This should only happen for intent items
	 * as they are unpinned once the associated done item is committed to
	 * the on-disk log.
	 */
	if (!lip->li_ops->iop_push)
		return XFS_ITEM_PINNED;
	if (test_bit(XFS_LI_FAILED, &lip->li_flags))
		return xfsaild_resubmit_item(lip, &ailp->ail_buf_list);
	return lip->li_ops->iop_push(lip, &ailp->ail_buf_list);
}

/*
 * Compute the LSN that we'd need to push the log tail towards in order to have
 * at least 25% of the log space free.  If the log free space already meets this
 * threshold, this function returns the lowest LSN in the AIL to slowly keep
 * writeback ticking over and the tail of the log moving forward.
 */
static xfs_lsn_t
xfs_ail_calc_push_target(
	struct xfs_ail		*ailp)
{
	struct xlog		*log = ailp->ail_log;
	struct xfs_log_item	*lip;
	xfs_lsn_t		target_lsn;
	xfs_lsn_t		max_lsn;
	xfs_lsn_t		min_lsn;
	int32_t			free_bytes;
	uint32_t		target_block;
	uint32_t		target_cycle;

	lockdep_assert_held(&ailp->ail_lock);

	lip = xfs_ail_max(ailp);
	if (!lip)
		return NULLCOMMITLSN;

	max_lsn = lip->li_lsn;
	min_lsn = __xfs_ail_min_lsn(ailp);

	/*
	 * If we are supposed to push all the items in the AIL, we want to push
	 * to the current head. We then clear the push flag so that we don't
	 * keep pushing newly queued items beyond where the push all command was
	 * run. If the push waiter wants to empty the ail, it should queue
	 * itself on the ail_empty wait queue.
	 */
	if (test_and_clear_bit(XFS_AIL_OPSTATE_PUSH_ALL, &ailp->ail_opstate))
		return max_lsn;

	/* If someone wants the AIL empty, keep pushing everything we have. */
	if (waitqueue_active(&ailp->ail_empty))
		return max_lsn;

	/*
	 * Background pushing - attempt to keep 25% of the log free and if we
	 * have that much free retain the existing target.
	 */
	free_bytes = log->l_logsize - xlog_lsn_sub(log, max_lsn, min_lsn);
	if (free_bytes >= log->l_logsize >> 2)
		return ailp->ail_target;

	target_cycle = CYCLE_LSN(min_lsn);
	target_block = BLOCK_LSN(min_lsn) + (log->l_logBBsize >> 2);
	if (target_block >= log->l_logBBsize) {
		target_block -= log->l_logBBsize;
		target_cycle += 1;
	}
	target_lsn = xlog_assign_lsn(target_cycle, target_block);

	/* Cap the target to the highest LSN known to be in the AIL. */
	if (XFS_LSN_CMP(target_lsn, max_lsn) > 0)
		return max_lsn;

	/* If the existing target is higher than the new target, keep it. */
	if (XFS_LSN_CMP(ailp->ail_target, target_lsn) >= 0)
		return ailp->ail_target;
	return target_lsn;
}

static long
xfsaild_push(
	struct xfs_ail		*ailp)
{
	struct xfs_mount	*mp = ailp->ail_log->l_mp;
	struct xfs_ail_cursor	cur;
	struct xfs_log_item	*lip;
	xfs_lsn_t		lsn;
	long			tout;
	int			stuck = 0;
	int			flushing = 0;
	int			count = 0;
	/* mxfs log-wedge diagnostic (gated by mxfs.instr) */
	int			i_pinned = 0, i_locked = 0, i_success = 0;
	unsigned int		first_stuck_type = 0;
	xfs_lsn_t		dbg_max_lsn = 0;

	/*
	 * If we encountered pinned items or did not finish writing out all
	 * buffers the last time we ran, force a background CIL push to get the
	 * items unpinned in the near future. We do not wait on the CIL push as
	 * that could stall us for seconds if there is enough background IO
	 * load. Stalling for that long when the tail of the log is pinned and
	 * needs flushing will hard stop the transaction subsystem when log
	 * space runs out.
	 */
	if (ailp->ail_log_flush && ailp->ail_last_pushed_lsn == 0 &&
	    (!list_empty_careful(&ailp->ail_buf_list) ||
	     xfs_ail_min_lsn(ailp))) {
		ailp->ail_log_flush = 0;

		XFS_STATS_INC(mp, xs_push_ail_flush);
		xlog_cil_flush(ailp->ail_log);
	}

	spin_lock(&ailp->ail_lock);
	WRITE_ONCE(ailp->ail_target, xfs_ail_calc_push_target(ailp));
	if (ailp->ail_target == NULLCOMMITLSN)
		goto out_done;

	/* we're done if the AIL is empty or our push has reached the end */
	lip = xfs_trans_ail_cursor_first(ailp, &cur, ailp->ail_last_pushed_lsn);
	if (!lip)
		goto out_done_cursor;

	XFS_STATS_INC(mp, xs_push_ail);

	ASSERT(ailp->ail_target != NULLCOMMITLSN);

	lsn = lip->li_lsn;
	while ((XFS_LSN_CMP(lip->li_lsn, ailp->ail_target) <= 0)) {
		int	lock_result;

		if (test_bit(XFS_LI_FLUSHING, &lip->li_flags))
			goto next_item;

		/*
		 * Note that iop_push may unlock and reacquire the AIL lock.  We
		 * rely on the AIL cursor implementation to be able to deal with
		 * the dropped lock.
		 */
		lock_result = xfsaild_push_item(ailp, lip);
		if (unlikely(mxfs_instr_enabled) && lock_result != XFS_ITEM_SUCCESS &&
		    !first_stuck_type)
			first_stuck_type = lip->li_type;
		switch (lock_result) {
		case XFS_ITEM_SUCCESS:
			XFS_STATS_INC(mp, xs_push_ail_success);
			trace_xfs_ail_push(lip);

			i_success++;
			ailp->ail_last_pushed_lsn = lsn;
			break;

		case XFS_ITEM_FLUSHING:
			/*
			 * The item or its backing buffer is already being
			 * flushed.  The typical reason for that is that an
			 * inode buffer is locked because we already pushed the
			 * updates to it as part of inode clustering.
			 *
			 * We do not want to stop flushing just because lots
			 * of items are already being flushed, but we need to
			 * re-try the flushing relatively soon if most of the
			 * AIL is being flushed.
			 */
			XFS_STATS_INC(mp, xs_push_ail_flushing);
			trace_xfs_ail_flushing(lip);

			flushing++;
			ailp->ail_last_pushed_lsn = lsn;
			break;

		case XFS_ITEM_PINNED:
			XFS_STATS_INC(mp, xs_push_ail_pinned);
			trace_xfs_ail_pinned(lip);

			i_pinned++;
			stuck++;
			ailp->ail_log_flush++;
			break;
		case XFS_ITEM_LOCKED:
			XFS_STATS_INC(mp, xs_push_ail_locked);
			trace_xfs_ail_locked(lip);

			i_locked++;
			stuck++;
			break;
		default:
			ASSERT(0);
			break;
		}

		count++;

		/*
		 * Are there too many items we can't do anything with?
		 *
		 * If we are skipping too many items because we can't flush
		 * them or they are already being flushed, we back off and
		 * given them time to complete whatever operation is being
		 * done. i.e. remove pressure from the AIL while we can't make
		 * progress so traversals don't slow down further inserts and
		 * removals to/from the AIL.
		 *
		 * The value of 100 is an arbitrary magic number based on
		 * observation.
		 */
		if (stuck > 100)
			break;

next_item:
		lip = xfs_trans_ail_cursor_next(ailp, &cur);
		if (lip == NULL)
			break;
		if (lip->li_lsn != lsn && count > 1000)
			break;
		lsn = lip->li_lsn;
	}

out_done_cursor:
	xfs_trans_ail_cursor_done(&cur);
out_done:
	if (unlikely(mxfs_instr_enabled)) {
		struct xfs_log_item *maxlip = xfs_ail_max(ailp);
		if (maxlip)
			dbg_max_lsn = maxlip->li_lsn;
	}
	spin_unlock(&ailp->ail_lock);

	if (xfs_buf_delwri_submit_nowait(&ailp->ail_buf_list))
		ailp->ail_log_flush++;

	if (!count || XFS_LSN_CMP(lsn, ailp->ail_target) >= 0) {
		/*
		 * We reached the target or the AIL is empty, so wait a bit
		 * longer for I/O to complete and remove pushed items from the
		 * AIL before we start the next scan from the start of the AIL.
		 */
		tout = 50;
		ailp->ail_last_pushed_lsn = 0;
	} else if (((stuck + flushing) * 100) / count > 90) {
		/*
		 * Either there is a lot of contention on the AIL or we are
		 * stuck due to operations in progress. "Stuck" in this case
		 * is defined as >90% of the items we tried to push were stuck.
		 *
		 * Backoff a bit more to allow some I/O to complete before
		 * restarting from the start of the AIL. This prevents us from
		 * spinning on the same items, and if they are pinned will all
		 * the restart to issue a log force to unpin the stuck items.
		 */
		tout = 20;
		ailp->ail_last_pushed_lsn = 0;
	} else {
		/*
		 * Assume we have more work to do in a short while.
		 */
		tout = 0;
	}

	if (unlikely(mxfs_instr_enabled) && dbg_max_lsn != 0) {
		pr_warn("mxfs: P-LWEDGE xfsaild_push count=%d success=%d pinned=%d locked=%d flushing=%d stuck=%d target=0x%llx maxlsn=0x%llx lastpushed=0x%llx log_flush=%d first_stuck_type=%u tout=%ld\n",
			count, i_success, i_pinned, i_locked, flushing, stuck,
			(unsigned long long)ailp->ail_target,
			(unsigned long long)dbg_max_lsn,
			(unsigned long long)ailp->ail_last_pushed_lsn,
			ailp->ail_log_flush, first_stuck_type, tout);
	}

	return tout;
}

static int
xfsaild(
	void		*data)
{
	struct xfs_ail	*ailp = data;
	long		tout = 0;	/* milliseconds */
	unsigned int	noreclaim_flag;

	noreclaim_flag = memalloc_noreclaim_save();
	set_freezable();

	while (1) {
		/*
		 * Long waits of 50ms or more occur when we've run out of items
		 * to push, so we only want uninterruptible state if we're
		 * actually blocked on something.
		 */
		if (tout && tout <= 20)
			set_current_state(TASK_KILLABLE|TASK_FREEZABLE);
		else
			set_current_state(TASK_INTERRUPTIBLE|TASK_FREEZABLE);

		/*
		 * Check kthread_should_stop() after we set the task state to
		 * guarantee that we either see the stop bit and exit or the
		 * task state is reset to runnable such that it's not scheduled
		 * out indefinitely and detects the stop bit at next iteration.
		 * A memory barrier is included in above task state set to
		 * serialize again kthread_stop().
		 */
		if (kthread_should_stop()) {
			__set_current_state(TASK_RUNNING);

			/*
			 * The caller forces out the AIL before stopping the
			 * thread in the common case, which means the delwri
			 * queue is drained. In the shutdown case, the queue may
			 * still hold relogged buffers that haven't been
			 * submitted because they were pinned since added to the
			 * queue.
			 *
			 * Log I/O error processing stales the underlying buffer
			 * and clears the delwri state, expecting the buf to be
			 * removed on the next submission attempt. That won't
			 * happen if we're shutting down, so this is the last
			 * opportunity to release such buffers from the queue.
			 */
			ASSERT(list_empty(&ailp->ail_buf_list) ||
			       xlog_is_shutdown(ailp->ail_log));
			xfs_buf_delwri_cancel(&ailp->ail_buf_list);
			break;
		}

		/* Idle if the AIL is empty. */
		spin_lock(&ailp->ail_lock);
		if (!xfs_ail_min(ailp) && list_empty(&ailp->ail_buf_list)) {
			spin_unlock(&ailp->ail_lock);
			schedule();
			tout = 0;
			continue;
		}
		spin_unlock(&ailp->ail_lock);

		if (tout)
			schedule_timeout(msecs_to_jiffies(tout));

		__set_current_state(TASK_RUNNING);

		try_to_freeze();

		tout = xfsaild_push(ailp);
	}

	memalloc_noreclaim_restore(noreclaim_flag);
	return 0;
}

/*
 * Push out all items in the AIL immediately and wait until the AIL is empty.
 */
void
xfs_ail_push_all_sync(
	struct xfs_ail  *ailp)
{
	DEFINE_WAIT(wait);
	unsigned int iter = 0;

	spin_lock(&ailp->ail_lock);
	while (xfs_ail_max(ailp) != NULL) {
		/*
		 * sess128 RULE-4 probe: this wait has no bound; when it wedges
		 * (test_many_files single-node inodegc pile-up) we need to see
		 * WHAT is stuck.  Every ~30s of waiting (3000 × 10ms), dump
		 * the first few AIL items: type/flags/lsn, plus buf flags or
		 * ino for the two common types.  ail_lock is held here.
		 */
		if (iter && (iter % 3000) == 0) {
			struct xfs_log_item	*dlip;
			int			dk = 0;

			/* sess129: latch the push-path branch probes ON. */
			atomic_set(&mxfs_ailstuck_probe, 1);
			pr_warn("mxfs: P128-AILSTUCK iter=%u comm=%s dumping AIL head:\n",
				iter, current->comm);
			list_for_each_entry(dlip, &ailp->ail_head, li_ail) {
				if (dlip->li_type == XFS_LI_BUF) {
					struct xfs_buf_log_item *dbli =
						container_of(dlip,
						    struct xfs_buf_log_item,
						    bli_item);
					struct xfs_buf *dbp = dbli->bli_buf;

					pr_warn("mxfs: P128-AILSTUCK  [%d] BUF lsn=0x%llx liflags=0x%lx bflags=0x%x daddr=0x%llx pin=%d\n",
						dk, (unsigned long long)dlip->li_lsn,
						dlip->li_flags,
						dbp ? dbp->b_flags : 0,
						dbp ? (unsigned long long)xfs_buf_daddr(dbp) : 0,
						dbp ? atomic_read(&dbp->b_pin_count) : -1);
				} else if (dlip->li_type == XFS_LI_INODE) {
					struct xfs_inode_log_item *dili =
						container_of(dlip,
						    struct xfs_inode_log_item,
						    ili_item);

					pr_warn("mxfs: P128-AILSTUCK  [%d] INODE lsn=0x%llx liflags=0x%lx ino=%llu iflags=0x%lx libuf=%px libuf_flags=0x%x pincount=%d ili_fields=0x%x\n",
						dk, (unsigned long long)dlip->li_lsn,
						dlip->li_flags,
						dili->ili_inode ?
						  (unsigned long long)dili->ili_inode->i_ino : 0,
						dili->ili_inode ?
						  dili->ili_inode->i_flags : 0,
						dlip->li_buf,
						dlip->li_buf ?
						  dlip->li_buf->b_flags : 0,
						dili->ili_inode ?
						  atomic_read(&dili->ili_inode->i_pincount) : -1,
						dili->ili_fields);
				} else {
					pr_warn("mxfs: P128-AILSTUCK  [%d] type=0x%x lsn=0x%llx liflags=0x%lx\n",
						dk, dlip->li_type,
						(unsigned long long)dlip->li_lsn,
						dlip->li_flags);
				}
				if (++dk >= 6)
					break;
			}
		}
		prepare_to_wait(&ailp->ail_empty, &wait, TASK_UNINTERRUPTIBLE);
		wake_up_process(ailp->ail_task);
		spin_unlock(&ailp->ail_lock);
		/*
		 * v0.3.144 sess32: kick CIL push every few iterations.
		 *
		 * Standard XFS upstream relies on xfsaild's natural-pressure
		 * push to drain AIL.  Under MXFS lazy_ag_drain=1, CIL
		 * accumulates faster than the auto-tick can flush it; items
		 * stay PINNED in CIL forever from xfsaild_push's perspective,
		 * so this loop never sees AIL drain.  Standard XFS callers of
		 * xfs_ail_push_all_sync (xfs_inactive_ifree, sync_fs, etc.)
		 * then wedge for hours.
		 *
		 * Async log_force(0) just kicks CIL push; cheap.  Every 4th
		 * iteration is enough to keep CIL flowing without becoming a
		 * SCSI queue contention source.  The async unpin callback
		 * fires on m_cil_workqueue and updates AIL items so xfsaild
		 * can push them on the next round.
		 */
		if ((iter++ & 3) == 0)
			xfs_log_force(ailp->ail_log->l_mp, 0);
		schedule_timeout(msecs_to_jiffies(10));
		spin_lock(&ailp->ail_lock);
	}
	spin_unlock(&ailp->ail_lock);

	finish_wait(&ailp->ail_empty, &wait);
}

/*
 * sess39: BOUNDED whole-AIL sync push.  Like xfs_ail_push_all_sync but gives
 * up after max_ms milliseconds instead of waiting (possibly forever) for the
 * AIL to fully drain.  Used by multi-node sync_fs for cross-node di_size
 * coherence: we want the dirty inode clusters written to disk before a peer
 * FUA-reads them, but the unbounded wait under 4-node DLM contention makes
 * sync(2) so slow the full cache_coherency criterion times out.  A bounded
 * wait writes the vast majority of dirty metadata (a node's ~20 dirty inodes
 * drain in well under a second) while guaranteeing forward progress.
 */
void
xfs_ail_push_all_sync_bounded(
	struct xfs_ail  *ailp,
	unsigned int	max_ms)
{
	DEFINE_WAIT(wait);
	unsigned int iter = 0;
	unsigned int max_iter = max_ms / 10;	/* loop body sleeps ~10ms */

	if (max_iter == 0)
		max_iter = 1;

	spin_lock(&ailp->ail_lock);
	while (xfs_ail_max(ailp) != NULL && iter < max_iter) {
		prepare_to_wait(&ailp->ail_empty, &wait, TASK_UNINTERRUPTIBLE);
		wake_up_process(ailp->ail_task);
		spin_unlock(&ailp->ail_lock);
		if ((iter & 3) == 0)
			xfs_log_force(ailp->ail_log->l_mp, 0);
		schedule_timeout(msecs_to_jiffies(10));
		iter++;
		spin_lock(&ailp->ail_lock);
	}
	spin_unlock(&ailp->ail_lock);

	finish_wait(&ailp->ail_empty, &wait);
}

/*
 * sess6(ccloop a9a03929) FIX-12: LSN-targeted bounded whole-AIL sync push for
 * the no-inode BAST release (Invariant #1 without an extent map).  The noino
 * release cannot scope its drain to the departing inode's dir blocks (no
 * in-core inode => no data fork), and its old single-AG push provably missed
 * cross-AG dir data blocks (run81 r5: bno5@48144232, allocated by a peer's
 * AG-affine grow, held 46 committed adds; the push targeted the inode's AG,
 * the block never landed, the EX handoff exposed the stale platter cluster-
 * wide).  Snapshot the AIL max LSN at entry and push until the AIL min passes
 * it: every item committed BEFORE this release is then on disk, while later
 * commits (concurrent foreground load) cannot livelock the wait.  Returns
 * true when the snapshot target fully landed.
 */
bool
xfs_ail_push_upto_sync_bounded(
	struct xfs_ail  *ailp,
	unsigned int	max_ms,
	xfs_lsn_t	*out_target)
{
	DEFINE_WAIT(wait);
	struct xfs_log_item *maxlip;
	xfs_lsn_t	target, min_lsn;
	unsigned int	iter = 0;
	unsigned int	max_iter = max_ms / 10;	/* loop body sleeps ~10ms */
	bool		drained = true;

	if (max_iter == 0)
		max_iter = 1;

	spin_lock(&ailp->ail_lock);
	maxlip = xfs_ail_max(ailp);
	if (!maxlip) {
		spin_unlock(&ailp->ail_lock);
		if (out_target)
			*out_target = 0;
		return true;
	}
	target = maxlip->li_lsn;
	if (out_target)
		*out_target = target;

	while ((min_lsn = __xfs_ail_min_lsn(ailp)) != 0 &&
	       XFS_LSN_CMP(min_lsn, target) <= 0) {
		if (iter >= max_iter) {
			drained = false;
			break;
		}
		/* waiting on ail_empty makes xfsaild push to max_lsn (see
		 * xfs_ail_calc_push_target's waitqueue_active branch). */
		prepare_to_wait(&ailp->ail_empty, &wait, TASK_UNINTERRUPTIBLE);
		wake_up_process(ailp->ail_task);
		spin_unlock(&ailp->ail_lock);
		if ((iter & 3) == 0)
			xfs_log_force(ailp->ail_log->l_mp, 0);
		schedule_timeout(msecs_to_jiffies(10));
		iter++;
		spin_lock(&ailp->ail_lock);
	}
	spin_unlock(&ailp->ail_lock);

	finish_wait(&ailp->ail_empty, &wait);
	return drained;
}

/*
 * Phase 1 (D8) per-AG AIL drain helper.
 *
 * Returns true if @lip's on-disk target lies in @agno.  Only XFS_LI_BUF
 * (filterable by buf daddr) and XFS_LI_INODE (filterable by inode number)
 * are mapped; other item types fall through to false (treated as not
 * blocking this AG's release — the on-disk metadata they target is
 * reflected in BUF items, which we DO drain).
 */
static bool
xfs_log_item_in_ag(
	struct xfs_log_item	*lip,
	xfs_agnumber_t		agno)
{
	struct xfs_mount	*mp = lip->li_log->l_mp;

	switch (lip->li_type) {
	case XFS_LI_BUF: {
		struct xfs_buf_log_item	*bip;
		struct xfs_buf		*bp;

		bip = container_of(lip, struct xfs_buf_log_item, bli_item);
		bp = bip->bli_buf;
		if (!bp || !bp->b_maps)
			return false;
		if (xfs_daddr_to_agno(mp, xfs_buf_daddr(bp)) != agno)
			return false;
		/*
		 * v0.3.148 sess33: skip ONLY bufs queued by mxfs's
		 * alloc-buflist path (cluster bufs from
		 * xfs_ialloc_inode_init).  These have BOTH _XBF_DELWRI_Q
		 * and _XBF_MXFS_ALLOC_QUEUED set, and they're drained by
		 * mxfs_dlm_ag_drain_alloc_buflist in Phase 2 of
		 * bast_work_fn (NOT by xfsaild — xfsaild's
		 * xfs_buf_delwri_queue would fail because _XBF_DELWRI_Q
		 * is already set, returning XFS_ITEM_FLUSHING).
		 *
		 * Regular xfsaild-managed bufs (dir3 data, agf, agi,
		 * btree blocks logged via normal trans paths) have
		 * _XBF_DELWRI_Q only when xfsaild itself queued them.
		 * They MUST NOT be skipped here — Phase 2 doesn't drain
		 * them.  Skipping them caused sess33 iter-3 dir3 corruption
		 * (signature: xfs_dir3_data_reada_verify on peer after
		 * AG-DLM transition with stale dir block on disk).
		 */
		if ((bp->b_flags & (_XBF_DELWRI_Q | _XBF_MXFS_ALLOC_QUEUED)) ==
		    (_XBF_DELWRI_Q | _XBF_MXFS_ALLOC_QUEUED))
			return false;
		return true;
	}
	case XFS_LI_INODE: {
		struct xfs_inode_log_item *iip;

		iip = container_of(lip, struct xfs_inode_log_item, ili_item);
		if (!iip->ili_inode)
			return false;
		if (XFS_INO_TO_AGNO(mp, iip->ili_inode->i_ino) != agno)
			return false;
		/*
		 * v0.3.148 sess33: items in IFLUSHING state are being flushed
		 * — xfs_iflush_cluster has already written content into the
		 * cluster buf and set IFLUSHING.  The buf may be on
		 * pag_mxfs_alloc_buflist (mxfs's own delwri queue), where it
		 * waits for mxfs_dlm_ag_drain_alloc_buflist (Phase 2 of
		 * bast_work_fn) to submit.  xfsaild's iop_push for these
		 * items returns FLUSHING (because xfs_buf_delwri_queue fails
		 * on already-_XBF_DELWRI_Q bufs), so they're stuck in AIL
		 * until iodone clears IFLUSHING.  Don't WAIT for them in
		 * Phase 1 — Phase 2's drain_alloc_buflist will submit the
		 * cluster buf, iodone clears IFLUSHING + removes the items.
		 * Treating them as "not in AG" lets ail_push_ag_sync return
		 * once non-IFLUSHING items have drained, breaking the
		 * Phase 1 wedge that was the multi-node deadlock root cause.
		 */
		if (xfs_iflags_test(iip->ili_inode, XFS_IFLUSHING))
			return false;
		return true;
	}
	default:
		return false;
	}
}

/*
 * Push AIL items belonging to @agno and wait until none remain.
 * Items in other AGs are not waited on.  See xfs_trans_priv.h for
 * scope and rationale.
 *
 * Walks the global AIL under ail_lock looking for any item whose
 * target lies in @agno; if found, kicks xfsaild and sleeps briefly,
 * then re-walks.  When the walk completes with no match, returns.
 *
 * Cost: O(N) AIL walk per polling iteration under spinlock.  Bounded
 * by AIL depth, which is bounded by reservation accounting.  Polling
 * sleep keeps us off the CPU between walks.
 */
/*
 * v0.3.147 sess33: bounded variant.  Returns 0 if drain completed,
 * -ETIMEDOUT if max_iters reached without items leaving the AG.
 * max_iters=0 disables the bound (legacy unbounded behavior).
 *
 * Detects DEADLOCK STALL via no-progress: if the count of items in
 * @agno fails to decrease for stall_iters consecutive iterations after
 * iter > min_iters, returns -EAGAIN.  Caller (mxfs_dlm_ag_bast_work_fn)
 * then ABORTS the release sequence (does not drop the AG-DLM grant)
 * and reschedules the bast work for a future attempt — peer's CAW
 * poll times out, peer drops its transaction's ILOCK, and the next
 * bast cycle can drain.
 *
 * Differs from sess32 v0.3.141-142's bounded timeout (which proceeded
 * to release after timeout, causing Mode A): on -EAGAIN, the caller
 * MUST NOT release.  Sess27 finding "bounded per-AG drain is unsafe"
 * referred to release-after-bound, not abort-after-bound.
 */
#include <linux/sched/debug.h>	/* sess13(c7ee71c6): sched_show_task */

/* sess13(c7ee71c6): peek the i_lock rwsem owner — a writer, or the last
 * reader hint (RWSEM_READER_OWNED-tagged, best-effort).  Same technique the
 * kernel's own rwsem_spin_on_owner uses; task_struct deref is RCU-safe.
 * Debug read for the AG-AIL stall probe: names the task that blocks iflush. */
static struct task_struct *
mxfs_rwsem_owner_peek(struct rw_semaphore *sem, bool *reader)
{
	unsigned long o = atomic_long_read((atomic_long_t *)&sem->owner);

	*reader = (o & 1UL) != 0;
	return (struct task_struct *)(o & ~7UL);
}

int
xfs_ail_push_ag_sync_bounded(
	struct xfs_ail		*ailp,
	xfs_agnumber_t		agno,
	unsigned int		stall_iters,
	unsigned int		min_iters)
{
	struct xfs_log_item	*lip;
	bool			found;
	unsigned int		last_count = UINT_MAX;
	unsigned int		stall = 0;
	{
		unsigned int iter = 0;
		struct xfs_mount *mp = ailp->ail_log->l_mp;
		for (;;) {
			unsigned int n_buf = 0, n_inode = 0, n_other = 0;
			unsigned int n_pinned_buf = 0;
			unsigned int total;
			xfs_ino_t stuck_ino = 0;
			unsigned int stuck_iflags = 0;
			bool stuck_buf_locked = false;
			/*
			 * sess109 P109-DRAIN: capture the exact iop_push gating
			 * state for the first stuck inode item.  xfs_inode_item_push
			 * returns PINNED if (li_buf==NULL || ISTALE) or
			 * (i_pincount>0 || buf pinned); FLUSHING if IFLUSHING;
			 * LOCKED if buf trylock fails.  These fields disambiguate
			 * which branch wedges the AG-AIL drain.
			 */
			int stuck_pincount = -1;
			bool stuck_libuf_null = false;
			bool stuck_buf_pinned = false;
			unsigned int stuck_ili_fields = 0;
			bool stuck_in_ail = false;
			unsigned int stuck_buf_flags = 0;
			/* sess16 (a9a03929) P16-ILOCKED: k1 tds 2-node wedge — is the
			 * stuck inode's ILOCK rwsem held?  Hypothesis: a rename thread
			 * holds the child's ILOCK (ascending-ino set lock) while its
			 * dir PR->EX conversion EDEADLK-retries cross-node, so iflush
			 * can never take ILOCK_SHARED and the AG drain stalls. */
			bool stuck_ilocked = false;
			/* sess13(c7ee71c6): 32/caw fence wedge forensics — the
			 * incident boot proved a 212s continuously-rwsem-held
			 * stuck inode with the holder invisible to hung_task
			 * (short-sleep/interruptible waits).  Name the holder:
			 * rwsem owner peek + the mxfs_ilk last-locker stamps +
			 * item LSN + log tail/grant heads, and (throttled) dump
			 * the owner task's stack from inside the walk while the
			 * AIL ref keeps the inode live. */
			xfs_lsn_t stuck_lsn = 0, ail_min_lsn = 0;
			struct task_struct *stuck_owner = NULL;
			bool stuck_owner_rd = false;
			char stuck_owner_comm[16] = "";
			int stuck_owner_pid = 0;
			unsigned int stuck_owner_state = 0;
			unsigned long stuck_owner_nvcsw = 0, stuck_owner_nivcsw = 0;
			unsigned long stuck_wr_ret = 0, stuck_rd_ret = 0, stuck_un_ret = 0;
			int stuck_wr_pid = 0, stuck_rd_pid = 0, stuck_rd_held = 0;
			char stuck_wr_comm[16] = "", stuck_rd_comm[16] = "";
			spin_lock(&ailp->ail_lock);
			if (!list_empty(&ailp->ail_head))
				ail_min_lsn = list_first_entry(&ailp->ail_head,
					struct xfs_log_item, li_ail)->li_lsn;
			found = false;
			list_for_each_entry(lip, &ailp->ail_head, li_ail) {
				if (!xfs_log_item_in_ag(lip, agno))
					continue;
				if (!found)
					found = true;
				switch (lip->li_type) {
				case XFS_LI_BUF: {
					struct xfs_buf_log_item *bip;
					bip = container_of(lip,
						struct xfs_buf_log_item,
						bli_item);
					n_buf++;
					if (bip->bli_buf &&
					    atomic_read(&bip->bli_buf->b_pin_count))
						n_pinned_buf++;
					break;
				}
				case XFS_LI_INODE: {
					struct xfs_inode_log_item *iip;
					iip = container_of(lip,
						struct xfs_inode_log_item,
						ili_item);
					n_inode++;
					if (!stuck_ino && iip->ili_inode) {
						stuck_ino = iip->ili_inode->i_ino;
						stuck_iflags = iip->ili_inode->i_flags;
						stuck_ilocked = rwsem_is_locked(
							&iip->ili_inode->i_lock);
						stuck_pincount = atomic_read(&iip->ili_inode->i_pincount);
						stuck_ili_fields = iip->ili_fields;
						stuck_in_ail = test_bit(XFS_LI_IN_AIL,
							&lip->li_flags);
						stuck_libuf_null = (lip->li_buf == NULL);
						if (lip->li_buf) {
							stuck_buf_locked = xfs_buf_islocked(lip->li_buf);
							stuck_buf_pinned = atomic_read(
								&lip->li_buf->b_pin_count) > 0;
							stuck_buf_flags = lip->li_buf->b_flags;
						}
						/* sess13(c7ee71c6) wedge forensics */
						{
							struct xfs_inode *sip = iip->ili_inode;

							stuck_lsn = lip->li_lsn;
							stuck_wr_ret = sip->i_mxfs_ilk_wr_ret;
							stuck_wr_pid = sip->i_mxfs_ilk_wr_pid;
							memcpy(stuck_wr_comm, sip->i_mxfs_ilk_wr_comm,
							       sizeof(stuck_wr_comm) - 1);
							stuck_rd_ret = sip->i_mxfs_ilk_rd_ret;
							stuck_rd_pid = sip->i_mxfs_ilk_rd_pid;
							memcpy(stuck_rd_comm, sip->i_mxfs_ilk_rd_comm,
							       sizeof(stuck_rd_comm) - 1);
							stuck_rd_held = atomic_read(&sip->i_mxfs_ilk_rd_held);
							stuck_un_ret = sip->i_mxfs_ilk_un_ret;
							if (stuck_ilocked) {
								rcu_read_lock();
								stuck_owner = mxfs_rwsem_owner_peek(
									&sip->i_lock, &stuck_owner_rd);
								if (stuck_owner) {
									stuck_owner_pid = stuck_owner->pid;
									memcpy(stuck_owner_comm,
									       stuck_owner->comm,
									       sizeof(stuck_owner_comm) - 1);
									stuck_owner_state = READ_ONCE(
										stuck_owner->__state);
									stuck_owner_nvcsw = stuck_owner->nvcsw;
									stuck_owner_nivcsw = stuck_owner->nivcsw;
									/* Throttled holder stack dump from
									 * inside the walk: the AIL entry keeps
									 * sip live; RCU keeps the task deref
									 * safe (rwsem_spin_on_owner pattern).
									 * Only once a stall episode is on. */
									{
										static unsigned long mxfs_stalldump_j;

										if (stall >= 4 &&
										    time_after(jiffies,
											mxfs_stalldump_j + 30 * HZ)) {
											mxfs_stalldump_j = jiffies;
											pr_warn("mxfs: P67-STALL-OWNER-STACK agno=%u ino=%llu owner=%s/%d rd=%d state=0x%x nvcsw=%lu/%lu — dumping holder stack\n",
												agno,
												(unsigned long long)stuck_ino,
												stuck_owner_comm,
												stuck_owner_pid,
												stuck_owner_rd ? 1 : 0,
												stuck_owner_state,
												stuck_owner_nvcsw,
												stuck_owner_nivcsw);
											sched_show_task(stuck_owner);
										}
									}
								}
								rcu_read_unlock();
							}
						}
					}
					break;
				}
				default:
					n_other++;
					break;
				}
			}
			/*
			 * v0.3.148 sess33: don't return on first iter even
			 * if !found.  Items skipped via xfs_log_item_in_ag
			 * (XFS_IFLUSHING set or _XBF_DELWRI_Q set) need
			 * xfsaild's iop_push to ACTUALLY run before they
			 * can be safely treated as drained.  iop_push for
			 * inode items writes iflushed content into the
			 * cluster buf (Phase 2 drain_alloc_buflist then
			 * submits that current content).  If we return at
			 * iter=0 before xfsaild runs, the cluster buf still
			 * has stale/empty content → peer reads corruption
			 * (xfs_dinode_verify failure observed in sess33).
			 *
			 * Force at least one push+log_force+msleep cycle.
			 * This gives xfsaild time to walk AIL and run
			 * iop_push on items in target AG, which sets
			 * IFLUSHING / writes content / etc.
			 */
			if (!found && iter > 0) {
				spin_unlock(&ailp->ail_lock);
				return 0;
			}
			spin_unlock(&ailp->ail_lock);
			total = n_buf + n_inode + n_other;
			if (stall_iters && iter > min_iters) {
				if (total < last_count) {
					stall = 0;
					last_count = total;
				} else if (++stall >= stall_iters) {
					pr_warn("mxfs: P67-INSTR AG-AIL-STALL-ABORT agno=%u iter=%u stall=%u total=%u(buf=%u inode=%u other=%u pinned=%u)\n",
						agno, iter, stall, total,
						n_buf, n_inode, n_other,
						n_pinned_buf);
					/* sess13(c7ee71c6): name the ILOCK holder +
					 * log/AIL position so the wedge's blocking
					 * task and log-space state are in every
					 * abort line (the incident boot had neither). */
					if (stuck_ino) {
						struct xlog *sl = ailp->ail_log;

						pr_warn("mxfs: P67-STALL-OWNER agno=%u ino=%llu lsn=0x%llx ail_min=0x%llx tail=0x%llx resv=0x%llx write=0x%llx owner=%s/%d rd=%d st=0x%x csw=%lu/%lu wr_last=%pS/%d/%s rd_last=%pS/%d/%s rd_held=%d un_last=%pS\n",
							agno,
							(unsigned long long)stuck_ino,
							(unsigned long long)stuck_lsn,
							(unsigned long long)ail_min_lsn,
							(unsigned long long)atomic64_read(&sl->l_tail_lsn),
							(unsigned long long)atomic64_read(&sl->l_reserve_head.grant),
							(unsigned long long)atomic64_read(&sl->l_write_head.grant),
							stuck_owner ? stuck_owner_comm : "-",
							stuck_owner_pid,
							stuck_owner_rd ? 1 : 0,
							stuck_owner_state,
							stuck_owner_nvcsw,
							stuck_owner_nivcsw,
							(void *)stuck_wr_ret,
							stuck_wr_pid, stuck_wr_comm,
							(void *)stuck_rd_ret,
							stuck_rd_pid, stuck_rd_comm,
							stuck_rd_held,
							(void *)stuck_un_ret);
					}
					return -EAGAIN;
				}
			}
			if (last_count == UINT_MAX || total < last_count)
				last_count = total;
			if (iter > 0 && (iter & 255) == 0)
				pr_warn("mxfs: P67-INSTR AG-AIL-STALL agno=%u iter=%u buf=%u(pinned=%u) inode=%u other=%u stuck_ino=%llu iflags=0x%x buf_locked=%d pin=%d libuf_null=%d buf_pinned=%d ili_fields=0x%x in_ail=%d buf_flags=0x%x ilocked=%d\n",
					agno, iter, n_buf, n_pinned_buf,
					n_inode, n_other,
					(unsigned long long)stuck_ino,
					stuck_iflags, stuck_buf_locked,
					stuck_pincount, stuck_libuf_null,
					stuck_buf_pinned, stuck_ili_fields,
					stuck_in_ail, stuck_buf_flags,
					stuck_ilocked ? 1 : 0);
			xfs_ail_push_all(ailp);
			if ((iter++ & 3) == 0)
				xfs_log_force(mp, 0);
			msleep(10);
		}
	}
}

void
xfs_ail_push_ag_sync(
	struct xfs_ail		*ailp,
	xfs_agnumber_t		agno)
{
	/*
	 * Legacy unbounded wrapper around xfs_ail_push_ag_sync_bounded.
	 * stall_iters=0 disables the stall-abort behavior, preserving
	 * pre-sess33 semantics.  Used by mxfs_dlm_bast_process (inode
	 * BAST drain) where the caller cannot reasonably abort.
	 */
	(void)xfs_ail_push_ag_sync_bounded(ailp, agno, 0, 0);
}

void
__xfs_ail_assign_tail_lsn(
	struct xfs_ail		*ailp)
{
	struct xlog		*log = ailp->ail_log;
	xfs_lsn_t		tail_lsn;

	assert_spin_locked(&ailp->ail_lock);

	if (xlog_is_shutdown(log))
		return;

	tail_lsn = __xfs_ail_min_lsn(ailp);
	if (!tail_lsn)
		tail_lsn = ailp->ail_head_lsn;

	WRITE_ONCE(log->l_tail_space,
			xlog_lsn_sub(log, ailp->ail_head_lsn, tail_lsn));
	trace_xfs_log_assign_tail_lsn(log, tail_lsn);
	atomic64_set(&log->l_tail_lsn, tail_lsn);
}

/*
 * Callers should pass the original tail lsn so that we can detect if the tail
 * has moved as a result of the operation that was performed. If the caller
 * needs to force a tail space update, it should pass NULLCOMMITLSN to bypass
 * the "did the tail LSN change?" checks. If the caller wants to avoid a tail
 * update (e.g. it knows the tail did not change) it should pass an @old_lsn of
 * 0.
 */
void
xfs_ail_update_finish(
	struct xfs_ail		*ailp,
	xfs_lsn_t		old_lsn) __releases(ailp->ail_lock)
{
	struct xlog		*log = ailp->ail_log;

	/* If the tail lsn hasn't changed, don't do updates or wakeups. */
	if (!old_lsn || old_lsn == __xfs_ail_min_lsn(ailp)) {
		spin_unlock(&ailp->ail_lock);
		return;
	}

	__xfs_ail_assign_tail_lsn(ailp);
	if (list_empty(&ailp->ail_head))
		wake_up_all(&ailp->ail_empty);
	spin_unlock(&ailp->ail_lock);
	xfs_log_space_wake(log->l_mp);
}

/*
 * xfs_trans_ail_update_bulk - bulk AIL insertion operation.
 *
 * @xfs_trans_ail_update_bulk takes an array of log items that all need to be
 * positioned at the same LSN in the AIL. If an item is not in the AIL, it will
 * be added. Otherwise, it will be repositioned by removing it and re-adding
 * it to the AIL.
 *
 * If we move the first item in the AIL, update the log tail to match the new
 * minimum LSN in the AIL.
 *
 * This function should be called with the AIL lock held.
 *
 * To optimise the insert operation, we add all items to a temporary list, then
 * splice this list into the correct position in the AIL.
 *
 * Items that are already in the AIL are first deleted from their current
 * location before being added to the temporary list.
 *
 * This avoids needing to do an insert operation on every item.
 *
 * The AIL lock is dropped by xfs_ail_update_finish() before returning to
 * the caller.
 */
void
xfs_trans_ail_update_bulk(
	struct xfs_ail		*ailp,
	struct xfs_ail_cursor	*cur,
	struct xfs_log_item	**log_items,
	int			nr_items,
	xfs_lsn_t		lsn) __releases(ailp->ail_lock)
{
	struct xfs_log_item	*mlip;
	xfs_lsn_t		tail_lsn = 0;
	int			i;
	LIST_HEAD(tmp);

	ASSERT(nr_items > 0);		/* Not required, but true. */
	mlip = xfs_ail_min(ailp);

	for (i = 0; i < nr_items; i++) {
		struct xfs_log_item *lip = log_items[i];
		if (test_and_set_bit(XFS_LI_IN_AIL, &lip->li_flags)) {
			/* check if we really need to move the item */
			if (XFS_LSN_CMP(lsn, lip->li_lsn) <= 0)
				continue;

			trace_xfs_ail_move(lip, lip->li_lsn, lsn);
			if (mlip == lip && !tail_lsn)
				tail_lsn = lip->li_lsn;

			xfs_ail_delete(ailp, lip);
		} else {
			trace_xfs_ail_insert(lip, 0, lsn);
		}
		lip->li_lsn = lsn;
		list_add_tail(&lip->li_ail, &tmp);
	}

	if (!list_empty(&tmp))
		xfs_ail_splice(ailp, cur, &tmp, lsn);

	/*
	 * If this is the first insert, wake up the push daemon so it can
	 * actively scan for items to push. We also need to do a log tail
	 * LSN update to ensure that it is correctly tracked by the log, so
	 * set the tail_lsn to NULLCOMMITLSN so that xfs_ail_update_finish()
	 * will see that the tail lsn has changed and will update the tail
	 * appropriately.
	 */
	if (!mlip) {
		wake_up_process(ailp->ail_task);
		tail_lsn = NULLCOMMITLSN;
	}

	xfs_ail_update_finish(ailp, tail_lsn);
}

/* Insert a log item into the AIL. */
void
xfs_trans_ail_insert(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip,
	xfs_lsn_t		lsn)
{
	spin_lock(&ailp->ail_lock);
	xfs_trans_ail_update_bulk(ailp, NULL, &lip, 1, lsn);
}

/*
 * Delete one log item from the AIL.
 *
 * If this item was at the tail of the AIL, return the LSN of the log item so
 * that we can use it to check if the LSN of the tail of the log has moved
 * when finishing up the AIL delete process in xfs_ail_update_finish().
 */
xfs_lsn_t
xfs_ail_delete_one(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip)
{
	struct xfs_log_item	*mlip = xfs_ail_min(ailp);
	xfs_lsn_t		lsn = lip->li_lsn;

	trace_xfs_ail_delete(lip, mlip->li_lsn, lip->li_lsn);
	xfs_ail_delete(ailp, lip);
	clear_bit(XFS_LI_IN_AIL, &lip->li_flags);
	lip->li_lsn = 0;

	if (mlip == lip)
		return lsn;
	return 0;
}

void
xfs_trans_ail_delete(
	struct xfs_log_item	*lip,
	int			shutdown_type)
{
	struct xfs_ail		*ailp = lip->li_ailp;
	struct xlog		*log = ailp->ail_log;
	xfs_lsn_t		tail_lsn;

	spin_lock(&ailp->ail_lock);
	if (!test_bit(XFS_LI_IN_AIL, &lip->li_flags)) {
		spin_unlock(&ailp->ail_lock);
		if (shutdown_type && !xlog_is_shutdown(log)) {
			xfs_alert_tag(log->l_mp, XFS_PTAG_AILDELETE,
	"%s: attempting to delete a log item that is not in the AIL",
					__func__);
			xlog_force_shutdown(log, shutdown_type);
		}
		return;
	}

	clear_bit(XFS_LI_FAILED, &lip->li_flags);
	tail_lsn = xfs_ail_delete_one(ailp, lip);
	xfs_ail_update_finish(ailp, tail_lsn);	/* drops the AIL lock */
}

int
xfs_trans_ail_init(
	xfs_mount_t	*mp)
{
	struct xfs_ail	*ailp;

	ailp = kzalloc(sizeof(struct xfs_ail),
			GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!ailp)
		return -ENOMEM;

	ailp->ail_log = mp->m_log;
	INIT_LIST_HEAD(&ailp->ail_head);
	INIT_LIST_HEAD(&ailp->ail_cursors);
	spin_lock_init(&ailp->ail_lock);
	INIT_LIST_HEAD(&ailp->ail_buf_list);
	init_waitqueue_head(&ailp->ail_empty);

	ailp->ail_task = kthread_run(xfsaild, ailp, "xfsaild/%s",
				mp->m_super->s_id);
	if (IS_ERR(ailp->ail_task))
		goto out_free_ailp;

	mp->m_ail = ailp;
	return 0;

out_free_ailp:
	kfree(ailp);
	return -ENOMEM;
}

void
xfs_trans_ail_destroy(
	xfs_mount_t	*mp)
{
	struct xfs_ail	*ailp = mp->m_ail;

	kthread_stop(ailp->ail_task);
	kfree(ailp);
}
