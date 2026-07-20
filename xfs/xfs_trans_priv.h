// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000,2002,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_TRANS_PRIV_H__
#define	__XFS_TRANS_PRIV_H__

struct xlog;
struct xfs_log_item;
struct xfs_mount;
struct xfs_trans;
struct xfs_ail;
struct xfs_log_vec;


/*
 * sess129 RULE-4 probe: set (latched) by the P128-AILSTUCK dump in
 * xfs_ail_push_all_sync after ~30s of a non-advancing AIL.  While set,
 * xfs_inode_item_push and xfs_iflush_cluster emit ratelimited branch-
 * outcome logs so we can see WHY the head item never flushes.  Zero
 * overhead until a wedge manifests (single atomic read per call).
 */
extern atomic_t mxfs_ailstuck_probe;

void	xfs_trans_init(struct xfs_mount *);
void	xfs_trans_add_item(struct xfs_trans *, struct xfs_log_item *);
void	xfs_trans_del_item(struct xfs_log_item *);
void	xfs_trans_unreserve_and_mod_sb(struct xfs_trans *tp);

/*
 * AIL traversal cursor.
 *
 * Rather than using a generation number for detecting changes in the ail, use
 * a cursor that is protected by the ail lock. The aild cursor exists in the
 * struct xfs_ail, but other traversals can declare it on the stack and link it
 * to the ail list.
 *
 * When an object is deleted from or moved int the AIL, the cursor list is
 * searched to see if the object is a designated cursor item. If it is, it is
 * deleted from the cursor so that the next time the cursor is used traversal
 * will return to the start.
 *
 * This means a traversal colliding with a removal will cause a restart of the
 * list scan, rather than any insertion or deletion anywhere in the list. The
 * low bit of the item pointer is set if the cursor has been invalidated so
 * that we can tell the difference between invalidation and reaching the end
 * of the list to trigger traversal restarts.
 */
struct xfs_ail_cursor {
	struct list_head	list;
	struct xfs_log_item	*item;
};

/*
 * Private AIL structures.
 *
 * Eventually we need to drive the locking in here as well.
 */
struct xfs_ail {
	struct xlog		*ail_log;
	struct task_struct	*ail_task;
	struct list_head	ail_head;
	struct list_head	ail_cursors;
	spinlock_t		ail_lock;
	xfs_lsn_t		ail_last_pushed_lsn;
	xfs_lsn_t		ail_head_lsn;
	int			ail_log_flush;
	unsigned long		ail_opstate;
	struct list_head	ail_buf_list;
	wait_queue_head_t	ail_empty;
	xfs_lsn_t		ail_target;
};

/* Push all items out of the AIL immediately. */
#define XFS_AIL_OPSTATE_PUSH_ALL	0u

/*
 * From xfs_trans_ail.c
 */
void	xfs_trans_ail_update_bulk(struct xfs_ail *ailp,
				struct xfs_ail_cursor *cur,
				struct xfs_log_item **log_items, int nr_items,
				xfs_lsn_t lsn) __releases(ailp->ail_lock);
/*
 * Return a pointer to the first item in the AIL.  If the AIL is empty, then
 * return NULL.
 */
static inline struct xfs_log_item *
xfs_ail_min(
	struct xfs_ail  *ailp)
{
	return list_first_entry_or_null(&ailp->ail_head, struct xfs_log_item,
					li_ail);
}

static inline void
xfs_trans_ail_update(
	struct xfs_ail		*ailp,
	struct xfs_log_item	*lip,
	xfs_lsn_t		lsn) __releases(ailp->ail_lock)
{
	xfs_trans_ail_update_bulk(ailp, NULL, &lip, 1, lsn);
}

void xfs_trans_ail_insert(struct xfs_ail *ailp, struct xfs_log_item *lip,
		xfs_lsn_t lsn);

xfs_lsn_t xfs_ail_delete_one(struct xfs_ail *ailp, struct xfs_log_item *lip);
void xfs_ail_update_finish(struct xfs_ail *ailp, xfs_lsn_t old_lsn)
			__releases(ailp->ail_lock);
void xfs_trans_ail_delete(struct xfs_log_item *lip, int shutdown_type);

static inline void xfs_ail_push(struct xfs_ail *ailp)
{
	wake_up_process(ailp->ail_task);
}

static inline void xfs_ail_push_all(struct xfs_ail *ailp)
{
	if (!test_and_set_bit(XFS_AIL_OPSTATE_PUSH_ALL, &ailp->ail_opstate))
		xfs_ail_push(ailp);
}

static inline xfs_lsn_t xfs_ail_get_push_target(struct xfs_ail *ailp)
{
	return READ_ONCE(ailp->ail_target);
}

void			xfs_ail_push_all_sync(struct xfs_ail *ailp);
void			xfs_ail_push_all_sync_bounded(struct xfs_ail *ailp,
						      unsigned int max_ms);
/*
 * sess6(ccloop a9a03929) FIX-12: LSN-targeted bounded whole-AIL sync push.
 * Snapshots the AIL max LSN at entry and waits (≤max_ms) until every item at
 * or below it has been written — i.e. everything committed BEFORE the call is
 * on disk, without being livelocked by later commits.  Returns false if the
 * bound expired first.  The no-inode BAST release uses this as its Invariant-1
 * fence (it has no extent map to scope a narrower drain).
 */
bool			xfs_ail_push_upto_sync_bounded(struct xfs_ail *ailp,
						       unsigned int max_ms,
						       xfs_lsn_t *out_target);
xfs_lsn_t		xfs_ail_max_lsn(struct xfs_ail *ailp);
/*
 * Phase 1 (D8): per-AG AIL drain.  Waits until no AIL items belonging
 * to @agno remain.  Items in OTHER AGs are not waited on — they belong
 * to other AG locks and drain via their own bast handlers.
 *
 * Filter scope: XFS_LI_BUF (mapped by daddr → AG) and XFS_LI_INODE
 * (mapped by ino → AG).  Other item types are not AG-tied in a simple
 * way; the on-disk metadata they target is reflected in BUF items,
 * which we DO drain.  See architecture spec §11.3.
 *
 * Replaces sess27's xfs_ail_push_all_sync_timed (bounded-time variant
 * which broke correctness — partial drain releases lock with dirty
 * data).  Filtering is by AG, not by time.
 */
void			xfs_ail_push_ag_sync(struct xfs_ail *ailp,
					     xfs_agnumber_t agno);
/*
 * v0.3.147 sess33: bounded variant.  Returns 0 on full drain,
 * -EAGAIN if no-progress detected (stall_iters consecutive iterations
 * without items leaving target AG, after iter > min_iters).  Caller
 * must not release the AG-DLM grant on -EAGAIN.  stall_iters=0 ⇒
 * unbounded (legacy behavior; xfs_ail_push_ag_sync wraps with this).
 */
int			xfs_ail_push_ag_sync_bounded(struct xfs_ail *ailp,
					     xfs_agnumber_t agno,
					     unsigned int stall_iters,
					     unsigned int min_iters);
xfs_lsn_t		xfs_ail_min_lsn(struct xfs_ail *ailp);

struct xfs_log_item *	xfs_trans_ail_cursor_first(struct xfs_ail *ailp,
					struct xfs_ail_cursor *cur,
					xfs_lsn_t lsn);
struct xfs_log_item *	xfs_trans_ail_cursor_last(struct xfs_ail *ailp,
					struct xfs_ail_cursor *cur,
					xfs_lsn_t lsn);
struct xfs_log_item *	xfs_trans_ail_cursor_next(struct xfs_ail *ailp,
					struct xfs_ail_cursor *cur);
void			xfs_trans_ail_cursor_done(struct xfs_ail_cursor *cur);

void			__xfs_ail_assign_tail_lsn(struct xfs_ail *ailp);

static inline void
xfs_ail_assign_tail_lsn(
	struct xfs_ail		*ailp)
{

	spin_lock(&ailp->ail_lock);
	__xfs_ail_assign_tail_lsn(ailp);
	spin_unlock(&ailp->ail_lock);
}

#if BITS_PER_LONG != 64
static inline void
xfs_trans_ail_copy_lsn(
	struct xfs_ail	*ailp,
	xfs_lsn_t	*dst,
	xfs_lsn_t	*src)
{
	ASSERT(sizeof(xfs_lsn_t) == 8);	/* don't lock if it shrinks */
	spin_lock(&ailp->ail_lock);
	*dst = *src;
	spin_unlock(&ailp->ail_lock);
}
#else
static inline void
xfs_trans_ail_copy_lsn(
	struct xfs_ail	*ailp,
	xfs_lsn_t	*dst,
	xfs_lsn_t	*src)
{
	ASSERT(sizeof(xfs_lsn_t) == 8);
	*dst = *src;
}
#endif

#endif	/* __XFS_TRANS_PRIV_H__ */
