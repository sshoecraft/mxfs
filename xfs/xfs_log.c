// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_bit.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_trace.h"
#include "xfs_sysfs.h"
#include "xfs_sb.h"
#include "xfs_health.h"
#include "xfs_ag.h"
#include "xfs_zone_alloc.h"

/* xfs_mxfs_dlm.c — queued cluster withdrawal on first shutdown */
void mxfs_dlm_shutdown_withdraw(struct xfs_mount *mp);
#include "xfs_relmark_item.h"	/* clean-release marker table teardown */
#include "xfs_mxfs_dlm.h"	/* mxfs_recov_image_evict: retire replay-written cached images */
#include "xfs_mxfs_icensus.h"	/* intent/done census terminal predicate */
#include "../dlm/v5_mount.h"	/* victim untagged-replay authority */
#include <mxfs/mxfs_super.h>	/* 0.88.0: MXFS_SLIFE_* slice lifecycle states */

/* mxfs log-wedge diagnostic gate (module param mxfs.instr, defined in xfs_mxfs_dlm.c) */
extern int mxfs_instr_enabled;
extern int mxfs_adopted_slice_full_replay;	/* xfs_mxfs_dlm.c */
extern int mxfs_obl_complete_enable;		/* 0.85.0: xfs_mxfs_dlm.c */

/* mxfs grant-balance diagnostic counters (reserve_head only) */
static atomic64_t mxfs_dbg_grant_added = ATOMIC64_INIT(0);
static atomic64_t mxfs_dbg_grant_subbed = ATOMIC64_INIT(0);
static atomic64_t mxfs_dbg_grant_addcnt = ATOMIC64_INIT(0);
static atomic64_t mxfs_dbg_grant_subcnt = ATOMIC64_INIT(0);

struct xlog_write_data {
	struct xlog_ticket	*ticket;
	struct xlog_in_core	*iclog;
	uint32_t		bytes_left;
	uint32_t		record_cnt;
	uint32_t		data_cnt;
	int			log_offset;
};

struct kmem_cache	*xfs_log_ticket_cache;

/* Local miscellaneous function prototypes */
STATIC struct xlog *
xlog_alloc_log(
	struct xfs_mount	*mp,
	struct xfs_buftarg	*log_target,
	xfs_daddr_t		blk_offset,
	int			num_bblks);
STATIC void
xlog_dealloc_log(
	struct xlog		*log);

/* local state machine functions */
STATIC void xlog_state_done_syncing(
	struct xlog_in_core	*iclog);
STATIC void xlog_state_do_callback(
	struct xlog		*log);
STATIC int
xlog_state_get_iclog_space(
	struct xlog		*log,
	struct xlog_write_data	*data);
STATIC void
xlog_sync(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	struct xlog_ticket	*ticket);
#if defined(DEBUG)
STATIC void
xlog_verify_iclog(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	int			count);
STATIC void
xlog_verify_tail_lsn(
	struct xlog		*log,
	struct xlog_in_core	*iclog);
#else
#define xlog_verify_iclog(a,b,c)
#define xlog_verify_tail_lsn(a,b)
#endif

STATIC int
xlog_iclogs_empty(
	struct xlog		*log);

static int
xfs_log_cover(struct xfs_mount *);

static inline void
xlog_grant_sub_space(
	struct xlog_grant_head	*head,
	int64_t			bytes)
{
	atomic64_sub(bytes, &head->grant);
	if (unlikely(mxfs_instr_enabled)) {
		atomic64_add(bytes, &mxfs_dbg_grant_subbed);
		atomic64_inc(&mxfs_dbg_grant_subcnt);
		if (bytes < 0) {
			mxfs_probe_ratelimited("mxfs: P-LSUBNEG xlog_grant_sub_space NEGATIVE bytes=%lld\n",
				(long long)bytes);
			mxfs_probe_stack();
		}
	}
}

static inline void
xlog_grant_add_space(
	struct xlog_grant_head	*head,
	int64_t			bytes)
{
	atomic64_add(bytes, &head->grant);
	if (unlikely(mxfs_instr_enabled)) {
		atomic64_add(bytes, &mxfs_dbg_grant_added);
		atomic64_inc(&mxfs_dbg_grant_addcnt);
	}
}

static void
xlog_grant_head_init(
	struct xlog_grant_head	*head)
{
	atomic64_set(&head->grant, 0);
	INIT_LIST_HEAD(&head->waiters);
	spin_lock_init(&head->lock);
}

void
xlog_grant_return_space(
	struct xlog	*log,
	xfs_lsn_t	old_head,
	xfs_lsn_t	new_head)
{
	int64_t		diff = xlog_lsn_sub(log, new_head, old_head);

	if (unlikely(mxfs_instr_enabled))
		mxfs_probe_ratelimited("mxfs: P-LRET return_space old=0x%llx new=0x%llx diff=%lld\n",
			(unsigned long long)old_head, (unsigned long long)new_head,
			(long long)diff);
	xlog_grant_sub_space(&log->l_reserve_head, diff);
	xlog_grant_sub_space(&log->l_write_head, diff);
}

/*
 * Return the space in the log between the tail and the head.  In the case where
 * we have overrun available reservation space, return 0. The memory barrier
 * pairs with the smp_wmb() in xlog_cil_ail_insert() to ensure that grant head
 * vs tail space updates are seen in the correct order and hence avoid
 * transients as space is transferred from the grant heads to the AIL on commit
 * completion.
 */
static uint64_t
xlog_grant_space_left(
	struct xlog		*log,
	struct xlog_grant_head	*head)
{
	int64_t			free_bytes;

	smp_rmb();	/* paired with smp_wmb in xlog_cil_ail_insert() */
	free_bytes = log->l_logsize - READ_ONCE(log->l_tail_space) -
			atomic64_read(&head->grant);
	if (free_bytes > 0)
		return free_bytes;
	return 0;
}

STATIC void
xlog_grant_head_wake_all(
	struct xlog_grant_head	*head)
{
	struct xlog_ticket	*tic;

	spin_lock(&head->lock);
	list_for_each_entry(tic, &head->waiters, t_queue)
		wake_up_process(tic->t_task);
	spin_unlock(&head->lock);
}

static inline int
xlog_ticket_reservation(
	struct xlog		*log,
	struct xlog_grant_head	*head,
	struct xlog_ticket	*tic)
{
	if (head == &log->l_write_head) {
		ASSERT(tic->t_flags & XLOG_TIC_PERM_RESERV);
		return tic->t_unit_res;
	}

	if (tic->t_flags & XLOG_TIC_PERM_RESERV)
		return tic->t_unit_res * tic->t_cnt;

	return tic->t_unit_res;
}

STATIC bool
xlog_grant_head_wake(
	struct xlog		*log,
	struct xlog_grant_head	*head,
	int			*free_bytes)
{
	struct xlog_ticket	*tic;
	int			need_bytes;

	list_for_each_entry(tic, &head->waiters, t_queue) {
		need_bytes = xlog_ticket_reservation(log, head, tic);
		if (*free_bytes < need_bytes)
			return false;

		*free_bytes -= need_bytes;
		trace_xfs_log_grant_wake_up(log, tic);
		wake_up_process(tic->t_task);
	}

	return true;
}

STATIC int
xlog_grant_head_wait(
	struct xlog		*log,
	struct xlog_grant_head	*head,
	struct xlog_ticket	*tic,
	int			need_bytes) __releases(&head->lock)
					    __acquires(&head->lock)
{
	list_add_tail(&tic->t_queue, &head->waiters);

	do {
		if (xlog_is_shutdown(log))
			goto shutdown;

		__set_current_state(TASK_UNINTERRUPTIBLE);
		spin_unlock(&head->lock);

		XFS_STATS_INC(log->l_mp, xs_sleep_logspace);

		/* Push on the AIL to free up all the log space. */
		xfs_ail_push_all(log->l_ailp);

		if (unlikely(mxfs_instr_enabled)) {
			struct xfs_cil_ctx *ctx = log->l_cilp ? log->l_cilp->xc_ctx : NULL;
			mxfs_probe_ratelimited("mxfs: P-LGRANT wait need=%d free=%llu logsize=%d tail_space=%llu rgrant=%lld wgrant=%lld head_lsn=0x%llx tail_lsn=0x%llx cil_space=%d cil_push_seq=%llu cil_ctx_seq=%llu\n",
				need_bytes,
				(unsigned long long)xlog_grant_space_left(log, head),
				log->l_logsize,
				(unsigned long long)READ_ONCE(log->l_tail_space),
				(long long)atomic64_read(&log->l_reserve_head.grant),
				(long long)atomic64_read(&log->l_write_head.grant),
				(unsigned long long)log->l_ailp->ail_head_lsn,
				(unsigned long long)atomic64_read(&log->l_tail_lsn),
				ctx ? atomic_read(&ctx->space_used) : -1,
				(unsigned long long)(log->l_cilp ? log->l_cilp->xc_push_seq : 0),
				(unsigned long long)(ctx ? ctx->sequence : 0));
			mxfs_probe_ratelimited("mxfs: P-LGRANT2 added=%lld subbed=%lld balance=%lld addcnt=%lld subcnt=%lld\n",
				(long long)atomic64_read(&mxfs_dbg_grant_added),
				(long long)atomic64_read(&mxfs_dbg_grant_subbed),
				(long long)(atomic64_read(&mxfs_dbg_grant_added) - atomic64_read(&mxfs_dbg_grant_subbed)),
				(long long)atomic64_read(&mxfs_dbg_grant_addcnt),
				(long long)atomic64_read(&mxfs_dbg_grant_subcnt));
		}

		trace_xfs_log_grant_sleep(log, tic);
		schedule();
		trace_xfs_log_grant_wake(log, tic);

		spin_lock(&head->lock);
		if (xlog_is_shutdown(log))
			goto shutdown;
	} while (xlog_grant_space_left(log, head) < need_bytes);

	list_del_init(&tic->t_queue);
	return 0;
shutdown:
	list_del_init(&tic->t_queue);
	return -EIO;
}

/*
 * Atomically get the log space required for a log ticket.
 *
 * Once a ticket gets put onto head->waiters, it will only return after the
 * needed reservation is satisfied.
 *
 * This function is structured so that it has a lock free fast path. This is
 * necessary because every new transaction reservation will come through this
 * path. Hence any lock will be globally hot if we take it unconditionally on
 * every pass.
 *
 * As tickets are only ever moved on and off head->waiters under head->lock, we
 * only need to take that lock if we are going to add the ticket to the queue
 * and sleep. We can avoid taking the lock if the ticket was never added to
 * head->waiters because the t_queue list head will be empty and we hold the
 * only reference to it so it can safely be checked unlocked.
 */
STATIC int
xlog_grant_head_check(
	struct xlog		*log,
	struct xlog_grant_head	*head,
	struct xlog_ticket	*tic,
	int			*need_bytes)
{
	int			free_bytes;
	int			error = 0;

	ASSERT(!xlog_in_recovery(log));

	/*
	 * If there are other waiters on the queue then give them a chance at
	 * logspace before us.  Wake up the first waiters, if we do not wake
	 * up all the waiters then go to sleep waiting for more free space,
	 * otherwise try to get some space for this transaction.
	 */
	*need_bytes = xlog_ticket_reservation(log, head, tic);
	free_bytes = xlog_grant_space_left(log, head);
	if (!list_empty_careful(&head->waiters)) {
		spin_lock(&head->lock);
		if (!xlog_grant_head_wake(log, head, &free_bytes) ||
		    free_bytes < *need_bytes) {
			error = xlog_grant_head_wait(log, head, tic,
						     *need_bytes);
		}
		spin_unlock(&head->lock);
	} else if (free_bytes < *need_bytes) {
		spin_lock(&head->lock);
		error = xlog_grant_head_wait(log, head, tic, *need_bytes);
		spin_unlock(&head->lock);
	}

	return error;
}

bool
xfs_log_writable(
	struct xfs_mount	*mp)
{
	/*
	 * Do not write to the log on norecovery mounts, if the data or log
	 * devices are read-only, or if the filesystem is shutdown. Read-only
	 * mounts allow internal writes for log recovery and unmount purposes,
	 * so don't restrict that case.
	 */
	if (xfs_has_norecovery(mp))
		return false;
	if (xfs_readonly_buftarg(mp->m_ddev_targp))
		return false;
	if (xfs_readonly_buftarg(mp->m_log->l_targ))
		return false;
	if (xlog_is_shutdown(mp->m_log))
		return false;
	return true;
}

/*
 * Replenish the byte reservation required by moving the grant write head.
 */
int
xfs_log_regrant(
	struct xfs_mount	*mp,
	struct xlog_ticket	*tic)
{
	struct xlog		*log = mp->m_log;
	int			need_bytes;
	int			error = 0;

	if (xlog_is_shutdown(log))
		return -EIO;

	XFS_STATS_INC(mp, xs_try_logspace);

	/*
	 * This is a new transaction on the ticket, so we need to change the
	 * transaction ID so that the next transaction has a different TID in
	 * the log. Just add one to the existing tid so that we can see chains
	 * of rolling transactions in the log easily.
	 */
	tic->t_tid++;
	tic->t_curr_res = tic->t_unit_res;
	if (tic->t_cnt > 0)
		return 0;

	trace_xfs_log_regrant(log, tic);

	error = xlog_grant_head_check(log, &log->l_write_head, tic,
				      &need_bytes);
	if (error)
		goto out_error;

	xlog_grant_add_space(&log->l_write_head, need_bytes);
	trace_xfs_log_regrant_exit(log, tic);
	return 0;

out_error:
	/*
	 * If we are failing, make sure the ticket doesn't have any current
	 * reservations.  We don't want to add this back when the ticket/
	 * transaction gets cancelled.
	 */
	tic->t_curr_res = 0;
	tic->t_cnt = 0;	/* ungrant will give back unit_res * t_cnt. */
	return error;
}

/*
 * Reserve log space and return a ticket corresponding to the reservation.
 *
 * Each reservation is going to reserve extra space for a log record header.
 * When writes happen to the on-disk log, we don't subtract the length of the
 * log record header from any reservation.  By wasting space in each
 * reservation, we prevent over allocation problems.
 */
int
xfs_log_reserve(
	struct xfs_mount	*mp,
	int			unit_bytes,
	int			cnt,
	struct xlog_ticket	**ticp,
	bool			permanent)
{
	struct xlog		*log = mp->m_log;
	struct xlog_ticket	*tic;
	int			need_bytes;
	int			error = 0;

	if (xlog_is_shutdown(log))
		return -EIO;

	XFS_STATS_INC(mp, xs_try_logspace);

	ASSERT(*ticp == NULL);
	tic = xlog_ticket_alloc(log, unit_bytes, cnt, permanent);
	*ticp = tic;
	trace_xfs_log_reserve(log, tic);
	error = xlog_grant_head_check(log, &log->l_reserve_head, tic,
				      &need_bytes);
	if (error)
		goto out_error;

	xlog_grant_add_space(&log->l_reserve_head, need_bytes);
	xlog_grant_add_space(&log->l_write_head, need_bytes);
	trace_xfs_log_reserve_exit(log, tic);
	return 0;

out_error:
	/*
	 * If we are failing, make sure the ticket doesn't have any current
	 * reservations.  We don't want to add this back when the ticket/
	 * transaction gets cancelled.
	 */
	tic->t_curr_res = 0;
	tic->t_cnt = 0;	/* ungrant will give back unit_res * t_cnt. */
	return error;
}

/*
 * Run all the pending iclog callbacks and wake log force waiters and iclog
 * space waiters so they can process the newly set shutdown state. We really
 * don't care what order we process callbacks here because the log is shut down
 * and so state cannot change on disk anymore. However, we cannot wake waiters
 * until the callbacks have been processed because we may be in unmount and
 * we must ensure that all AIL operations the callbacks perform have completed
 * before we tear down the AIL.
 *
 * We avoid processing actively referenced iclogs so that we don't run callbacks
 * while the iclog owner might still be preparing the iclog for IO submssion.
 * These will be caught by xlog_state_iclog_release() and call this function
 * again to process any callbacks that may have been added to that iclog.
 */
static void
xlog_state_shutdown_callbacks(
	struct xlog		*log)
{
	struct xlog_in_core	*iclog;
	LIST_HEAD(cb_list);

	iclog = log->l_iclog;
	do {
		if (atomic_read(&iclog->ic_refcnt)) {
			/* Reference holder will re-run iclog callbacks. */
			continue;
		}
		list_splice_init(&iclog->ic_callbacks, &cb_list);
		spin_unlock(&log->l_icloglock);

		xlog_cil_process_committed(&cb_list);

		spin_lock(&log->l_icloglock);
		wake_up_all(&iclog->ic_write_wait);
		wake_up_all(&iclog->ic_force_wait);
	} while ((iclog = iclog->ic_next) != log->l_iclog);

	wake_up_all(&log->l_flush_wait);
}

/*
 * Flush iclog to disk if this is the last reference to the given iclog and the
 * it is in the WANT_SYNC state.
 *
 * If XLOG_ICL_NEED_FUA is already set on the iclog, we need to ensure that the
 * log tail is updated correctly. NEED_FUA indicates that the iclog will be
 * written to stable storage, and implies that a commit record is contained
 * within the iclog. We need to ensure that the log tail does not move beyond
 * the tail that the first commit record in the iclog ordered against, otherwise
 * correct recovery of that checkpoint becomes dependent on future operations
 * performed on this iclog.
 *
 * Hence if NEED_FUA is set and the current iclog tail lsn is empty, write the
 * current tail into iclog. Once the iclog tail is set, future operations must
 * not modify it, otherwise they potentially violate ordering constraints for
 * the checkpoint commit that wrote the initial tail lsn value. The tail lsn in
 * the iclog will get zeroed on activation of the iclog after sync, so we
 * always capture the tail lsn on the iclog on the first NEED_FUA release
 * regardless of the number of active reference counts on this iclog.
 */
int
xlog_state_release_iclog(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	struct xlog_ticket	*ticket)
{
	bool			last_ref;

	lockdep_assert_held(&log->l_icloglock);

	trace_xlog_iclog_release(iclog, _RET_IP_);
	/*
	 * Grabbing the current log tail needs to be atomic w.r.t. the writing
	 * of the tail LSN into the iclog so we guarantee that the log tail does
	 * not move between the first time we know that the iclog needs to be
	 * made stable and when we eventually submit it.
	 */
	if ((iclog->ic_state == XLOG_STATE_WANT_SYNC ||
	     (iclog->ic_flags & XLOG_ICL_NEED_FUA)) &&
	    !iclog->ic_header->h_tail_lsn) {
		iclog->ic_header->h_tail_lsn =
				cpu_to_be64(atomic64_read(&log->l_tail_lsn));
	}

	last_ref = atomic_dec_and_test(&iclog->ic_refcnt);

	if (xlog_is_shutdown(log)) {
		/*
		 * If there are no more references to this iclog, process the
		 * pending iclog callbacks that were waiting on the release of
		 * this iclog.
		 */
		if (last_ref)
			xlog_state_shutdown_callbacks(log);
		return -EIO;
	}

	if (!last_ref)
		return 0;

	if (iclog->ic_state != XLOG_STATE_WANT_SYNC) {
		ASSERT(iclog->ic_state == XLOG_STATE_ACTIVE);
		return 0;
	}

	iclog->ic_state = XLOG_STATE_SYNCING;
	xlog_verify_tail_lsn(log, iclog);
	trace_xlog_iclog_syncing(iclog, _RET_IP_);

	spin_unlock(&log->l_icloglock);
	xlog_sync(log, iclog, ticket);
	spin_lock(&log->l_icloglock);
	return 0;
}

/*
 * MXFS B1 (D-MIXED-VERSION-UNGATED-REPLAY): no log image may be
 * applied before this node's cluster-protocol admission is decided.
 * xfs_fs_fill_super sets m_mxfs_proto_admitted after the C7 gate admits
 * (trivially for non-envelope mounts); every recovery entry point calls
 * this first.  A replay reached without admission means a code path
 * exists where an unadmitted (possibly protocol-mismatched) kernel could
 * interpret and apply another generation's log images — refuse it.
 */
static int
mxfs_assert_proto_admitted(
	struct xfs_mount	*mp,
	const char		*where)
{
	if (!mp->m_mxfs_has_envelope || mp->m_mxfs_proto_admitted)
		return 0;
	xfs_alert(mp,
"MXFS: %s reached before C7 protocol admission — refusing log replay (fail closed)",
		  where);
	return -EPROTO;
}

/*
 * Mount a log filesystem
 *
 * mp		- ubiquitous xfs mount point structure
 * log_target	- buftarg of on-disk log device
 * blk_offset	- Start block # where block size is 512 bytes (BBSIZE)
 * num_bblocks	- Number of BBSIZE blocks in on-disk log
 *
 * Return error or zero.
 */
int
xfs_log_mount(
	xfs_mount_t		*mp,
	struct xfs_buftarg	*log_target,
	xfs_daddr_t		blk_offset,
	int			num_bblks)
{
	struct xlog		*log;
	int			error = 0;
	int			min_logfsbs;

	if (!xfs_has_norecovery(mp)) {
		xfs_notice(mp, "Mounting V%d Filesystem %pU",
			   XFS_SB_VERSION_NUM(&mp->m_sb),
			   &mp->m_sb.sb_uuid);
	} else {
		xfs_notice(mp,
"Mounting V%d filesystem %pU in no-recovery mode. Filesystem will be inconsistent.",
			   XFS_SB_VERSION_NUM(&mp->m_sb),
			   &mp->m_sb.sb_uuid);
		ASSERT(xfs_is_readonly(mp));
	}

	log = xlog_alloc_log(mp, log_target, blk_offset, num_bblks);
	if (IS_ERR(log)) {
		error = PTR_ERR(log);
		goto out;
	}
	mp->m_log = log;

	/*
	 * (D-FOREIGN-REPLAY-UNGATED-IMAGES): a PASS-2 (fresh) disklock
	 * claim means this node's previous-incarnation stamp was absent or
	 * zeroed — so any dirty records in the inherited log slice belong to
	 * an incarnation whose recovery already completed (the elected
	 * survivor replayed the slice and zeroed the HB slot) or to a foreign
	 * pre-format ghost.  Re-applying their buf/dquot/icreate images here
	 * would go through the upstream on-disk-LSN gate, which is
	 * meaningless across per-node slices, and can revert state survivors
	 * have written SINCE that recovery.  A PASS-1 reclaim (our own ACTIVE
	 * stamp survived — nobody replayed us) keeps full recovery: it is the
	 * required own-crash recovery path and is safe because our unreplayed
	 * death left our grants quarantined.
	 */
	if (mp->m_mxfs_bootstrap_adopted) {
		/*
		 * (§6.5 shape B): the whole-cluster bootstrap owner's
		 * slot is a certified VICTIM's slice.  Never ADOPTED_SLICE
		 * (that suppresses images and intents): this is the FULL
		 * own-log replay the ruling requires, gated per transaction
		 * by the victim's escrowed certificate + fence-time manifest
		 * (the evaluator is fed from the escrow for this slot).
		 *
		 * (design-consult review S1): the bootstrap finish records
		 * K_REPLAY_OK on the strength of THIS replay having run.  A
		 * norecovery mount skips xlog_recover entirely, so under it
		 * an adopted slice must not mount at all — the term would be
		 * completed on a replay that never happened.
		 */
		if (xfs_has_norecovery(mp)) {
			xfs_alert(mp,
		"MXFS: P-BOOT-ADOPTED-NORECOVERY slot=%u — a whole-cluster bootstrap owner cannot mount its adopted victim slice with norecovery: the term's completion requires the replay; mount refused, the term stands (K_CLAIMED)",
				  mp->m_mxfs_node_slot);
			error = -EINVAL;
			goto out_free_log;
		}
		set_bit(XLOG_MXFS_BOOTSTRAP_ADOPTED, &log->l_opstate);
		log->l_mxfs_victim_slot = mp->m_mxfs_node_slot;
		xfs_notice(mp,
	"MXFS: P-BOOT-ADOPTED-LOG slot=%u — bootstrap owner mounting a certified victim's slice as its own log: FULL replay, authority-evaluated; a refused transaction is terminal",
			   mp->m_mxfs_node_slot);
	} else if (mp->m_mxfs_slice_adopted && !mxfs_adopted_slice_full_replay) {
		set_bit(XLOG_MXFS_ADOPTED_SLICE, &log->l_opstate);
		/*
		 * the "victim" whose records the shadow authority
		 * evaluator judges here is the PRIOR incarnation of the slot
		 * we just claimed — same slot number, dead incarnation.  Its
		 * CAW authority was purged when its recovery completed (a
		 * pass-2 claim requires a CONSUMABLE sector, which only the
		 * completed recovery produces), so the expected verdict for
		 * every record is would-skip/not-held; a would-apply here is
		 * evidence of an unpurged manifest, not of applicability.
		 */
		log->l_mxfs_victim_slot = mp->m_mxfs_node_slot;
		xfs_notice(mp,
	"MXFS: adopted log slice (fresh disklock claim) — image records in prior dirty content will not be re-applied");
	}

	/*
	 * Now that we have set up the log and it's internal geometry
	 * parameters, we can validate the given log space and drop a critical
	 * message via syslog if the log size is too small. A log that is too
	 * small can lead to unexpected situations in transaction log space
	 * reservation stage. The superblock verifier has already validated all
	 * the other log geometry constraints, so we don't have to check those
	 * here.
	 *
	 * Note: For v4 filesystems, we can't just reject the mount if the
	 * validation fails.  This would mean that people would have to
	 * downgrade their kernel just to remedy the situation as there is no
	 * way to grow the log (short of black magic surgery with xfs_db).
	 *
	 * We can, however, reject mounts for V5 format filesystems, as the
	 * mkfs binary being used to make the filesystem should never create a
	 * filesystem with a log that is too small.
	 */
	min_logfsbs = xfs_log_calc_minimum_size(mp);
	if (mp->m_sb.sb_logblocks < min_logfsbs) {
		xfs_warn(mp,
		"Log size %d blocks too small, minimum size is %d blocks",
			 mp->m_sb.sb_logblocks, min_logfsbs);

		/*
		 * Log check errors are always fatal on v5; or whenever bad
		 * metadata leads to a crash.
		 */
		if (xfs_has_crc(mp)) {
			xfs_crit(mp, "AAIEEE! Log failed size checks. Abort!");
			ASSERT(0);
			error = -EINVAL;
			goto out_free_log;
		}
		xfs_crit(mp, "Log size out of supported range.");
		xfs_crit(mp,
"Continuing onwards, but if log hangs are experienced then please report this message in the bug report.");
	}

	/*
	 * Initialize the AIL now we have a log.
	 */
	error = xfs_trans_ail_init(mp);
	if (error) {
		xfs_warn(mp, "AIL initialisation failed: error %d", error);
		goto out_free_log;
	}
	log->l_ailp = mp->m_ail;

	/*
	 * skip log recovery on a norecovery mount.  pretend it all
	 * just worked.
	 */
	if (!xfs_has_norecovery(mp)) {
		error = mxfs_assert_proto_admitted(mp,
				"mount-time xlog_recover");
		if (error)
			goto out_destroy_ail;
		/*
		 * the adopted slot K runs the ENFORCING gate (the
		 * evaluator + sealed fence-time manifest from the escrow),
		 * armed here exactly as the foreign path arms it.  A
		 * structurally invalid manifest is a typed terminal for the
		 * term; every other preflight failure leaves it resumable.
		 */
		if (xlog_is_mxfs_bootstrap_adopted(log)) {
			error = mxfs_fr_enforce_preflight(log);
			if (error) {
				xfs_alert(mp,
		"MXFS: P-BOOT-ADOPTED-PREFLIGHT slot=%u rc=%d — the adopted slice's enforcement preflight failed; mount refused",
					  mp->m_mxfs_node_slot, error);
				if (error == -EFSCORRUPTED)
					mxfs_v5_dlm_bootstrap_k_refused(
						mp->m_mxfs_dlm, error);
				goto out_destroy_ail;
			}
		}
		error = xlog_recover(log);
		/*
		 * (D-0521): a clustered mount's own-slice recovery
		 * (trusted PASS-1 reclaim, or an adopted/bootstrap slice) reports
		 * how many buffer images the on-disk LSN stamp vetoed; on a
		 * clustered mount every such veto is a candidate lost update.
		 */
		if (mp->m_mxfs_dlm_was_active &&
		    (log->l_mxfs_buflsn_skips || log->l_mxfs_buflsn_overrides))
			xfs_notice(mp,
	"MXFS: P-OWN-RECOVERY slot=%u rc=%d untrusted=%d buflsn_skips=%u buflsn_overrides=%u — own-slice recovery LSN-veto census (D-0521: skips on a trusted clustered recovery are unverified lost updates)",
				   mp->m_mxfs_node_slot, error,
				   xlog_is_mxfs_untrusted_replay(log) ? 1 : 0,
				   log->l_mxfs_buflsn_skips,
				   log->l_mxfs_buflsn_overrides);
		if (error) {
			xfs_warn(mp, "log mount/recovery failed: error %d",
				error);
			/*
			 * (design-consult review (a)): on the adopted slice K
			 * only a TYPED verdict is terminal for the term — a
			 * torn/corrupt K (the ruling's "torn K is a terminal
			 * K_REPLAY_REFUSED").  A transport error (-EIO,
			 * -ENOMEM) leaves the escrow K_CLAIMED, resumable.
			 */
			if (xlog_is_mxfs_bootstrap_adopted(log) &&
			    (error == -EFSCORRUPTED || error == -EUCLEAN))
				mxfs_v5_dlm_bootstrap_k_refused(mp->m_mxfs_dlm,
								error);
			xlog_recover_cancel(log);
			goto out_destroy_ail;
		}
		/*
		 * (§6.5 shape B): on the bootstrap owner's adopted
		 * victim slice a refused (ATOMIC-SKIP / untagged) transaction
		 * or an evaluator abort is TERMINAL for the term — the mount
		 * fails here and the DLM unwind records K_REPLAY_REFUSED.
		 * Never a silent skip, never a fallback to another slot.
		 */
		if (xlog_is_mxfs_bootstrap_adopted(log) &&
		    (log->l_mxfs_untagged_skips || log->l_mxfs_malformed_skips ||
		     log->l_mxfs_rman_invalid || log->l_mxfs_rman_mutated ||
		     log->l_mxfs_icensus_lost ||
		     mxfs_fr_shadow_mutated(log))) {
			xfs_alert(mp,
	"MXFS: P-BOOT-ADOPTED-REFUSED slot=%u refused=%u malformed=%u rman_invalid=%d mutated=%d census_lost=%d — the adopted victim slice carries transactions its certificate does not authorise; the bootstrap term is terminal",
				  mp->m_mxfs_node_slot,
				  log->l_mxfs_untagged_skips,
				  log->l_mxfs_malformed_skips,
				  log->l_mxfs_rman_invalid ? 1 : 0,
				  log->l_mxfs_rman_mutated ? 1 : 0,
				  log->l_mxfs_icensus_lost ? 1 : 0);
			error = -EFSCORRUPTED;
			/* the typed refusal — the ONLY path (with a
			 * torn K above) that ends the term; recorded here, at
			 * the verdict, never inferred by the unwind */
			mxfs_v5_dlm_bootstrap_k_refused(mp->m_mxfs_dlm, error);
			xlog_recover_cancel(log);
			goto out_destroy_ail;
		}
	}

	error = xfs_sysfs_init(&log->l_kobj, &xfs_log_ktype, &mp->m_kobj,
			       "log");
	if (error)
		goto out_destroy_ail;

	/* Normal transactions can now occur */
	clear_bit(XLOG_ACTIVE_RECOVERY, &log->l_opstate);

	/*
	 * Now the log has been fully initialised and we know were our
	 * space grant counters are, we can initialise the permanent ticket
	 * needed for delayed logging to work.
	 */
	xlog_cil_init_post_recovery(log);

	return 0;

out_destroy_ail:
	xfs_trans_ail_destroy(mp);
out_free_log:
	xlog_dealloc_log(log);
out:
	return error;
}

/*
 * MXFS v0.5.0 — live foreign-slice replay.
 *
 * When a peer dies, its fsync-acknowledged metadata may exist only in its
 * per-node log slice; without replay, survivors serve stale on-disk state
 * until some future mount claims the slice.  The elected survivor (lowest
 * live disklock slot) replays the dead slice through a private shadow xlog:
 *
 *  - direct metadata images (buf/inode/dquot/icreate) are written to disk;
 *  - intent/done items are skipped (XLOG_MXFS_FOREIGN_REPLAY gates in
 *    xfs_log_recover.c), so this node's live AIL is never touched;
 *  - the slice is left dirty, so the next mount-time claimer performs full
 *    replay including intents; buffer/inode re-replay is LSN-gated and
 *    therefore a no-op, making double replay safe (election is perf-only).
 *
 * The shadow xlog gets a private dummy AIL (no xfsaild task) because
 * xlog_find_tail writes l_ailp->ail_head_lsn — sharing mp->m_ail would
 * clobber live log accounting.
 */

/*
 * (D-513): forensic identity of a REFUSED slice — reread the whole
 * slice image from the shared LUN and crc32c it.  Runs only on the refusal
 * path, so the extra IO never touches a successful replay.  A failed read
 * leaves the digest invalid; the verdict still publishes terminally with
 * digest_valid=false and a zero digest (ruling item 5: the digest is
 * forensics, never a gate on containment).
 */
static int
mxfs_freplay_slice_digest(
	struct xfs_mount	*mp,
	xfs_daddr_t		daddr,
	int			bblks,
	uint64_t		*digest)
{
	struct xfs_buftarg	*targ = mp->m_logdev_targp;
	char			*buf;
	uint32_t		crc = 0;
	int			chunk_bb = min_t(int, bblks, 2048); /* 1 MiB */
	int			done = 0;
	int			error = 0;

	if (bblks <= 0 || !targ || !targ->bt_bdev)
		return -EINVAL;
	buf = kvmalloc(BBTOB(chunk_bb), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	while (done < bblks) {
		int	this_bb = min(chunk_bb, bblks - done);

		error = xfs_rw_bdev(targ->bt_bdev,
				    targ->bt_sector_offset + daddr + done,
				    BBTOB(this_bb), buf, REQ_OP_READ);
		if (error)
			break;
		crc = crc32c(crc, buf, BBTOB(this_bb));
		done += this_bb;
	}
	kvfree(buf);
	if (!error)
		*digest = crc;
	return error;
}

/*
 * D-513 fault injection (ruling, Q7 rig plan; scope per the
 * ruling Q2): force a foreign-replay refusal.  Shapes 1-3 forge the verdict
 * AFTER a clean replay — phase-A containment/plumbing coverage only (durable
 * outcome publish, survivor import, quarantine EIO, PENDING park, lease
 * release); the platter stays consistent.  Shape 4 is the GENUINE mid-replay
 * TORN: pass 2 fails with -EFSCORRUPTED after applying a deterministic
 * freplay_force_torn_items-1 item prefix and takes the real
 * xlog_recover_cancel unwind.
 *
 * The knob is ONE-SHOT and slot-scoped: it is consumed (xchg to 0) by the
 * first replay attempt whose victim slot passes freplay_force_slot, so it
 * covers exactly one recovery attempt of one victim — a sticky global here
 * would make every later recovery's verdict ambiguous.
 * 0 = off (default).  1 = POLICY refusal, AG-mask (ag 0).  2 = POLICY
 * refusal, fs-wide.  3 = TORN verdict forged post-success (whole-fs).
 * 4 = genuine mid-replay TORN (whole-fs).  Test-only.
 */
static int mxfs_freplay_force_refusal;
module_param_named(freplay_force_refusal, mxfs_freplay_force_refusal,
		   int, 0644);
MODULE_PARM_DESC(freplay_force_refusal,
	"Fault injection, ONE-SHOT: force foreign-slice replay refusal (0=off, 1=POLICY ag0, 2=POLICY fswide, 3=TORN forged post-success, 4=TORN genuine mid-replay)");
static int mxfs_freplay_force_slot = -1;
module_param_named(freplay_force_slot, mxfs_freplay_force_slot, int, 0644);
MODULE_PARM_DESC(freplay_force_slot,
	"Fault injection: victim slot freplay_force_refusal fires on (-1 = first replay attempted)");
static int mxfs_freplay_force_torn_items = 8;
module_param_named(freplay_force_torn_items, mxfs_freplay_force_torn_items,
		   int, 0644);
MODULE_PARM_DESC(freplay_force_torn_items,
	"Fault injection: shape-4 fails pass 2 before applying the Nth item (deterministic prefix = N-1)");
/*
 * which AG-mask shape 1 forges.  Default 1 (AG 0) keeps the
 * pre-existing shape-1 semantics byte for byte.  The out-of-closure purge and
 * scrub (D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356) can only be exercised with
 * a domain that EXCLUDES the AG the probe resources live in — with ag0 in the
 * closure the root inode is in-domain and correctly stays frozen, so the fix
 * has nothing to do.  Test-only.
 */
static unsigned long mxfs_freplay_force_ag_mask = 1;
module_param_named(freplay_force_ag_mask, mxfs_freplay_force_ag_mask,
		   ulong, 0644);
MODULE_PARM_DESC(freplay_force_ag_mask,
	"Fault injection: AG bitmask shape-1 forges as the refused domain (default 1 = ag0)");
/*
 * (D-LOG-ERROR-SHUTDOWN-SKIPS-DLM-WITHDRAW-409 verification): fail the
 * next N iclog write completions with -EIO so the FIRST shutdown of this mount
 * originates in xlog_force_shutdown (the "shut down due to log error" path),
 * not in xfs_do_force_shutdown.  This build has no DEBUG, so the upstream
 * XFS_ERRTAG_IODONE_IOERR errortag is compiled out.  Consumable (decremented
 * per failed completion, 0 = off).  Test-only.
 */
static int mxfs_log_inject_ioerr;
module_param_named(log_inject_ioerr, mxfs_log_inject_ioerr, int, 0644);
MODULE_PARM_DESC(log_inject_ioerr,
	"TEST ONLY: fail the next N log (iclog) write completions with -EIO (consumable; 0=off)");

static bool
mxfs_log_inject_ioerr_take(void)
{
	int	n;

	do {
		n = READ_ONCE(mxfs_log_inject_ioerr);
		if (n <= 0)
			return false;
	} while (cmpxchg(&mxfs_log_inject_ioerr, n, n - 1) != n);
	return true;
}

/*
 * (D-FOREIGN-REPLAY-FAILURE-PUBLISHED-AS-RECOVERED closure arm):
 * while >0, every foreign-slice replay fails with a RETRYABLE -EIO before
 * any replay work.  The callers must then refuse to publish: the live path
 * keeps the victim's HB sector ACTIVE and manifest intact and re-arms the
 * reap (MXFS_REAPF_FREPLAY); the mount-cohort barrier continues the mount
 * with the slot unpublished.  Clearing the knob must let the normal retry
 * replay and publish — the refusal is a delay, never a lost slice.
 */
static int mxfs_dbg_fr_fail_replay;
module_param_named(dbg_fr_fail_replay, mxfs_dbg_fr_fail_replay, int, 0644);
MODULE_PARM_DESC(dbg_fr_fail_replay,
	"TEST ONLY: while >0 every foreign-slice replay fails -EIO before any work (retryable; 0=off)");

int
mxfs_xlog_recover_foreign_slice(
	struct xfs_mount	*mp,
	uint32_t		dead_slot,
	struct mxfs_freplay_verdict *verdict)
{
	struct xlog		*shadow;
	struct xfs_ail		*ailp;
	xfs_daddr_t		daddr;
	int			bblks;
	int			error;
	int			inject = 0;
	bool			slife_empty = false;

	uint32_t		slice;

	if (verdict)
		memset(verdict, 0, sizeof(*verdict));

	if (!mxfs_has_log_slices(mp)) {
		xfs_warn(mp,
	"MXFS: foreign replay of slot %u skipped — no per-node log slices",
			 dead_slot);
		return -EINVAL;
	}
	if (xfs_is_shutdown(mp) || !mp->m_log)
		return -EIO;
	/*
	 * (design-consult ruling Q5, D-FSWIDE-TERMINAL-REPLAY-CONTINUES-407):
	 * an FSWIDE TERMINAL quarantine means a filesystem-level recovery
	 * invariant failed (authority mutated post-seal / manifest invalid) and
	 * the operator owns the filesystem now — NO further slice replay may
	 * start on it, however sound the next victim's own manifest looks
	 * (recovery transactions carry ordering / allocation / log dependencies
	 * beyond simultaneous EX ownership).  matrix mutate2 on 0.26.2: slot 12
	 * MUTATED-TERMINAL at 3848.68 s, slot 17 replayed to completion at
	 * 3853.98 s by the same node.  Verdict reason stays NONE: nothing is
	 * published for THIS slot, its slice stays frozen and dirty.
	 */
	if (READ_ONCE(mp->m_mxfs_quar_fswide)) {
		xfs_alert_ratelimited(mp,
	"MXFS: P-RMAN-FSWIDE-HALT foreign replay of slot %u NOT started — an FSWIDE terminal quarantine is in force on this filesystem; the slice stays frozen and unpublished until operator repair + remount",
			dead_slot);
		return -EIO;
	}

	if (unlikely(READ_ONCE(mxfs_dbg_fr_fail_replay) > 0)) {
		xfs_alert(mp,
	"MXFS: P-DBG-FR-FAIL-REPLAY slot %u — forced retryable replay failure (test knob); nothing may be published for this slot",
			dead_slot);
		return -EIO;
	}

	error = mxfs_assert_proto_admitted(mp, "foreign-slice replay");
	if (error)
		return error;

	/*
	 * dead_slot is the dead node's heartbeat slot (0-63); its XFS log
	 * slice is the identically numbered slice — the same identity
	 * mapping xfs_mountfs applies for the node's own slice.  A slot
	 * beyond the slice count has no slice: replaying anything for it
	 * would read (and worse, later stamp clean) a slice belonging to
	 * a DIFFERENT slot.  Refuse without touching the disk.
	 */
	error = mxfs_log_slice_of_slot(mp, dead_slot, &slice);
	if (error) {
		xfs_alert(mp,
	"MXFS: foreign replay refused — dead slot %u has no log slice (fs has %u slices)",
			  dead_slot, mp->m_mxfs_log_node_count);
		return error;
	}
	daddr = XFS_FSB_TO_DADDR(mp, mp->m_sb.sb_logstart) +
		(xfs_daddr_t)slice * mp->m_mxfs_log_slice_bblks;
	bblks = mp->m_mxfs_log_slice_bblks;

	xfs_notice(mp,
	"MXFS: foreign replay of dead slot %u (slice %u/%u) offset=%lld bblks=%d",
		   dead_slot, slice, mp->m_mxfs_log_node_count,
		   (long long)daddr, bblks);

	ailp = kzalloc(sizeof(*ailp), GFP_KERNEL);
	if (!ailp)
		return -ENOMEM;
	spin_lock_init(&ailp->ail_lock);
	INIT_LIST_HEAD(&ailp->ail_head);
	INIT_LIST_HEAD(&ailp->ail_cursors);
	INIT_LIST_HEAD(&ailp->ail_buf_list);
	init_waitqueue_head(&ailp->ail_empty);

	shadow = xlog_alloc_log(mp, mp->m_logdev_targp, daddr, bblks);
	if (IS_ERR(shadow)) {
		kfree(ailp);
		return PTR_ERR(shadow);
	}
	set_bit(XLOG_MXFS_FOREIGN_REPLAY, &shadow->l_opstate);
	/* bind the shadow authority evaluator to the dead node */
	shadow->l_mxfs_victim_slot = dead_slot;
	/*
	 * 0.89.18: and to the dead node's INCARNATION, because the slot alone
	 * does not name a victim — the next claimant of that slot is a
	 * different one.  Read here, once, from the same descriptor everything
	 * else about this replay comes from; a failure leaves it 0, which every
	 * consumer treats as "unfiltered" rather than as a match.
	 */
	{
		uint16_t vstage = 0;
		uint64_t vepoch = 0;
		uint32_t vnode = 0;

		if (mxfs_v5_dlm_victim_recovery_read(mp->m_mxfs_dlm, dead_slot,
						     &vstage, &vepoch,
						     &vnode) == 0)
			shadow->l_mxfs_victim_epoch = vepoch;
	}

	/*
	 * (ruling): untagged-record replay authority.  Both
	 * predicates come from the victim's recovery descriptor — the kind-17
	 * certificate (operator assertion, proven at fence time by the
	 * membership gate) and the victim's own durable write-time snlocal
	 * marker.  Only their CONJUNCTION authorizes applying untagged
	 * images; any read failure leaves both false (fail closed —
	 * xlog_alloc_log kzalloc'd the fields to 0/false already, this just
	 * makes the evaluation explicit and logged).
	 */
	{
		bool cert_sn = false, victim_sn = false;
		int arc = mxfs_v5_dlm_victim_untagged_authority(
				mp->m_mxfs_dlm, dead_slot,
				&cert_sn, &victim_sn);

		shadow->l_mxfs_cert_single_node = cert_sn;
		shadow->l_mxfs_untagged_authorized = cert_sn && victim_sn;
		if (arc)
			xfs_warn(mp,
	"MXFS: untagged-authority read for slot %u failed (%d) — untagged records will be refused",
				 dead_slot, arc);
		else if (cert_sn && !victim_sn)
			xfs_warn(mp,
	"MXFS: P227-SNLOCAL-DIVERGE slot %u: kind-17 certificate but victim never self-classified snlocal — untagged records will be refused",
				 dead_slot);
	}
	ailp->ail_log = shadow;
	shadow->l_ailp = ailp;

	/*
	 * (#1, ruling): enforcement preflight — one
	 * descriptor read, cached on the shadow log for every per-txn
	 * verdict.  A configured-but-uncapable recovery aborts HERE, before
	 * any replay side effect; the plain (non -EFSCORRUPTED) error keeps
	 * the verdict reason NONE, so no terminal outcome publishes and a
	 * later election retries.
	 */
	error = mxfs_fr_enforce_preflight(shadow);
	/*
	 * (D-527): capture + stabilize the slice snapshot BEFORE
	 * consuming the one-shot injection knob (same principle as the
	 * preflight ordering: an abort here must never eat an armed
	 * injection) and before any recovery read.  -EBUSY (not quiesced) and
	 * -ENOMEM are plain errors: verdict reason stays NONE, nothing
	 * publishes, the slice stays dirty and a later election retries.
	 * Recovery NEVER runs from live slice reads any more.
	 */
	/*
	 * 0.88.0 (D-SLICE-CLAIM-TIME-INIT-UNTRUSTED-ZERO-531): a slice whose
	 * lifecycle record is not READY holds no record of this incarnation —
	 * READY is persisted before the first journal write — so there is
	 * nothing to replay, and its payload is exactly the untrusted bytes
	 * the record exists to keep discovery away from.  Skip the snapshot
	 * and the replay; the outcome is a clean recovery of an empty slice,
	 * and the record is left as it is for the slot's next claimant to
	 * restart the full zero.  A record that cannot be read or validated
	 * on a volume that carries the region is a plain error (reason NONE,
	 * nothing published, a later election retries); a legacy volume
	 * (-ENODEV) replays as before.
	 */
	if (!error) {
		uint32_t	lstate = 0;
		int		lrc = mxfs_v5_dlm_slice_lifecycle_state(
					mp->m_mxfs_dlm, slice, &lstate);

		if (lrc == 0 && lstate != MXFS_SLIFE_READY) {
			xfs_notice(mp,
	"MXFS: P-SLIFE-FOREIGN-UNINIT slot=%u slice=%u state=%s — the dead node never brought this slice to READY, so it journaled nothing; replay skipped, payload untouched, the record stays for the slot's next claimant",
				   dead_slot, slice,
				   mxfs_v5_dlm_slice_lifecycle_name(lstate));
			slife_empty = true;
		} else if (lrc && lrc != -ENODEV) {
			xfs_alert(mp,
	"MXFS: P-SLIFE-FOREIGN-UNREADABLE slot=%u slice=%u rc=%d — the slice lifecycle record could not be validated; replay not started (retryable)",
				  dead_slot, slice, lrc);
			error = lrc;
		}
	}
	if (!error && !slife_empty)
		error = mxfs_xlog_slice_snapshot(shadow);
	if (!error && !slife_empty) {
		/*
		 * ruling Q2: consume the fault knob ONE-SHOT, scoped
		 * to the configured victim slot — this replay attempt (and
		 * only this one) carries the injection, so every other
		 * recovery's verdict stays unambiguous.  (design review
		 * Q1): consumed only AFTER a successful preflight, so a
		 * preflight abort can never eat an armed injection — the
		 * shape fires on the attempt that actually replays.
		 */
		if (unlikely(READ_ONCE(mxfs_freplay_force_refusal)) &&
		    (mxfs_freplay_force_slot < 0 ||
		     (uint32_t)mxfs_freplay_force_slot == dead_slot)) {
			inject = xchg(&mxfs_freplay_force_refusal, 0);
			if (inject)
				xfs_alert(mp,
	"MXFS: P227-FR-INJECT-ARMED slot=%u shape=%d torn_items=%d — one-shot knob consumed for this replay attempt",
					  dead_slot, inject,
					  mxfs_freplay_force_torn_items);
		}
		/*
		 * Shape 4 (ruling Q2b): genuine mid-replay TORN — arm
		 * the pass-2 countdown on the shadow log so the failure
		 * happens INSIDE the replay, after a deterministic applied
		 * prefix, with the real xlog_recover_cancel unwind below.
		 */
		if (unlikely(inject >= 4))
			shadow->l_mxfs_force_torn_countdown =
				mxfs_freplay_force_torn_items > 0 ?
				mxfs_freplay_force_torn_items : 1;

		/* every read this task completes from here to the image
		 * retirement below is a recovery-populated cache image */
		WRITE_ONCE(mp->m_mxfs_freplay_task, current);
		error = xlog_recover(shadow);
	}
	/*
	 * D-513 fault injection shapes 1-3: only a CLEAN replay is overridden
	 * — a real failure keeps its own verdict.  Shape 3 (TORN) forces the
	 * corrupt-image arm below, including the recover_cancel a real
	 * mid-replay failure takes; the POLICY shapes forge refused-item
	 * state so the policy-refusal arm fires with the chosen domain.
	 */
	if (unlikely(inject && inject < 4) && !error) {
		xfs_alert(mp,
	"MXFS: P227-FR-FORCED-REFUSAL slot %u shape=%d — fault injection, verdict is synthetic",
			  dead_slot, inject);
		if (inject >= 3) {
			error = -EFSCORRUPTED;
		} else {
			shadow->l_mxfs_untagged_skips += 1;
			if (inject == 2)
				shadow->l_mxfs_refused_fswide = true;
			else
				/*
				 * ASSIGN, not OR.  Shape 1's verdict is
				 * explicitly synthetic ("fires with the chosen
				 * domain"), and a real replay usually has
				 * genuinely refused AGs of its own —
				 * measured 0x2 forged | 0x81 real = 0x83, which
				 * silently put ag0 back INTO the closure and
				 * made the out-of-closure test unable to
				 * discriminate at all.  The chosen domain is
				 * the whole point of the knob.
				 */
				shadow->l_mxfs_refused_ag_mask =
					mxfs_freplay_force_ag_mask ?
					mxfs_freplay_force_ag_mask : 1;
		}
	}
	if (error)
		xlog_recover_cancel(shadow);
	/*
	 * (item 5 increment 2, design-consult ruling STOP-SHIP 1): the
	 * IMAGES_REPLAYED milestone that follows a clean replay attests that
	 * the applied images are HOME — a takeover successor is forbidden to
	 * re-replay once it sees that milestone durable, so the milestone must
	 * be preceded by the buffers' own completion (xfs_buf_delwri_submit
	 * inside the recovery pass waits for them) AND a device flush.  The
	 * ladder's flush after the CAW purge was too late for that rule.  A
	 * flush failure is a plain retryable error (reason NONE): nothing is
	 * published and a later election replays again.
	 */
	if (!error) {
		int	frc = blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);

		if (frc) {
			xfs_alert(mp,
		"MXFS: P226-FR-HOMEFLUSH-FAIL slot %u rc=%d — the replayed images are not proven durable; slice NOT published, will retry",
				  dead_slot, frc);
			error = frc;
		} else {
			mxfs_xfs_probe(mp,
		"MXFS: P226-FR-HOMEFLUSH slot %u — replayed images flushed home before the IMAGES_REPLAYED milestone",
				   dead_slot);
			/*
			 * The images are home; the cached copies the replay
			 * left were read under no tenure and no tenure end will
			 * retire them, so retire them here, before publication.
			 * A copy that cannot be retired is a retryable error
			 * like the flush: nothing published, replay again.
			 */
			error = mxfs_recov_image_evict(mp, dead_slot);
		}
	}
	WRITE_ONCE(mp->m_mxfs_freplay_task, NULL);

	/*
	 * (D-513, ruling): a corrupt/torn slice image is as
	 * DETERMINISTIC a refusal as a policy one — replaying it again reads
	 * the same broken bytes.  It carries no trustworthy per-item domain
	 * information (the failure may precede item parsing entirely), so the
	 * quarantine domain is forced whole-filesystem.
	 */
	if ((error == -EFSCORRUPTED || error == -EFSBADCRC) && verdict) {
		verdict->reason          = shadow->l_mxfs_rman_invalid ?
					   MXFS_FREPLAY_REASON_MANIFEST_INVALID :
					   MXFS_FREPLAY_REASON_TORN;
		verdict->fswide          = true;
		verdict->refused_items   = shadow->l_mxfs_untagged_skips;
		verdict->malformed_items = shadow->l_mxfs_malformed_skips;
	}

	/*
	 * (D-527 ruling): the assembly validator refused a committed
	 * transaction whose item stream crossed an ophdr discontinuity —
	 * regions the platter's real stream would have held were replaced by
	 * stale prior-life records and silently skipped as slack.  With the
	 * snapshot proven stable, rereading identical bytes cannot converge:
	 * TERMINAL for this snapshot, whole-filesystem domain (the failure
	 * precedes per-item domain knowledge) — but a DISTINCT reason: this
	 * is an assembly/provenance refusal, not a media tear.
	 *
	 * -EILSEQ, NOT -EUCLEAN: EUCLEAN IS EFSCORRUPTED (same errno, 117),
	 * so an EUCLEAN class would shadow every TORN verdict above — the
	 * fln7 publish loop (reason 6 rejected -EINVAL, retry
	 * forever) was exactly that mistake.
	 */
	if (error == -EILSEQ && verdict) {
		verdict->reason          = MXFS_FREPLAY_REASON_ASSEMBLY_DISCONTINUITY;
		verdict->fswide          = true;
		verdict->refused_items   = shadow->l_mxfs_untagged_skips;
		verdict->malformed_items = shadow->l_mxfs_malformed_skips;
	}

	/*
	 * (docs/recovery-manifest.md; design review items 8/9): the
	 * evaluator found the victim's fence-time authority MUTATED after the
	 * seal (manifest entry vs live slot).  That is a broken protocol
	 * invariant, never a transient — TERMINAL, FSWIDE, nothing purged.
	 * Checked here, after xlog_recover returned, so a mutation detected on
	 * the last transaction (no later commit to abort) still publishes.
	 * Only under enforcement (report-only never applies tokenized images,
	 * so a mutation seen there is telemetry — it is still logged).
	 */
	if (mxfs_fr_shadow_mutated(shadow)) {
		xfs_alert(mp,
	"MXFS: P-RMAN-MUTATED-TERMINAL slot %u — fence-time authority mutated after the seal; publishing TERMINAL FSWIDE quarantine (nothing purged, slice stays frozen, operator action)",
			  dead_slot);
		error = -EFSCORRUPTED;
		if (verdict) {
			verdict->reason          = MXFS_FREPLAY_REASON_AUTHORITY_MUTATED;
			verdict->fswide          = true;
			verdict->refused_items   = shadow->l_mxfs_untagged_skips;
			verdict->malformed_items = shadow->l_mxfs_malformed_skips;
		}
	}

	/*
	 * a kind-17 slice that had untagged records REFUSED cannot be
	 * published as recovered — the operator called the victim's log local,
	 * so those untagged images are part of the slice's durable state and a
	 * replay that skipped them is a TORN image.  Fail the whole replay so
	 * the caller keeps the slice frozen/unpublished (same containment path
	 * as any other replay error).
	 *
	 * (#21 incident-481 design-consult ruling): generalized to EVERY
	 * untrusted replay, not just kind-17.  An ATOMIC-SKIP abandons a
	 * COMMITTED victim transaction, and skipping cannot undo the victim's
	 * own partial AIL writeback of that transaction's buffers: incident
	 * 481 had AGI+finobt home but not inobt when the victim withdrew, so
	 * the skip left the platter torn (finobt freecount ahead of inobt,
	 * orphaned nlink=0 inodes on no bucket) and replay was the only redo
	 * path.  XFS atomicity is log-commit atomicity — redo restores it;
	 * refusing the redo and then publishing the recovery manufactured a
	 * state no node ever had.  Fail closed instead: the slice stays
	 * frozen/unpublished and the victim's log slice is itself the
	 * preserved evidence.  The per-record P227-FR-ATOMIC-SKIP /
	 * P223-FR-UNTAGGED-SKIP notices already name the lsn/item detail.
	 */
	if (!error && shadow->l_mxfs_untagged_skips > 0) {
		if (shadow->l_mxfs_cert_single_node &&
		    !shadow->l_mxfs_untagged_authorized)
			xfs_alert(mp,
	"MXFS: P227-SNLOCAL-TORN slot %u: kind-17 replay refused %u untagged record(s) without the victim snlocal marker — slice stays unpublished",
				  dead_slot, shadow->l_mxfs_untagged_skips);
		else
			xfs_alert(mp,
	"MXFS: P227-FR-TORN-UNPUBLISHED slot %u: replay refused %u committed unauthorized image(s) (sbclean_skips=%u not counted) — the victim's partial home-writeback cannot be ruled out, so publishing would publish a torn platter; slice stays unpublished (needs repair or token-authorized redo)",
				  dead_slot, shadow->l_mxfs_untagged_skips,
				  shadow->l_mxfs_sbclean_skips);
		error = -EFSCORRUPTED;
		/*
		 * (D-513): the gates refused every part of the slice
		 * they could not authorize — a complete, deterministic policy
		 * verdict.  The quarantine domain is the AG set the refused
		 * items would have modified, collected per-item during the
		 * replay; anything unmappable already forced fswide there.
		 */
		if (verdict) {
			verdict->reason  = MXFS_FREPLAY_REASON_POLICY_REFUSED;
			verdict->fswide  = shadow->l_mxfs_refused_fswide ||
					   shadow->l_mxfs_refused_ag_mask == 0;
			verdict->ag_mask = shadow->l_mxfs_refused_ag_mask;
			verdict->refused_items   = shadow->l_mxfs_untagged_skips;
			verdict->malformed_items = shadow->l_mxfs_malformed_skips;
		}
	}

	/*
	 * (D-FOREIGN-SLICE-INTENTS-ABANDONED interim; barrier
	 * ruling stop-ship 1): FAIL BEFORE PURGE.  A slot may reach
	 * GRANTS_RELEASED only if IMAGES_REPLAYED && (OBLIGATIONS_DONE or an
	 * enforced QUARANTINED).  Nothing on this path can discharge a dead
	 * peer's intents, so a slice whose census is still open at the end of
	 * the replay is refused through the same terminal path as a policy
	 * refusal — reason INTENTS_UNDISCHARGED, domain = the union of the
	 * open intents' AGs (FSWIDE when any is unmappable).  When another
	 * verdict already refused the slice, its domain is widened by the
	 * census so the quarantine covers the open obligations as well; a
	 * retryable failure (verdict reason NONE) is left alone.
	 */
	{
		uint64_t	imask = 0;
		bool		ifsw = false;
		uint32_t	imal = 0;
		uint32_t	nopen;

		nopen = mxfs_icensus_undischarged(shadow, "foreign", &imask,
						  &ifsw, &imal);
		if (nopen && !error) {
			uint32_t	nrec = 0, nq = 0;
			uint64_t	rmask = 0, qmask = 0;
			bool		qfsw = false;
			bool		recoverable = false;

			/*
			 * (item 5 increment 1): classify the open set
			 * per the ruling's matrix.  RECOVER entries are the
			 * admitted EFIs the recovery owner may complete once the
			 * completion increments land; QUARANTINE entries keep
			 * this terminal refusal for ever.
			 */
			mxfs_icensus_classify(shadow, "foreign", &nrec, &rmask,
					      &nq, &qmask, &qfsw);
			/*
			 * (increment 2): hand the RECOVER extents out
			 * through the verdict so the publisher can make them
			 * durable as evidence next to the terminal outcome.
			 * A list that cannot be built is reported as LOST —
			 * never as "nothing to recover" (ruling STOP-SHIP 4).
			 */
			if (verdict) {
				int	xrc;

				verdict->obl_count   = nrec;
				verdict->obl_ag_mask = rmask;
				verdict->q_count     = nq;
				verdict->q_mask      = qmask;
				verdict->q_fswide    = qfsw;
				xrc = mxfs_icensus_export_recover(shadow,
						&verdict->obl_list,
						&verdict->obl_count);
				if (xrc) {
					verdict->obl_lost  = true;
					verdict->obl_count = nrec;
					xfs_warn(mp,
		"MXFS: P226-OBL-EXPORT-LOST slot %u rc=%d recover=%u — the obligation list could not be carried out of the replay",
						 dead_slot, xrc, nrec);
				}
			}
			/*
			 * 0.85.0 (D-FOREIGN-SLICE-INTENTS-ABANDONED, item 5
			 * increment 3, the verdict flip): an open set made ONLY
			 * of RECOVER entries — admitted EFIs, no done, extents
			 * mappable and canonical, nothing malformed — is a
			 * COMPLETABLE obligation, not a refusal.  The replay
			 * succeeds and hands the extent list out through the
			 * verdict; the recovery ladder publishes it as an OPEN
			 * record in the IMAGES_REPLAYED milestone and the
			 * custodian completes it in live transactions before
			 * anything is purged (xfs_mxfs_recov_obl.c).  Every
			 * other open-entry case stays the terminal refusal
			 * below exactly as before: a QUARANTINE entry, an
			 * unmappable/FSWIDE domain, a malformed item, a lost
			 * list, a filesystem whose rmapbt/reflink feature bits
			 * would give an EFI a meaning this completion does not
			 * implement, or the CAW transport (which has no custody
			 * model for an OPEN case in this build).
			 */
			/* obl_count is the EXTENT total the export produced
			 * (nrec counts intent items; an EFI names up to 16) */
			recoverable = verdict && nrec >= 1 && nq == 0 &&
				      !ifsw && imal == 0 && !verdict->obl_lost &&
				      verdict->obl_count >= 1 &&
				      verdict->obl_list &&
				      !xfs_has_rmapbt(mp) && !xfs_has_reflink(mp) &&
				      mp->m_mxfs_dlm &&
				      !mxfs_v5_dlm_is_caw(mp->m_mxfs_dlm) &&
				      READ_ONCE(mxfs_obl_complete_enable);
			if (recoverable) {
				int	drc = mxfs_freplay_slice_digest(mp, daddr,
							bblks,
							&verdict->slice_digest);

				verdict->digest_valid = (drc == 0);
				xfs_notice(mp,
		"MXFS: P226-FR-INTENTS-RECOVERABLE slot %u: %u open EFI obligation(s), %u extent(s), ag_mask=0x%llx, quarantine=0 — replay SUCCEEDS with an OPEN obligation case; the custodian completes the extents before any purge (digest=%llx dvalid=%d)",
					   dead_slot, nopen, verdict->obl_count,
					   (unsigned long long)rmask,
					   (unsigned long long)verdict->slice_digest,
					   (int)verdict->digest_valid);
				goto census_done;
			}
			xfs_alert(mp,
	"MXFS: P226-FR-INTENTS-UNDISCHARGED slot %u: %u intent obligation(s) of the victim's slice have no done record inside the slice (fswide=%d ag_mask=0x%llx malformed=%u; class recover=%u recover_mask=0x%llx quarantine=%u q_mask=0x%llx q_fswide=%d) — nothing here may complete them, so the slice is REFUSED before any purge; terminal quarantine, needs repair",
				  dead_slot, nopen, (int)ifsw,
				  (unsigned long long)imask, imal, nrec,
				  (unsigned long long)rmask, nq,
				  (unsigned long long)qmask, (int)qfsw);
			error = -EFSCORRUPTED;
			if (verdict) {
				verdict->reason  = MXFS_FREPLAY_REASON_INTENTS_UNDISCHARGED;
				verdict->fswide  = ifsw || imask == 0;
				verdict->ag_mask = imask;
				verdict->refused_items   = nopen;
				verdict->malformed_items =
					shadow->l_mxfs_malformed_skips + imal;
			}
		} else if (nopen && verdict &&
			   verdict->reason != MXFS_FREPLAY_REASON_NONE &&
			   !verdict->fswide) {
			verdict->ag_mask |= imask;
			if (ifsw || verdict->ag_mask == 0)
				verdict->fswide = true;
		}
census_done:;
	}

	/*
	 * Capture the refused slice's forensic digest.  A failed reread keeps
	 * digest_valid=false; the verdict STILL publishes terminally (
	 * ruling item 5) — the outcome record carries the DIGEST_VALID flag
	 * clear and a zero digest, weakening forensics but never containment.
	 */
	if (verdict && verdict->reason != MXFS_FREPLAY_REASON_NONE) {
		int	drc = mxfs_freplay_slice_digest(mp, daddr, bblks,
						&verdict->slice_digest);
		if (drc)
			xfs_warn(mp,
	"MXFS: refused slice slot %u digest reread failed (%d) — verdict publishes with digest_valid=false",
				 dead_slot, drc);
		else
			verdict->digest_valid = true;
	}

	/* (#94): counted clean skips survive shadow teardown so the
	 * outcome line reports them — a slice of ONLY routine SB-counter
	 * logging now completes instead of arming the terminal verdict. */
	{
		uint32_t sbclean_skips = shadow->l_mxfs_sbclean_skips;
		uint32_t buflsn_skips = shadow->l_mxfs_buflsn_skips;
		uint32_t buflsn_overrides = shadow->l_mxfs_buflsn_overrides;
		uint32_t drain_deferred = shadow->l_mxfs_drain_deferred;

		mxfs_shadow_eval_finish(shadow);
		xlog_dealloc_log(shadow);
		kfree(ailp);

		if (error)
			xfs_warn(mp,
			"MXFS: foreign replay of slot %u failed: error %d (buflsn_skips=%u buflsn_overrides=%u drain_deferred=%u)",
				 dead_slot, error, buflsn_skips, buflsn_overrides,
				 drain_deferred);
		else
			xfs_notice(mp,
			"MXFS: foreign replay of slot %u complete (sbclean_skips=%u buflsn_skips=%u buflsn_overrides=%u drain_deferred=%u)",
				   dead_slot, sbclean_skips, buflsn_skips,
				   buflsn_overrides, drain_deferred);
	}
	return error;
}

/* release the obligation list a verdict carries (idempotent). */
void
mxfs_freplay_verdict_free(
	struct mxfs_freplay_verdict *verdict)
{
	if (!verdict)
		return;
	kvfree(verdict->obl_list);
	verdict->obl_list = NULL;
}

/*
 * Finish the recovery of the file system.  This is separate from the
 * xfs_log_mount() call, because it depends on the code in xfs_mountfs() to read
 * in the root and real-time bitmap inodes between calling xfs_log_mount() and
 * here.
 *
 * If we finish recovery successfully, start the background log work. If we are
 * not doing recovery, then we have a RO filesystem and we don't need to start
 * it.
 */
static void xlog_unmount_write(struct xlog *log);	/* P308 */

/*
 * 0.41.2 (D-0354 lap 3): the P308 boundary record is written
 * through xlog_write directly, not through a CIL checkpoint, and the AIL
 * head is advanced ONLY by xlog_cil_ail_insert (measured 0.41.1, test5
 * 22:20Z: 'P308 ... did NOT advance ail_head_lsn (0x100000012)').  With
 * the head still at the previous incarnation's last record, the empty-AIL
 * tail fallback kept pointing every later checkpoint's h_tail_lsn at that
 * record and the cut was not in force.  Move the head to where the next
 * record will be written — the LSN xlog_find_tail derives for a clean log
 * (after_umount_blk) — exactly as a checkpoint commit does: head first,
 * tail-space recomputed, then the consumed span returned to the grant
 * heads (pairs with xlog_grant_space_left's smp_rmb).
 */
static void
mxfs_log_head_past_boundary(
	struct xlog		*log)
{
	struct xfs_ail		*ailp = log->l_ailp;
	xfs_lsn_t		new_head, old_head;

	spin_lock(&log->l_icloglock);
	new_head = xlog_assign_lsn(log->l_curr_cycle, log->l_curr_block);
	spin_unlock(&log->l_icloglock);

	spin_lock(&ailp->ail_lock);
	old_head = ailp->ail_head_lsn;
	if (XFS_LSN_CMP(new_head, old_head) <= 0) {
		spin_unlock(&ailp->ail_lock);
		return;
	}
	ailp->ail_head_lsn = new_head;
	/* drops ail_lock; recomputes l_tail_lsn / l_tail_space */
	xfs_ail_update_finish(ailp, NULLCOMMITLSN);
	smp_wmb();
	xlog_grant_return_space(log, old_head, new_head);
}

int
xfs_log_mount_finish(
	struct xfs_mount	*mp)
{
	struct xlog		*log = mp->m_log;
	int			error = 0;

	if (xfs_has_norecovery(mp)) {
		ASSERT(xfs_is_readonly(mp));
		return 0;
	}

	/*
	 * During the second phase of log recovery, we need iget and
	 * iput to behave like they do for an active filesystem.
	 * xfs_fs_drop_inode needs to be able to prevent the deletion
	 * of inodes before we're done replaying log items on those
	 * inodes.  Turn it off immediately after recovery finishes
	 * so that we don't leak the quota inodes if subsequent mount
	 * activities fail.
	 *
	 * We let all inodes involved in redo item processing end up on
	 * the LRU instead of being evicted immediately so that if we do
	 * something to an unlinked inode, the irele won't cause
	 * premature truncation and freeing of the inode, which results
	 * in log recovery failure.  We have to evict the unreferenced
	 * lru inodes after clearing SB_ACTIVE because we don't
	 * otherwise clean up the lru if there's a subsequent failure in
	 * xfs_mountfs, which leads to us leaking the inodes if nothing
	 * else (e.g. quotacheck) references the inodes before the
	 * mount failure occurs.
	 */
	mp->m_super->s_flags |= SB_ACTIVE;
	xfs_log_work_queue(mp);
	if (xlog_recovery_needed(log)) {
		error = mxfs_assert_proto_admitted(mp,
				"xlog_recover_finish");
		if (!error)
			error = xlog_recover_finish(log);
	}
	mp->m_super->s_flags &= ~SB_ACTIVE;
	evict_inodes(mp->m_super);

	/*
	 * Drain the buffer LRU after log recovery. This is required for v4
	 * filesystems to avoid leaving around buffers with NULL verifier ops,
	 * but we do it unconditionally to make sure we're always in a clean
	 * cache state after mount.
	 *
	 * Don't push in the error case because the AIL may have pending intents
	 * that aren't removed until recovery is cancelled.
	 */
	if (xlog_recovery_needed(log)) {
		if (!error) {
			xfs_log_force(mp, XFS_LOG_SYNC);
			xfs_ail_push_all_sync(mp->m_ail);
			/*
			 * 0.41.1 (D-0354 lap 2): INCARNATION BOUNDARY.
			 *
			 * Measured: a node that recovered a dirty slice at mount
			 * (its own crash, or an ADOPTED already-published
			 * slice) and then crashed after one checkpoint left a
			 * replay window that still contained the PREVIOUS
			 * incarnation's last record — xlog_set_state seeds
			 * ail_head_lsn with that record's own LSN, so with an
			 * empty AIL the first new checkpoint's h_tail_lsn
			 * pointed AT it.  Upstream tolerates that (replay is
			 * LSN-idempotent); MXFS tokens bind every image to its
			 * emitting incarnation, so the survivor's foreign
			 * replay refused the stale image ('winc'), atomically
			 * refused the transaction, and quarantined the slice —
			 * the NEW incarnation's fsync'd work was lost (test2
			 * 21:51:50Z: lsn cf3 owner I1 + lsn cf8 owner I2).
			 *
			 * Cut the log here, once every recovery-generated
			 * record is forced and every recovered item has landed
			 * (above): a standard unmount record.  After it commits
			 * the empty-AIL tail fallback is the boundary itself,
			 * so no later window can reach back across it, and a
			 * mid-window unmount op is ignored by
			 * xlog_recover_process_ophdr (no START_TRANS).  The
			 * covering worker is stopped across the write so no
			 * producer straddles the cut (design-consult ruling stop-ship
			 * 1); requeued after.  The upstream summary-counter
			 * rule is preserved: a sick-counter mount keeps its
			 * log dirty so the next mount recalculates — that case
			 * is covered by the replayer's provenance-certified
			 * pre-incarnation skip (P310), not by this cut.
			 */
			if (mp->m_mxfs_dlm && xfs_log_writable(mp) &&
			    !xlog_is_shutdown(log)) {
				xfs_lsn_t	before, after;

				cancel_delayed_work_sync(&log->l_work);
				before = log->l_ailp->ail_head_lsn;
				if (xfs_fs_has_sickness(mp, XFS_SICK_FS_COUNTERS)) {
					xfs_warn(mp,
	"MXFS: P308-LOG-INCARNATION-BOUNDARY SKIPPED — summary counters sick, log stays dirty for the next mount's recalculation (pre-incarnation records rely on P310)");
				} else {
					xlog_unmount_write(log);
					mxfs_log_head_past_boundary(log);
					after = log->l_ailp->ail_head_lsn;
					xfs_notice(mp,
	"MXFS: P308-LOG-INCARNATION-BOUNDARY written after mount recovery: ail_head_lsn 0x%llx -> 0x%llx tail_lsn=0x%llx (adopted=%d) — the previous incarnation's records are outside every later replay window",
						(unsigned long long)before,
						(unsigned long long)after,
						(unsigned long long)atomic64_read(&log->l_tail_lsn),
						xlog_is_mxfs_adopted_slice(log) ? 1 : 0);
					if (after == before)
						xfs_alert(mp,
	"MXFS: P308-LOG-INCARNATION-BOUNDARY did NOT advance ail_head_lsn (0x%llx) — the cut is not in force",
							(unsigned long long)after);
				}
				xfs_log_work_queue(mp);
			}
		}
		xfs_notice(mp, "Ending recovery (logdev: %s)",
				mp->m_logname ? mp->m_logname : "internal");
	} else {
		xfs_info(mp, "Ending clean mount");
	}
	xfs_buftarg_drain(mp->m_ddev_targp);

	/* an ADOPTED_SLICE mount log accumulated shadow authority
	 * verdicts during pass 2 — recovery is over, emit and free them.
	 * No-op on every other mount (state never allocated). */
	mxfs_shadow_eval_finish(log);
	/* the adopted slice's pass-1 clean-release marker table is
	 * recovery-scoped too — free it now rather than at unmount. */
	mxfs_relmark_tbl_free(log);

	clear_bit(XLOG_RECOVERY_NEEDED, &log->l_opstate);

	/* Make sure the log is dead if we're returning failure. */
	ASSERT(!error || xlog_is_shutdown(log));

	return error;
}

/*
 * The mount has failed. Cancel the recovery if it hasn't completed and destroy
 * the log.
 */
void
xfs_log_mount_cancel(
	struct xfs_mount	*mp)
{
	xlog_recover_cancel(mp->m_log);
	xfs_log_unmount(mp);
}

/*
 * Flush out the iclog to disk ensuring that device caches are flushed and
 * the iclog hits stable storage before any completion waiters are woken.
 */
static inline int
xlog_force_iclog(
	struct xlog_in_core	*iclog)
{
	atomic_inc(&iclog->ic_refcnt);
	iclog->ic_flags |= XLOG_ICL_NEED_FLUSH | XLOG_ICL_NEED_FUA;
	if (iclog->ic_state == XLOG_STATE_ACTIVE)
		xlog_state_switch_iclogs(iclog->ic_log, iclog, 0);
	return xlog_state_release_iclog(iclog->ic_log, iclog, NULL);
}

/*
 * Cycle all the iclogbuf locks to make sure all log IO completion
 * is done before we tear down these buffers.
 */
static void
xlog_wait_iclog_completion(struct xlog *log)
{
	int		i;
	struct xlog_in_core	*iclog = log->l_iclog;

	for (i = 0; i < log->l_iclog_bufs; i++) {
		down(&iclog->ic_sema);
		up(&iclog->ic_sema);
		iclog = iclog->ic_next;
	}
}

/*
 * Wait for the iclog and all prior iclogs to be written disk as required by the
 * log force state machine. Waiting on ic_force_wait ensures iclog completions
 * have been ordered and callbacks run before we are woken here, hence
 * guaranteeing that all the iclogs up to this one are on stable storage.
 */
int
xlog_wait_on_iclog(
	struct xlog_in_core	*iclog)
		__releases(iclog->ic_log->l_icloglock)
{
	struct xlog		*log = iclog->ic_log;

	trace_xlog_iclog_wait_on(iclog, _RET_IP_);
	if (!xlog_is_shutdown(log) &&
	    iclog->ic_state != XLOG_STATE_ACTIVE &&
	    iclog->ic_state != XLOG_STATE_DIRTY) {
		XFS_STATS_INC(log->l_mp, xs_log_force_sleep);
		xlog_wait(&iclog->ic_force_wait, &log->l_icloglock);
	} else {
		spin_unlock(&log->l_icloglock);
	}

	if (xlog_is_shutdown(log))
		return -EIO;
	return 0;
}

int
xlog_write_one_vec(
	struct xlog		*log,
	struct xfs_cil_ctx	*ctx,
	struct xfs_log_iovec	*reg,
	struct xlog_ticket	*ticket)
{
	struct xfs_log_vec	lv = {
		.lv_niovecs	= 1,
		.lv_iovecp	= reg,
		.lv_bytes	= reg->i_len,
	};
	LIST_HEAD		(lv_chain);

	/* account for space used by record data */
	ticket->t_curr_res -= lv.lv_bytes;

	list_add(&lv.lv_list, &lv_chain);
	return xlog_write(log, ctx, &lv_chain, ticket, lv.lv_bytes);
}

/*
 * Write out an unmount record using the ticket provided. We have to account for
 * the data space used in the unmount ticket as this write is not done from a
 * transaction context that has already done the accounting for us.
 */
static int
xlog_write_unmount_record(
	struct xlog		*log,
	struct xlog_ticket	*ticket)
{
	struct  {
		struct xlog_op_header ophdr;
		struct xfs_unmount_log_format ulf;
	} unmount_rec = {
		.ophdr = {
			.oh_clientid = XFS_LOG,
			.oh_tid = cpu_to_be32(ticket->t_tid),
			.oh_flags = XLOG_UNMOUNT_TRANS,
		},
		.ulf = {
			.magic = XLOG_UNMOUNT_TYPE,
		},
	};
	struct xfs_log_iovec reg = {
		.i_addr = &unmount_rec,
		.i_len = sizeof(unmount_rec),
		.i_type = XLOG_REG_TYPE_UNMOUNT,
	};

	return xlog_write_one_vec(log, NULL, &reg, ticket);
}

/*
 * Mark the filesystem clean by writing an unmount record to the head of the
 * log.
 */
static void
xlog_unmount_write(
	struct xlog		*log)
{
	struct xfs_mount	*mp = log->l_mp;
	struct xlog_in_core	*iclog;
	struct xlog_ticket	*tic = NULL;
	int			error;

	error = xfs_log_reserve(mp, 600, 1, &tic, 0);
	if (error)
		goto out_err;

	error = xlog_write_unmount_record(log, tic);
	/*
	 * At this point, we're umounting anyway, so there's no point in
	 * transitioning log state to shutdown. Just continue...
	 */
out_err:
	if (error)
		xfs_alert(mp, "%s: unmount record failed", __func__);

	spin_lock(&log->l_icloglock);
	iclog = log->l_iclog;
	error = xlog_force_iclog(iclog);
	xlog_wait_on_iclog(iclog);

	if (tic) {
		trace_xfs_log_umount_write(log, tic);
		xfs_log_ticket_ungrant(log, tic);
	}
}

static void
xfs_log_unmount_verify_iclog(
	struct xlog		*log)
{
	struct xlog_in_core	*iclog = log->l_iclog;

	do {
		ASSERT(iclog->ic_state == XLOG_STATE_ACTIVE);
		ASSERT(iclog->ic_offset == 0);
	} while ((iclog = iclog->ic_next) != log->l_iclog);
}

/*
 * Unmount record used to have a string "Unmount filesystem--" in the
 * data section where the "Un" was really a magic number (XLOG_UNMOUNT_TYPE).
 * We just write the magic number now since that particular field isn't
 * currently architecture converted and "Unmount" is a bit foo.
 * As far as I know, there weren't any dependencies on the old behaviour.
 */
static void
xfs_log_unmount_write(
	struct xfs_mount	*mp)
{
	struct xlog		*log = mp->m_log;

	if (!xfs_log_writable(mp))
		return;

	xfs_log_force(mp, XFS_LOG_SYNC);

	if (xlog_is_shutdown(log))
		return;

	/*
	 * If we think the summary counters are bad, avoid writing the unmount
	 * record to force log recovery at next mount, after which the summary
	 * counters will be recalculated.  Refer to xlog_check_unmount_rec for
	 * more details.
	 */
	if (xfs_fs_has_sickness(mp, XFS_SICK_FS_COUNTERS) ||
	    XFS_TEST_ERROR(mp, XFS_ERRTAG_FORCE_SUMMARY_RECALC)) {
		xfs_alert(mp, "%s: will fix summary counters at next mount",
				__func__);
		return;
	}

	xfs_log_unmount_verify_iclog(log);
	xlog_unmount_write(log);
}

/*
 * /475 (D-0133, design-consult design A+ and the placement ruling,
 * d0133-lock-inert-put-super-
 * teardown-shape9-hardened): the clustered SB summary counters are written
 * ONLY inside the summary critical section — dedicated cluster EX lock ->
 * uncached-coherent AGF/AGI recount -> cover (whole-sector SB home write) ->
 * device flush -> durable re-read -> unlock.  put_super runs it while the
 * DLM is alive (mxfs_sb_summary_final_sync holds the lock across this
 * function: m_mxfs_sb_lock_held); the freeze/remount-ro paths reach it with
 * the DLM alive too and take the lock here.  Every stage prints its probe
 * with the grant epoch so a fleet unmount's writers can be ordered.
 */
static int
mxfs_sb_summary_cover(
	struct xfs_mount	*mp)
{
	extern int mxfs_sb_read_counters_coherent(struct xfs_mount *,
			uint64_t *, uint64_t *, uint64_t *);
	extern int mxfs_sb_summary_lock(struct xfs_mount *, uint64_t *);
	extern void mxfs_sb_summary_unlock(struct xfs_mount *);
	extern int mxfs_sb_summary_recount_uncached(struct xfs_mount *,
						    unsigned int *);
	extern void mxfs_sb_summary_pause(struct xfs_mount *, int);
	extern int mxfs_sb_summary_master_self(struct xfs_mount *);
	uint64_t pre_ifree = percpu_counter_sum(&mp->m_ifree);
	uint64_t d_ic = 0, d_if = 0, d_fd = 0;
	unsigned int ags = 0;
	bool caller_held = mp->m_mxfs_sb_lock_held;
	int derr, error, lk = 0;

	if (!caller_held) {
		/* 0.75.34 (D-0536): node-local order against the runtime cover */
		mutex_lock(&mp->m_mxfs_sb_summary_mutex);
		lk = mxfs_sb_summary_lock(mp, &mp->m_mxfs_sb_grant_epoch);
		mxfs_probe("mxfs: P-SB-SUMMARY-LOCK slot=%u rc=%d epoch=%llu master_self=%d at=quiesce\n",
			mp->m_mxfs_node_slot, lk,
			(unsigned long long)mp->m_mxfs_sb_grant_epoch,
			mxfs_sb_summary_master_self(mp));
		if (lk) {
			/*
			 * Fail closed: never an unlocked whole-sector SB write.
			 * The counters stay whatever the platter holds; the
			 * next clustered mount recounts anyway.
			 */
			xfs_alert(mp,
	"MXFS: P-SB-SUMMARY-LOCK-FAIL slot=%u rc=%d — SB summary lock unavailable; NOT covering (no unlocked SB write)",
				  mp->m_mxfs_node_slot, lk);
			mutex_unlock(&mp->m_mxfs_sb_summary_mutex);
			return lk;
		}
		WRITE_ONCE(mp->m_mxfs_sb_lock_held, true);
	}
	mxfs_sb_summary_pause(mp, 1);
	/*
	 * P-SB-SYNC-PRE: the durable SB counters before this node's recount
	 * + cover, beside its own in-core view (instrumentation).
	 */
	derr = mxfs_sb_read_counters_coherent(mp, &d_ic, &d_if, &d_fd);
	mxfs_probe("mxfs: P-SB-SYNC-PRE slot=%u epoch=%llu local[icount=%llu ifree=%llu fdblocks=%llu] durable[err=%d icount=%llu ifree=%llu fdblocks=%llu]\n",
		mp->m_mxfs_node_slot,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch,
		(unsigned long long)percpu_counter_sum(&mp->m_icount),
		(unsigned long long)pre_ifree,
		(unsigned long long)xfs_sum_freecounter(mp, XC_FREE_BLOCKS),
		derr, (unsigned long long)d_ic,
		(unsigned long long)d_if, (unsigned long long)d_fd);
	error = mxfs_sb_summary_recount_uncached(mp, &ags);
	mxfs_probe("P30-QUIESCE-RECOUNT err=%d ifree pre=%llu post=%llu icount=%llu fdblocks=%llu\n",
		error, (unsigned long long)pre_ifree,
		(unsigned long long)mp->m_sb.sb_ifree,
		(unsigned long long)mp->m_sb.sb_icount,
		(unsigned long long)mp->m_sb.sb_fdblocks);
	mxfs_probe("mxfs: P-SB-RECOUNT-DONE slot=%u err=%d ags=%u mode=uncached-coherent\n",
		mp->m_mxfs_node_slot, error, ags);
	if (error) {
		/*
		 * Fail closed: a recount that could not read the coherent AG
		 * headers must not publish this node's private counters.
		 */
		xfs_alert(mp,
	"MXFS: P-SB-RECOUNT-FAIL slot=%u rc=%d — summary recount failed; NOT covering (no SB write from private counters)",
			  mp->m_mxfs_node_slot, error);
		goto out_unlock;
	}
	mxfs_sb_summary_pause(mp, 2);
	mxfs_probe("mxfs: P-SB-SYNC-WRITE slot=%u epoch=%llu icount=%llu ifree=%llu fdblocks=%llu — counters this node's cover logs into the whole SB sector\n",
		mp->m_mxfs_node_slot,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch,
		(unsigned long long)mp->m_sb.sb_icount,
		(unsigned long long)mp->m_sb.sb_ifree,
		(unsigned long long)mp->m_sb.sb_fdblocks);
	error = xfs_log_cover(mp);
	mxfs_sb_summary_pause(mp, 3);
	/* the SB home write is retired by the cover's AIL push; push the
	 * device cache before the lock is released */
	xfs_buftarg_wait(mp->m_ddev_targp);
	blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	derr = mxfs_sb_read_counters_coherent(mp, &d_ic, &d_if, &d_fd);
	mxfs_probe("mxfs: P-SB-SYNC-POST slot=%u epoch=%llu cover_err=%d durable[err=%d icount=%llu ifree=%llu fdblocks=%llu]\n",
		mp->m_mxfs_node_slot,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch, error, derr,
		(unsigned long long)d_ic, (unsigned long long)d_if,
		(unsigned long long)d_fd);
	if (!error && !derr &&
	    (d_ic != mp->m_sb.sb_icount || d_if != mp->m_sb.sb_ifree ||
	     d_fd != mp->m_sb.sb_fdblocks)) {
		/*
		 * Under the lock the durable sector must read back exactly
		 * what we wrote — anything else is a writer outside the
		 * protocol (D-0536 runtime covers) or a lost write.
		 */
		pr_err("mxfs: P-SB-SYNC-POST-MISMATCH slot=%u epoch=%llu wrote[icount=%llu ifree=%llu fdblocks=%llu] durable[icount=%llu ifree=%llu fdblocks=%llu]\n",
			mp->m_mxfs_node_slot,
			(unsigned long long)mp->m_mxfs_sb_grant_epoch,
			(unsigned long long)mp->m_sb.sb_icount,
			(unsigned long long)mp->m_sb.sb_ifree,
			(unsigned long long)mp->m_sb.sb_fdblocks,
			(unsigned long long)d_ic, (unsigned long long)d_if,
			(unsigned long long)d_fd);
		error = -EIO;
	}
	mxfs_sb_summary_pause(mp, 4);
out_unlock:
	if (!caller_held) {
		WRITE_ONCE(mp->m_mxfs_sb_lock_held, false);
		mxfs_sb_summary_unlock(mp);
		mxfs_probe("mxfs: P-SB-SUMMARY-UNLOCK slot=%u epoch=%llu held=1 at=quiesce\n",
			mp->m_mxfs_node_slot,
			(unsigned long long)mp->m_mxfs_sb_grant_epoch);
		mutex_unlock(&mp->m_mxfs_sb_summary_mutex);
	}
	return error;
}

/*
 * 0.75.34 (D-SB-RUNTIME-COVER-WRITES-PRIVATE-COUNTERS-OUTSIDE-SUMMARY-LOCK-
 * 0536): the clustered periodic log cover.  Upstream's cover (xfs_log_worker
 * -> xfs_sync_sb) logs the whole superblock with THIS node's private lazy
 * counters folded in and leaves the sector write to the AIL — measured on
 * 32 nodes (chain 116 v2) and on the two-node TCP rig (s520 sbrc
 * laps): an idle peer's 1 s-period cover landed unlocked inside another
 * node's summary critical section every time, so the lock was not
 * exclusive against all SB-sector writers.  The cover now runs inside the
 * same critical section as the quiesce cover:
 *   node mutex (trylock: a busy section means put_super or a freeze cover
 *   owns it, and this period's cover is simply skipped) -> cluster summary
 *   lock -> the three summary counters replaced by the DURABLE ones read
 *   uncached at the coherence point, never this node's private view (a
 *   cover changes no counter; it only stamps the log tail) -> sync commit ->
 *   the sector written synchronously here, which retires the AIL item so no
 *   delayed checkpoint can write it after the unlock -> device flush ->
 *   unlock.
 * Every failure skips the cover: the log stays uncovered until the next
 * period, which costs nothing, and there is never an unlocked SB write.
 */
static void
mxfs_sb_runtime_cover(
	struct xfs_mount	*mp)
{
	extern int mxfs_sb_read_counters_coherent(struct xfs_mount *,
			uint64_t *, uint64_t *, uint64_t *);
	extern int mxfs_sb_summary_lock(struct xfs_mount *, uint64_t *);
	extern void mxfs_sb_summary_unlock(struct xfs_mount *);
	struct xfs_trans	*tp;
	struct xfs_buf		*bp;
	uint64_t		d_ic = 0, d_if = 0, d_fd = 0, epoch = 0;
	int			lk, derr, error;

	if (!mutex_trylock(&mp->m_mxfs_sb_summary_mutex)) {
		mxfs_probe_ratelimited("mxfs: P-SB-RUNTIME-COVER-BUSY slot=%u — the summary section is held by this node's final sync or freeze cover; skipping this period's cover\n",
				    mp->m_mxfs_node_slot);
		return;
	}
	if (READ_ONCE(mp->m_mxfs_sb_sealed) || mp->m_mxfs_sb_summary_done ||
	    xfs_is_shutdown(mp) || !xfs_log_writable(mp)) {
		mxfs_probe_ratelimited("mxfs: P-SB-RUNTIME-COVER-SKIP slot=%u sealed=%d done=%d — no runtime cover after the final sync\n",
				    mp->m_mxfs_node_slot,
				    READ_ONCE(mp->m_mxfs_sb_sealed) ? 1 : 0,
				    mp->m_mxfs_sb_summary_done ? 1 : 0);
		goto out_mutex;
	}
	lk = mxfs_sb_summary_lock(mp, &epoch);
	if (lk) {
		mxfs_probe_ratelimited("mxfs: P-SB-RUNTIME-COVER-LOCK-FAIL slot=%u rc=%d — summary lock unavailable; NOT covering (no unlocked SB write)\n",
				    mp->m_mxfs_node_slot, lk);
		goto out_mutex;
	}
	mp->m_mxfs_sb_grant_epoch = epoch;
	WRITE_ONCE(mp->m_mxfs_sb_lock_held, true);
	derr = mxfs_sb_read_counters_coherent(mp, &d_ic, &d_if, &d_fd);
	if (derr) {
		mxfs_probe_ratelimited("mxfs: P-SB-RUNTIME-COVER-READ-FAIL slot=%u epoch=%llu rc=%d — durable counters unreadable; NOT covering\n",
				    mp->m_mxfs_node_slot,
				    (unsigned long long)epoch, derr);
		goto out_unlock;
	}
	spin_lock(&mp->m_sb_lock);
	mp->m_sb.sb_icount = d_ic;
	mp->m_sb.sb_ifree = d_if;
	mp->m_sb.sb_fdblocks = d_fd;
	spin_unlock(&mp->m_sb_lock);
	WRITE_ONCE(mp->m_mxfs_sb_cover_durable, true);
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_sb, 0, 0,
				XFS_TRANS_NO_WRITECOUNT, &tp);
	if (error) {
		WRITE_ONCE(mp->m_mxfs_sb_cover_durable, false);
		goto out_unlock;
	}
	bp = xfs_trans_getsb(tp);
	xfs_log_sb(tp);
	xfs_trans_bhold(tp, bp);
	xfs_trans_set_sync(tp);
	error = xfs_trans_commit(tp);
	WRITE_ONCE(mp->m_mxfs_sb_cover_durable, false);
	if (!error)
		error = xfs_bwrite(bp);	/* the home write, inside the section */
	xfs_buf_relse(bp);
	if (!error) {
		xfs_buftarg_wait(mp->m_ddev_targp);
		blkdev_issue_flush(mp->m_ddev_targp->bt_bdev);
	}
	mxfs_probe("mxfs: P-SB-RUNTIME-COVER slot=%u epoch=%llu rc=%d durable[icount=%llu ifree=%llu fdblocks=%llu] — periodic log cover written under the summary lock with the durable counters\n",
		mp->m_mxfs_node_slot, (unsigned long long)epoch, error,
		(unsigned long long)d_ic, (unsigned long long)d_if,
		(unsigned long long)d_fd);
out_unlock:
	WRITE_ONCE(mp->m_mxfs_sb_lock_held, false);
	mxfs_sb_summary_unlock(mp);
out_mutex:
	mutex_unlock(&mp->m_mxfs_sb_summary_mutex);
}

/*
 * the guarded quiesce after put_super's locked final sync (the DLM
 * is gone by now).  Nothing may have logged since the seal: the log must
 * still be covered and every seal counter zero — then there is nothing to
 * write and the unmount record may follow.  Otherwise the clean departure is
 * REFUSED: XFS_SICK_FS_COUNTERS withholds the unmount record, the departure
 * goes DIRTY (slot retained, peers recover the slice) and the platter SB is
 * left to the last locked writer.  Never an unlocked whole-sector SB write.
 */
static int
mxfs_sb_summary_sealed_quiesce(
	struct xfs_mount	*mp)
{
	struct xlog		*log = mp->m_log;
	int			st;
	bool			cil_empty, iclogs_empty, ail_empty, covered;
	int			n_trans = atomic_read(&mp->m_mxfs_seal_trans);
	int			n_syncsb = atomic_read(&mp->m_mxfs_seal_syncsb);
	int			n_sbwrite = atomic_read(&mp->m_mxfs_seal_sbwrite);

	if (!xfs_log_writable(mp))
		return 0;
	spin_lock(&log->l_icloglock);
	st = log->l_covered_state;
	iclogs_empty = xlog_iclogs_empty(log);
	spin_unlock(&log->l_icloglock);
	cil_empty = xlog_cil_empty(log);
	ail_empty = xfs_ail_min_lsn(log->l_ailp) == 0;
	covered = cil_empty && iclogs_empty && ail_empty &&
		  (st == XLOG_STATE_COVER_DONE || st == XLOG_STATE_COVER_DONE2 ||
		   st == XLOG_STATE_COVER_IDLE);
	if (covered && !mp->m_mxfs_sb_late_dirty &&
	    n_trans == 0 && n_syncsb == 0 && n_sbwrite == 0) {
		mxfs_probe("mxfs: P-SB-SEAL-OK slot=%u epoch=%llu cover_state=%d trans=0 syncsb=0 sbwrite=0 — sealed quiesce writes nothing\n",
			mp->m_mxfs_node_slot,
			(unsigned long long)mp->m_mxfs_sb_grant_epoch, st);
		return 0;
	}
	mp->m_mxfs_sb_late_dirty = true;
	xfs_fs_mark_sick(mp, XFS_SICK_FS_COUNTERS);
	pr_err("mxfs: P-SB-LATE-DIRTY-COVER slot=%u epoch=%llu cover_state=%d cil_empty=%d iclogs_empty=%d ail_empty=%d trans=%d syncsb=%d sbwrite=%d — log dirtied after the SB summary seal; REFUSING the clean departure (no unmount record, slot retained, no unlocked SB write)\n",
		mp->m_mxfs_node_slot,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch, st,
		cil_empty ? 1 : 0, iclogs_empty ? 1 : 0, ail_empty ? 1 : 0,
		n_trans, n_syncsb, n_sbwrite);
	return -EBUSY;
}

/*
 * Empty the log for unmount/freeze.
 *
 * To do this, we first need to shut down the background log work so it is not
 * trying to cover the log as we clean up. We then need to unpin all objects in
 * the log so we can then flush them out. Once they have completed their IO and
 * run the callbacks removing themselves from the AIL, we can cover the log.
 */
int
xfs_log_quiesce(
	struct xfs_mount	*mp)
{
	/*
	 * Clear log incompat features since we're quiescing the log.  Report
	 * failures, though it's not fatal to have a higher log feature
	 * protection level than the log contents actually require.
	 */
	if (xfs_clear_incompat_log_features(mp)) {
		int error;

		error = xfs_sync_sb(mp, false);
		if (error)
			xfs_warn(mp,
	"Failed to clear log incompat features on quiesce");
	}

	cancel_delayed_work_sync(&mp->m_log->l_work);
	xfs_log_force(mp, XFS_LOG_SYNC);

	/*
	 * The superblock buffer is uncached and while xfs_ail_push_all_sync()
	 * will push it, xfs_buftarg_wait() will not wait for it. Further,
	 * xfs_buf_iowait() cannot be used because it was pushed with the
	 * XBF_ASYNC flag set, so we need to use a lock/unlock pair to wait for
	 * the IO to complete.
	 */
	xfs_ail_push_all_sync(mp->m_ail);
	xfs_buftarg_wait(mp->m_ddev_targp);
	xfs_buf_lock(mp->m_sb_bp);
	xfs_buf_unlock(mp->m_sb_bp);

	/*
	 * mxfs (run14d): the lazy-sbcount sync in xfs_log_cover folds
	 * THIS node's in-core percpu counters into the on-disk superblock.
	 * On a shared LUN those counters only track our own deltas — a node
	 * that idled while a peer allocated inodes/blocks would clobber the
	 * peer's accurate counters with its own mount-time snapshot (proven:
	 * 2-node chk_clean, idle node unmounting last wrote ifree=61 over the
	 * writer's 28).  Recompute the summary counters from the on-disk
	 * AGF/AGI before covering.  Our own dirty AG headers are already on
	 * disk (AIL emptied above); the AG-meta read path FUA-refreshes any
	 * buffer not protected by a held DLM lock.  Do NOT gate this on
	 * is_single_node — the last node out sees no peers but may still
	 * hold stale counters from when peers were active.  On failure keep
	 * the old counters; the next mount recalculates (lazy sbcount).
	 */
	if (mp->m_mxfs_dlm_was_active && xfs_has_lazysbcount(mp)) {
		/*
		 * 0.84.5 (D-...-0960): a mount refused before xfs_mountfs
		 * completed (its root lookup met a stalled authority
		 * transition, or any earlier failure) unwinds through here from
		 * xfs_log_mount_cancel.  The summary lock below is a plain,
		 * non-fallible cluster acquire, and measured on the stalled
		 * takeover arm it parked the refused mount's unwind on the very
		 * transition the mount had just been refused for, until the
		 * takeover moved again (70 s, s590j).  Nothing such a mount did
		 * is unreflected in the AG headers (its AIL was pushed above);
		 * the summary counters are derived state the last node out
		 * recounts under the lock and the next clustered mount recounts
		 * anyway.  Write nothing: no cluster acquire, and never an
		 * unlocked SB write.
		 */
		if (!mp->m_mxfs_mount_complete) {
			xfs_notice(mp,
	"MXFS: P960-REFUSED-MOUNT-NOCOVER slot=%u — the mount never completed; its quiesce writes no SB summary and takes no cluster lock for one",
				   mp->m_mxfs_node_slot);
			return 0;
		}
		if (mp->m_mxfs_sb_summary_done)
			return mxfs_sb_summary_sealed_quiesce(mp);
		return mxfs_sb_summary_cover(mp);
	}

	return xfs_log_cover(mp);
}

void
xfs_log_clean(
	struct xfs_mount	*mp)
{
	xfs_log_quiesce(mp);
	xfs_log_unmount_write(mp);
}

/*
 * Shut down and release the AIL and Log.
 *
 * During unmount, we need to ensure we flush all the dirty metadata objects
 * from the AIL so that the log is empty before we write the unmount record to
 * the log. Once this is done, we can tear down the AIL and the log.
 */
void
xfs_log_unmount(
	struct xfs_mount	*mp)
{
	/* a prefetched slice proof must never outlive its mount */
	mxfs_xlog_snap_prefetch_cancel(mp);
	xfs_log_clean(mp);

	/*
	 * If shutdown has come from iclog IO context, the log
	 * cleaning will have been skipped and so we need to wait
	 * for the iclog to complete shutdown processing before we
	 * tear anything down.
	 */
	xlog_wait_iclog_completion(mp->m_log);

	xfs_buftarg_drain(mp->m_ddev_targp);

	xfs_trans_ail_destroy(mp);

	xfs_sysfs_del(&mp->m_log->l_kobj);

	xlog_dealloc_log(mp->m_log);
}

void
xfs_log_item_init(
	struct xfs_mount	*mp,
	struct xfs_log_item	*item,
	int			type,
	const struct xfs_item_ops *ops)
{
	item->li_log = mp->m_log;
	item->li_ailp = mp->m_ail;
	item->li_type = type;
	item->li_ops = ops;
	item->li_lv = NULL;

	INIT_LIST_HEAD(&item->li_ail);
	INIT_LIST_HEAD(&item->li_cil);
	INIT_LIST_HEAD(&item->li_bio_list);
	INIT_LIST_HEAD(&item->li_trans);
}

/*
 * Wake up processes waiting for log space after we have moved the log tail.
 */
void
xfs_log_space_wake(
	struct xfs_mount	*mp)
{
	struct xlog		*log = mp->m_log;
	int			free_bytes;

	if (xlog_is_shutdown(log))
		return;

	if (!list_empty_careful(&log->l_write_head.waiters)) {
		ASSERT(!xlog_in_recovery(log));

		spin_lock(&log->l_write_head.lock);
		free_bytes = xlog_grant_space_left(log, &log->l_write_head);
		xlog_grant_head_wake(log, &log->l_write_head, &free_bytes);
		spin_unlock(&log->l_write_head.lock);
	}

	if (!list_empty_careful(&log->l_reserve_head.waiters)) {
		ASSERT(!xlog_in_recovery(log));

		spin_lock(&log->l_reserve_head.lock);
		free_bytes = xlog_grant_space_left(log, &log->l_reserve_head);
		xlog_grant_head_wake(log, &log->l_reserve_head, &free_bytes);
		spin_unlock(&log->l_reserve_head.lock);
	}
}

/*
 * Determine if we have a transaction that has gone to disk that needs to be
 * covered. To begin the transition to the idle state firstly the log needs to
 * be idle. That means the CIL, the AIL and the iclogs needs to be empty before
 * we start attempting to cover the log.
 *
 * Only if we are then in a state where covering is needed, the caller is
 * informed that dummy transactions are required to move the log into the idle
 * state.
 *
 * If there are any items in the AIl or CIL, then we do not want to attempt to
 * cover the log as we may be in a situation where there isn't log space
 * available to run a dummy transaction and this can lead to deadlocks when the
 * tail of the log is pinned by an item that is modified in the CIL.  Hence
 * there's no point in running a dummy transaction at this point because we
 * can't start trying to idle the log until both the CIL and AIL are empty.
 */
static bool
xfs_log_need_covered(
	struct xfs_mount	*mp)
{
	struct xlog		*log = mp->m_log;
	bool			needed = false;

	if (!xlog_cil_empty(log))
		return false;

	spin_lock(&log->l_icloglock);
	switch (log->l_covered_state) {
	case XLOG_STATE_COVER_DONE:
	case XLOG_STATE_COVER_DONE2:
	case XLOG_STATE_COVER_IDLE:
		break;
	case XLOG_STATE_COVER_NEED:
	case XLOG_STATE_COVER_NEED2:
		if (xfs_ail_min_lsn(log->l_ailp))
			break;
		if (!xlog_iclogs_empty(log))
			break;

		needed = true;
		if (log->l_covered_state == XLOG_STATE_COVER_NEED)
			log->l_covered_state = XLOG_STATE_COVER_DONE;
		else
			log->l_covered_state = XLOG_STATE_COVER_DONE2;
		break;
	default:
		needed = true;
		break;
	}
	spin_unlock(&log->l_icloglock);
	return needed;
}

/*
 * Explicitly cover the log. This is similar to background log covering but
 * intended for usage in quiesce codepaths. The caller is responsible to ensure
 * the log is idle and suitable for covering. The CIL, iclog buffers and AIL
 * must all be empty.
 */
static int
xfs_log_cover(
	struct xfs_mount	*mp)
{
	int			error = 0;
	bool			need_covered;

	if (!xlog_is_shutdown(mp->m_log)) {
		ASSERT(xlog_cil_empty(mp->m_log));
		ASSERT(xlog_iclogs_empty(mp->m_log));
		ASSERT(!xfs_ail_min_lsn(mp->m_log->l_ailp));
	}

	if (!xfs_log_writable(mp))
		return 0;

	/*
	 * xfs_log_need_covered() is not idempotent because it progresses the
	 * state machine if the log requires covering. Therefore, we must call
	 * this function once and use the result until we've issued an sb sync.
	 * Do so first to make that abundantly clear.
	 *
	 * Fall into the covering sequence if the log needs covering or the
	 * mount has lazy superblock accounting to sync to disk. The sb sync
	 * used for covering accumulates the in-core counters, so covering
	 * handles this for us.
	 */
	need_covered = xfs_log_need_covered(mp);
	if (!need_covered && !xfs_has_lazysbcount(mp))
		return 0;

	/*
	 * To cover the log, commit the superblock twice (at most) in
	 * independent checkpoints. The first serves as a reference for the
	 * tail pointer. The sync transaction and AIL push empties the AIL and
	 * updates the in-core tail to the LSN of the first checkpoint. The
	 * second commit updates the on-disk tail with the in-core LSN,
	 * covering the log. Push the AIL one more time to leave it empty, as
	 * we found it.
	 */
	do {
		error = xfs_sync_sb(mp, true);
		if (error)
			break;
		xfs_ail_push_all_sync(mp->m_ail);
	} while (xfs_log_need_covered(mp));

	return error;
}

static void
xlog_ioend_work(
	struct work_struct	*work)
{
	struct xlog_in_core     *iclog =
		container_of(work, struct xlog_in_core, ic_end_io_work);
	struct xlog		*log = iclog->ic_log;
	int			error;

	error = blk_status_to_errno(iclog->ic_bio.bi_status);
#ifdef DEBUG
	/* treat writes with injected CRC errors as failed */
	if (iclog->ic_fail_crc)
		error = -EIO;
#endif
	if (unlikely(!error && READ_ONCE(mxfs_log_inject_ioerr) > 0) &&
	    mxfs_log_inject_ioerr_take()) {
		xfs_alert(log->l_mp,
			  "P-LOG-INJECT-IOERR: failing iclog write completion (test knob)");
		error = -EIO;
	}

	/*
	 * Race to shutdown the filesystem if we see an error.
	 */
	/*
	 * (D-FENCED-VICTIM-NONCONTAINMENT-498): a log write bounced
	 * with SCSI RESERVATION CONFLICT means this node has been fenced.  The
	 * shutdown below still happens; ALSO tell the DLM so the fenced-self
	 * inspection runs and the cluster withdrawal (leave, stop fencing
	 * peers) does not wait on a slower path.  Nonblocking (flag only).
	 */
	if (unlikely(error == -EBADE)) {
		struct mxfs_v5_dlm *v5 = READ_ONCE(log->l_mp->m_mxfs_dlm);

		if (v5)
			mxfs_v5_dlm_note_resv_conflict(v5);
	}
	if (error || XFS_TEST_ERROR(log->l_mp, XFS_ERRTAG_IODONE_IOERR)) {
		xfs_alert(log->l_mp, "log I/O error %d", error);
		xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR);
	}

	xlog_state_done_syncing(iclog);
	bio_uninit(&iclog->ic_bio);

	/*
	 * Drop the lock to signal that we are done. Nothing references the
	 * iclog after this, so an unmount waiting on this lock can now tear it
	 * down safely. As such, it is unsafe to reference the iclog after the
	 * unlock as we could race with it being freed.
	 */
	up(&iclog->ic_sema);
}

/*
 * Return size of each in-core log record buffer.
 *
 * All machines get 8 x 32kB buffers by default, unless tuned otherwise.
 *
 * If the filesystem blocksize is too large, we may need to choose a
 * larger size since the directory code currently logs entire blocks.
 */
STATIC void
xlog_get_iclog_buffer_size(
	struct xfs_mount	*mp,
	struct xlog		*log)
{
	if (mp->m_logbufs <= 0)
		mp->m_logbufs = XLOG_MAX_ICLOGS;
	if (mp->m_logbsize <= 0)
		mp->m_logbsize = XLOG_BIG_RECORD_BSIZE;

	log->l_iclog_bufs = mp->m_logbufs;
	log->l_iclog_size = mp->m_logbsize;

	/*
	 * Combined size of the log record headers.  The first 32k cycles
	 * are stored directly in the xlog_rec_header, the rest in the
	 * variable number of xlog_rec_ext_headers at its end.
	 */
	log->l_iclog_hsize = struct_size(log->l_iclog->ic_header, h_ext,
		DIV_ROUND_UP(mp->m_logbsize, XLOG_HEADER_CYCLE_SIZE) - 1);
}

void
xfs_log_work_queue(
	struct xfs_mount        *mp)
{
	queue_delayed_work(mp->m_sync_workqueue, &mp->m_log->l_work,
				msecs_to_jiffies(xfs_syncd_centisecs * 10));
}

/*
 * Clear the log incompat flags if we have the opportunity.
 *
 * This only happens if we're about to log the second dummy transaction as part
 * of covering the log.
 */
static inline void
xlog_clear_incompat(
	struct xlog		*log)
{
	struct xfs_mount	*mp = log->l_mp;

	if (!xfs_sb_has_incompat_log_feature(&mp->m_sb,
				XFS_SB_FEAT_INCOMPAT_LOG_ALL))
		return;

	if (log->l_covered_state != XLOG_STATE_COVER_DONE2)
		return;

	xfs_clear_incompat_log_features(mp);
}

/*
 * Every sync period we need to unpin all items in the AIL and push them to
 * disk. If there is nothing dirty, then we might need to cover the log to
 * indicate that the filesystem is idle.
 */
static void
xfs_log_worker(
	struct work_struct	*work)
{
	struct xlog		*log = container_of(to_delayed_work(work),
						struct xlog, l_work);
	struct xfs_mount	*mp = log->l_mp;

	/* dgc: errors ignored - not fatal and nowhere to report them */
	if (xfs_fs_writable(mp, SB_FREEZE_WRITE) && xfs_log_need_covered(mp)) {
		/*
		 * Dump a transaction into the log that contains no real change.
		 * This is needed to stamp the current tail LSN into the log
		 * during the covering operation.
		 *
		 * We cannot use an inode here for this - that will push dirty
		 * state back up into the VFS and then periodic inode flushing
		 * will prevent log covering from making progress. Hence we
		 * synchronously log the superblock instead to ensure the
		 * superblock is immediately unpinned and can be written back.
		 */
		xlog_clear_incompat(log);
		/*
		 * 0.75.34 (D-0536): a clustered mount covers inside the SB
		 * summary critical section with the durable counters; the
		 * plain sync_sb below would publish this node's private
		 * counters in an unlocked whole-sector write.
		 */
		if (mp->m_mxfs_dlm && mp->m_mxfs_dlm_was_active &&
		    xfs_has_lazysbcount(mp))
			mxfs_sb_runtime_cover(mp);
		else
			xfs_sync_sb(mp, true);
	} else
		xfs_log_force(mp, 0);

	/* start pushing all the metadata that is currently dirty */
	xfs_ail_push_all(mp->m_ail);

	/* queue us up again */
	xfs_log_work_queue(mp);
}

/*
 * This routine initializes some of the log structure for a given mount point.
 * Its primary purpose is to fill in enough, so recovery can occur.  However,
 * some other stuff may be filled in too.
 */
STATIC struct xlog *
xlog_alloc_log(
	struct xfs_mount	*mp,
	struct xfs_buftarg	*log_target,
	xfs_daddr_t		blk_offset,
	int			num_bblks)
{
	struct xlog		*log;
	struct xlog_in_core	**iclogp;
	struct xlog_in_core	*iclog, *prev_iclog = NULL;
	int			i;
	int			error = -ENOMEM;
	uint			log2_size = 0;

	log = kzalloc(sizeof(struct xlog), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!log) {
		xfs_warn(mp, "Log allocation failed: No memory!");
		goto out;
	}

	log->l_mp	   = mp;
	log->l_targ	   = log_target;
	log->l_logsize     = BBTOB(num_bblks);
	log->l_logBBstart  = blk_offset;
	log->l_logBBsize   = num_bblks;
	log->l_covered_state = XLOG_STATE_COVER_IDLE;
	set_bit(XLOG_ACTIVE_RECOVERY, &log->l_opstate);
	INIT_DELAYED_WORK(&log->l_work, xfs_log_worker);
	INIT_LIST_HEAD(&log->r_dfops);

	log->l_prev_block  = -1;
	/* log->l_tail_lsn = 0x100000000LL; cycle = 1; current block = 0 */
	xlog_assign_atomic_lsn(&log->l_tail_lsn, 1, 0);
	log->l_curr_cycle  = 1;	    /* 0 is bad since this is initial value */

	/* slot 0 is valid, so the no-victim state needs a sentinel —
	 * kzalloc's 0 would silently mean "evaluate against slot 0".
	 * eval state/missed-count explicitly initialized (design-consult
	 * review) rather than riding the allocator's zeroing. */
	log->l_mxfs_victim_slot = MXFS_XLOG_VICTIM_NONE;
	log->l_mxfs_shadow_eval = NULL;
	log->l_mxfs_shadow_missed = 0;

	if (xfs_has_logv2(mp) && mp->m_sb.sb_logsunit > 1)
		log->l_iclog_roundoff = mp->m_sb.sb_logsunit;
	else
		log->l_iclog_roundoff = BBSIZE;

	xlog_grant_head_init(&log->l_reserve_head);
	xlog_grant_head_init(&log->l_write_head);

	error = -EFSCORRUPTED;
	if (xfs_has_sector(mp)) {
	        log2_size = mp->m_sb.sb_logsectlog;
		if (log2_size < BBSHIFT) {
			xfs_warn(mp, "Log sector size too small (0x%x < 0x%x)",
				log2_size, BBSHIFT);
			goto out_free_log;
		}

	        log2_size -= BBSHIFT;
		if (log2_size > mp->m_sectbb_log) {
			xfs_warn(mp, "Log sector size too large (0x%x > 0x%x)",
				log2_size, mp->m_sectbb_log);
			goto out_free_log;
		}

		/* for larger sector sizes, must have v2 or external log */
		if (log2_size && log->l_logBBstart > 0 &&
			    !xfs_has_logv2(mp)) {
			xfs_warn(mp,
		"log sector size (0x%x) invalid for configuration.",
				log2_size);
			goto out_free_log;
		}
	}
	log->l_sectBBsize = 1 << log2_size;

	xlog_get_iclog_buffer_size(mp, log);

	spin_lock_init(&log->l_icloglock);
	init_waitqueue_head(&log->l_flush_wait);

	iclogp = &log->l_iclog;
	ASSERT(log->l_iclog_size >= 4096);
	for (i = 0; i < log->l_iclog_bufs; i++) {
		size_t bvec_size = howmany(log->l_iclog_size, PAGE_SIZE) *
				sizeof(struct bio_vec);

		iclog = kzalloc(sizeof(*iclog) + bvec_size,
				GFP_KERNEL | __GFP_RETRY_MAYFAIL);
		if (!iclog)
			goto out_free_iclog;

		*iclogp = iclog;
		iclog->ic_prev = prev_iclog;
		prev_iclog = iclog;

		iclog->ic_header = kvzalloc(log->l_iclog_size,
				GFP_KERNEL | __GFP_RETRY_MAYFAIL);
		if (!iclog->ic_header)
			goto out_free_iclog;
		iclog->ic_header->h_magicno =
			cpu_to_be32(XLOG_HEADER_MAGIC_NUM);
		iclog->ic_header->h_version = cpu_to_be32(
			xfs_has_logv2(log->l_mp) ? 2 : 1);
		iclog->ic_header->h_size = cpu_to_be32(log->l_iclog_size);
		iclog->ic_header->h_fmt = cpu_to_be32(XLOG_FMT);
		memcpy(&iclog->ic_header->h_fs_uuid, &mp->m_sb.sb_uuid,
			sizeof(iclog->ic_header->h_fs_uuid));

		iclog->ic_datap = (void *)iclog->ic_header + log->l_iclog_hsize;
		iclog->ic_size = log->l_iclog_size - log->l_iclog_hsize;
		iclog->ic_state = XLOG_STATE_ACTIVE;
		iclog->ic_log = log;
		atomic_set(&iclog->ic_refcnt, 0);
		INIT_LIST_HEAD(&iclog->ic_callbacks);

		init_waitqueue_head(&iclog->ic_force_wait);
		init_waitqueue_head(&iclog->ic_write_wait);
		INIT_WORK(&iclog->ic_end_io_work, xlog_ioend_work);
		sema_init(&iclog->ic_sema, 1);

		iclogp = &iclog->ic_next;
	}
	*iclogp = log->l_iclog;			/* complete ring */
	log->l_iclog->ic_prev = prev_iclog;	/* re-write 1st prev ptr */

	log->l_ioend_workqueue = alloc_workqueue("xfs-log/%s",
			XFS_WQFLAGS(WQ_FREEZABLE | WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_PERCPU),
			0, mp->m_super->s_id);
	if (!log->l_ioend_workqueue)
		goto out_free_iclog;

	error = xlog_cil_init(log);
	if (error)
		goto out_destroy_workqueue;
	return log;

out_destroy_workqueue:
	destroy_workqueue(log->l_ioend_workqueue);
out_free_iclog:
	for (iclog = log->l_iclog; iclog; iclog = prev_iclog) {
		prev_iclog = iclog->ic_next;
		kvfree(iclog->ic_header);
		kfree(iclog);
		if (prev_iclog == log->l_iclog)
			break;
	}
out_free_log:
	kfree(log);
out:
	return ERR_PTR(error);
}	/* xlog_alloc_log */

/*
 * Stamp cycle number in every block
 */
STATIC void
xlog_pack_data(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	int			roundoff)
{
	struct xlog_rec_header	*rhead = iclog->ic_header;
	__be32			cycle_lsn = CYCLE_LSN_DISK(rhead->h_lsn);
	char			*dp = iclog->ic_datap;
	int			i;

	for (i = 0; i < BTOBB(iclog->ic_offset + roundoff); i++) {
		*xlog_cycle_data(rhead, i) = *(__be32 *)dp;
		*(__be32 *)dp = cycle_lsn;
		dp += BBSIZE;
	}

	for (i = 0; i < (log->l_iclog_hsize >> BBSHIFT) - 1; i++)
		rhead->h_ext[i].xh_cycle = cycle_lsn;
}

/*
 * Calculate the checksum for a log buffer.
 *
 * This is a little more complicated than it should be because the various
 * headers and the actual data are non-contiguous.
 */
__le32
xlog_cksum(
	struct xlog		*log,
	struct xlog_rec_header	*rhead,
	char			*dp,
	unsigned int		hdrsize,
	unsigned int		size)
{
	uint32_t		crc;

	/* first generate the crc for the record header ... */
	crc = xfs_start_cksum_update((char *)rhead, hdrsize,
			      offsetof(struct xlog_rec_header, h_crc));

	/* ... then for additional cycle data for v2 logs ... */
	if (xfs_has_logv2(log->l_mp)) {
		int		xheads, i;

		xheads = DIV_ROUND_UP(size, XLOG_HEADER_CYCLE_SIZE) - 1;
		for (i = 0; i < xheads; i++)
			crc = crc32c(crc, &rhead->h_ext[i], XLOG_REC_EXT_SIZE);
	}

	/* ... and finally for the payload */
	crc = crc32c(crc, dp, size);

	return xfs_end_cksum(crc);
}

static void
xlog_bio_end_io(
	struct bio		*bio)
{
	struct xlog_in_core	*iclog = bio->bi_private;

	queue_work(iclog->ic_log->l_ioend_workqueue,
		   &iclog->ic_end_io_work);
}

STATIC void
xlog_write_iclog(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	uint64_t		bno,
	unsigned int		count)
{
	ASSERT(bno < log->l_logBBsize);
	trace_xlog_iclog_write(iclog, _RET_IP_);

	/*
	 * We lock the iclogbufs here so that we can serialise against I/O
	 * completion during unmount.  We might be processing a shutdown
	 * triggered during unmount, and that can occur asynchronously to the
	 * unmount thread, and hence we need to ensure that completes before
	 * tearing down the iclogbufs.  Hence we need to hold the buffer lock
	 * across the log IO to archieve that.
	 */
	down(&iclog->ic_sema);
	if (xlog_is_shutdown(log)) {
		/*
		 * It would seem logical to return EIO here, but we rely on
		 * the log state machine to propagate I/O errors instead of
		 * doing it here.  We kick of the state machine and unlock
		 * the buffer manually, the code needs to be kept in sync
		 * with the I/O completion path.
		 */
		goto sync;
	}

	/*
	 * THE AUTHORITY GATE, journal arm.  An iclog is the most tempting thing
	 * in the filesystem to exempt — it is how the log stays consistent, and
	 * refusing it guarantees a dirty log.  It gets no exemption, because an
	 * "essential journal write" carve-out reopens the whole hazard: the
	 * journal slice this node would be writing is the slice a successor may
	 * already be replaying, and a write into it is exactly the unordered
	 * logical write into metadata-being-rewritten that the retirement proof
	 * exists to prevent.
	 *
	 * A dirty log is the correct outcome here.  This is a forced-shutdown
	 * path, not a clean unmount, and a node whose authority has expired must
	 * not try to make its filesystem look clean by issuing more writes.
	 * Recovery decides what was committed, once old-epoch mutation has been
	 * excluded.
	 */
	if (log->l_mp) {
		if (!mxfs_mount_write_admitted(log->l_mp, "log")) {
			xfs_alert(log->l_mp,
				  "P290-AUTH-REFUSED-LOG bno=%llu count=%u — this node's authority over the shared LUN has expired; the log write is REFUSED and the log is left dirty for recovery",
				  (unsigned long long)bno, count);
			goto shutdown;
		}
	}

	/*
	 * We use REQ_SYNC | REQ_IDLE here to tell the block layer the are more
	 * IOs coming immediately after this one. This prevents the block layer
	 * writeback throttle from throttling log writes behind background
	 * metadata writeback and causing priority inversions.
	 */
	bio_init(&iclog->ic_bio, log->l_targ->bt_bdev, iclog->ic_bvec,
		 howmany(count, PAGE_SIZE),
		 REQ_OP_WRITE | REQ_META | REQ_SYNC | REQ_IDLE);
	iclog->ic_bio.bi_iter.bi_sector = log->l_targ->bt_sector_offset +
					log->l_logBBstart + bno;
	iclog->ic_bio.bi_end_io = xlog_bio_end_io;
	iclog->ic_bio.bi_private = iclog;

	if (iclog->ic_flags & XLOG_ICL_NEED_FLUSH) {
		iclog->ic_bio.bi_opf |= REQ_PREFLUSH;
		/*
		 * For external log devices, we also need to flush the data
		 * device cache first to ensure all metadata writeback covered
		 * by the LSN in this iclog is on stable storage. This is slow,
		 * but it *must* complete before we issue the external log IO.
		 *
		 * If the flush fails, we cannot conclude that past metadata
		 * writeback from the log succeeded.  Repeating the flush is
		 * not possible, hence we must shut down with log IO error to
		 * avoid shutdown re-entering this path and erroring out again.
		 */
		if (log->l_targ != log->l_mp->m_ddev_targp &&
		    blkdev_issue_flush(log->l_mp->m_ddev_targp->bt_bdev))
			goto shutdown;
	}
	if (iclog->ic_flags & XLOG_ICL_NEED_FUA)
		iclog->ic_bio.bi_opf |= REQ_FUA;

	iclog->ic_flags &= ~(XLOG_ICL_NEED_FLUSH | XLOG_ICL_NEED_FUA);

	if (is_vmalloc_addr(iclog->ic_header)) {
		if (!bio_add_vmalloc(&iclog->ic_bio, iclog->ic_header, count))
			goto shutdown;
	} else {
		bio_add_virt_nofail(&iclog->ic_bio, iclog->ic_header, count);
	}

	/*
	 * If this log buffer would straddle the end of the log we will have
	 * to split it up into two bios, so that we can continue at the start.
	 */
	if (bno + BTOBB(count) > log->l_logBBsize) {
		struct bio *split;

		split = bio_split(&iclog->ic_bio, log->l_logBBsize - bno,
				  GFP_NOIO, &fs_bio_set);
		bio_chain(split, &iclog->ic_bio);
		submit_bio(split);

		/* restart at logical offset zero for the remainder */
		iclog->ic_bio.bi_iter.bi_sector = log->l_targ->bt_sector_offset +
						  log->l_logBBstart;
	}

	submit_bio(&iclog->ic_bio);
	return;
shutdown:
	xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR);
sync:
	xlog_state_done_syncing(iclog);
	up(&iclog->ic_sema);
}

/*
 * We need to bump cycle number for the part of the iclog that is
 * written to the start of the log. Watch out for the header magic
 * number case, though.
 */
static void
xlog_split_iclog(
	struct xlog		*log,
	void			*data,
	uint64_t		bno,
	unsigned int		count)
{
	unsigned int		split_offset = BBTOB(log->l_logBBsize - bno);
	unsigned int		i;

	for (i = split_offset; i < count; i += BBSIZE) {
		uint32_t cycle = get_unaligned_be32(data + i);

		if (++cycle == XLOG_HEADER_MAGIC_NUM)
			cycle++;
		put_unaligned_be32(cycle, data + i);
	}
}

static int
xlog_calc_iclog_size(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	uint32_t		*roundoff)
{
	uint32_t		count_init, count;

	/* Add for LR header */
	count_init = log->l_iclog_hsize + iclog->ic_offset;
	count = roundup(count_init, log->l_iclog_roundoff);

	*roundoff = count - count_init;

	ASSERT(count >= count_init);
	ASSERT(*roundoff < log->l_iclog_roundoff);
	return count;
}

/*
 * Flush out the in-core log (iclog) to the on-disk log in an asynchronous
 * fashion.  Previously, we should have moved the current iclog
 * ptr in the log to point to the next available iclog.  This allows further
 * write to continue while this code syncs out an iclog ready to go.
 * Before an in-core log can be written out, the data section must be scanned
 * to save away the 1st word of each BBSIZE block into the header.  We replace
 * it with the current cycle count.  Each BBSIZE block is tagged with the
 * cycle count because there in an implicit assumption that drives will
 * guarantee that entire 512 byte blocks get written at once.  In other words,
 * we can't have part of a 512 byte block written and part not written.  By
 * tagging each block, we will know which blocks are valid when recovering
 * after an unclean shutdown.
 *
 * This routine is single threaded on the iclog.  No other thread can be in
 * this routine with the same iclog.  Changing contents of iclog can there-
 * fore be done without grabbing the state machine lock.  Updating the global
 * log will require grabbing the lock though.
 *
 * The entire log manager uses a logical block numbering scheme.  Only
 * xlog_write_iclog knows about the fact that the log may not start with
 * block zero on a given device.
 */
STATIC void
xlog_sync(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	struct xlog_ticket	*ticket)
{
	unsigned int		count;		/* byte count of bwrite */
	unsigned int		roundoff;       /* roundoff to BB or stripe */
	uint64_t		bno;
	unsigned int		size;

	ASSERT(atomic_read(&iclog->ic_refcnt) == 0);
	trace_xlog_iclog_sync(iclog, _RET_IP_);

	count = xlog_calc_iclog_size(log, iclog, &roundoff);

	/*
	 * If we have a ticket, account for the roundoff via the ticket
	 * reservation to avoid touching the hot grant heads needlessly.
	 * Otherwise, we have to move grant heads directly.
	 */
	if (ticket) {
		ticket->t_curr_res -= roundoff;
	} else {
		xlog_grant_add_space(&log->l_reserve_head, roundoff);
		xlog_grant_add_space(&log->l_write_head, roundoff);
	}

	/* put cycle number in every block */
	xlog_pack_data(log, iclog, roundoff);

	/* real byte length */
	size = iclog->ic_offset;
	if (xfs_has_logv2(log->l_mp))
		size += roundoff;
	iclog->ic_header->h_len = cpu_to_be32(size);

	XFS_STATS_INC(log->l_mp, xs_log_writes);
	XFS_STATS_ADD(log->l_mp, xs_log_blocks, BTOBB(count));

	bno = BLOCK_LSN(be64_to_cpu(iclog->ic_header->h_lsn));

	/* Do we need to split this write into 2 parts? */
	if (bno + BTOBB(count) > log->l_logBBsize)
		xlog_split_iclog(log, iclog->ic_header, bno, count);

	/* calculcate the checksum */
	iclog->ic_header->h_crc = xlog_cksum(log, iclog->ic_header,
			iclog->ic_datap, XLOG_REC_SIZE, size);
	/*
	 * Intentionally corrupt the log record CRC based on the error injection
	 * frequency, if defined. This facilitates testing log recovery in the
	 * event of torn writes. Hence, set the IOABORT state to abort the log
	 * write on I/O completion and shutdown the fs. The subsequent mount
	 * detects the bad CRC and attempts to recover.
	 */
#ifdef DEBUG
	if (XFS_TEST_ERROR(log->l_mp, XFS_ERRTAG_LOG_BAD_CRC)) {
		iclog->ic_header->h_crc &= cpu_to_le32(0xAAAAAAAA);
		iclog->ic_fail_crc = true;
		xfs_warn(log->l_mp,
	"Intentionally corrupted log record at LSN 0x%llx. Shutdown imminent.",
			 be64_to_cpu(iclog->ic_header->h_lsn));
	}
#endif
	xlog_verify_iclog(log, iclog, count);
	xlog_write_iclog(log, iclog, bno, count);
}

/*
 * Deallocate a log structure
 */
STATIC void
xlog_dealloc_log(
	struct xlog		*log)
{
	struct xlog_in_core	*iclog, *next_iclog;
	int			i;

	/*
	 * Destroy the CIL after waiting for iclog IO completion because an
	 * iclog EIO error will try to shut down the log, which accesses the
	 * CIL to wake up the waiters.
	 */
	xlog_cil_destroy(log);

	iclog = log->l_iclog;
	for (i = 0; i < log->l_iclog_bufs; i++) {
		next_iclog = iclog->ic_next;
		kvfree(iclog->ic_header);
		kfree(iclog);
		iclog = next_iclog;
	}

	/* backstop: a recovery that errored out (or a mount-cancel
	 * path) can reach teardown without passing a finish site; emit
	 * whatever was counted rather than leaking it silently. */
	mxfs_shadow_eval_finish(log);

	/*
	 * MXFS: a foreign-replay shadow xlog shares l_mp with the live
	 * mount but never owned mp->m_log — don't NULL the live pointer.
	 */
	if (log->l_mp->m_log == log)
		log->l_mp->m_log = NULL;
	destroy_workqueue(log->l_ioend_workqueue);
	/* (#94): masked-compare baseline cached by the counter-only
	 * SB clean-skip classifier (foreign shadow logs and adopted mount
	 * logs alike). */
	kfree(log->l_mxfs_sb_baseline);
	/* pass-1 clean-release marker table (untrusted replay) */
	mxfs_relmark_tbl_free(log);
	/* intent/done census (untrusted replay) */
	mxfs_icensus_free(log);
	/* (D-527): foreign-slice snapshot — every exit path lands here */
	kvfree(log->l_mxfs_slice_snap);
	kfree(log);
}

/*
 * Update counters atomically now that memcpy is done.
 */
static inline void
xlog_state_finish_copy(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	int			record_cnt,
	int			copy_bytes)
{
	lockdep_assert_held(&log->l_icloglock);

	be32_add_cpu(&iclog->ic_header->h_num_logops, record_cnt);
	iclog->ic_offset += copy_bytes;
}

/*
 * print out info relating to regions written which consume
 * the reservation
 */
void
xlog_print_tic_res(
	struct xfs_mount	*mp,
	struct xlog_ticket	*ticket)
{
	xfs_warn(mp, "ticket reservation summary:");
	xfs_warn(mp, "  unit res    = %d bytes", ticket->t_unit_res);
	xfs_warn(mp, "  current res = %d bytes", ticket->t_curr_res);
	xfs_warn(mp, "  original count  = %d", ticket->t_ocnt);
	xfs_warn(mp, "  remaining count = %d", ticket->t_cnt);
}

/*
 * Print a summary of the transaction.
 */
void
xlog_print_trans(
	struct xfs_trans	*tp)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_log_item	*lip;

	/* dump core transaction and ticket info */
	xfs_warn(mp, "transaction summary:");
	xfs_warn(mp, "  log res   = %d", tp->t_log_res);
	xfs_warn(mp, "  log count = %d", tp->t_log_count);
	xfs_warn(mp, "  flags     = 0x%x", tp->t_flags);

	xlog_print_tic_res(mp, tp->t_ticket);

	/* dump each log item */
	list_for_each_entry(lip, &tp->t_items, li_trans) {
		struct xfs_log_vec	*lv = lip->li_lv;
		struct xfs_log_iovec	*vec;
		int			i;

		xfs_warn(mp, "log item: ");
		xfs_warn(mp, "  type	= 0x%x", lip->li_type);
		xfs_warn(mp, "  flags	= 0x%lx", lip->li_flags);
		if (!lv)
			continue;
		xfs_warn(mp, "  niovecs	= %d", lv->lv_niovecs);
		xfs_warn(mp, "  alloc_size = %d", lv->lv_alloc_size);
		xfs_warn(mp, "  bytes	= %d", lv->lv_bytes);
		xfs_warn(mp, "  buf used= %d", lv->lv_buf_used);

		/* dump each iovec for the log item */
		vec = lv->lv_iovecp;
		for (i = 0; i < lv->lv_niovecs; i++) {
			int dumplen = min(vec->i_len, 32);

			xfs_warn(mp, "  iovec[%d]", i);
			xfs_warn(mp, "    type	= 0x%x", vec->i_type);
			xfs_warn(mp, "    len	= %d", vec->i_len);
			xfs_warn(mp, "    first %d bytes of iovec[%d]:", dumplen, i);
			xfs_hex_dump(vec->i_addr, dumplen);

			vec++;
		}
	}
}

static inline uint32_t xlog_write_space_left(struct xlog_write_data *data)
{
	return data->iclog->ic_size - data->log_offset;
}

static void *
xlog_write_space_advance(
	struct xlog_write_data	*data,
	unsigned int		len)
{
	void			*p = data->iclog->ic_datap + data->log_offset;

	ASSERT(xlog_write_space_left(data) >= len);
	ASSERT(data->log_offset % sizeof(int32_t) == 0);
	ASSERT(len % sizeof(int32_t) == 0);

	data->data_cnt += len;
	data->log_offset += len;
	data->bytes_left -= len;
	return p;
}

static inline void
xlog_write_iovec(
	struct xlog_write_data	*data,
	void			*buf,
	uint32_t		buf_len)
{
	memcpy(xlog_write_space_advance(data, buf_len), buf, buf_len);
	data->record_cnt++;
}

/*
 * Write log vectors into a single iclog which is guaranteed by the caller
 * to have enough space to write the entire log vector into.
 */
static void
xlog_write_full(
	struct xfs_log_vec	*lv,
	struct xlog_write_data	*data)
{
	int			index;

	ASSERT(data->bytes_left <= xlog_write_space_left(data) ||
		data->iclog->ic_state == XLOG_STATE_WANT_SYNC);

	/*
	 * Ordered log vectors have no regions to write so this
	 * loop will naturally skip them.
	 */
	for (index = 0; index < lv->lv_niovecs; index++) {
		struct xfs_log_iovec	*reg = &lv->lv_iovecp[index];
		struct xlog_op_header	*ophdr = reg->i_addr;

		ophdr->oh_tid = cpu_to_be32(data->ticket->t_tid);
		xlog_write_iovec(data, reg->i_addr, reg->i_len);
	}
}

static int
xlog_write_get_more_iclog_space(
	struct xlog_write_data	*data)
{
	struct xlog		*log = data->iclog->ic_log;
	int			error;

	spin_lock(&log->l_icloglock);
	ASSERT(data->iclog->ic_state == XLOG_STATE_WANT_SYNC);
	xlog_state_finish_copy(log, data->iclog, data->record_cnt,
			data->data_cnt);
	error = xlog_state_release_iclog(log, data->iclog, data->ticket);
	spin_unlock(&log->l_icloglock);
	if (error)
		return error;

	error = xlog_state_get_iclog_space(log, data);
	if (error)
		return error;
	data->record_cnt = 0;
	data->data_cnt = 0;
	return 0;
}

/*
 * Write log vectors into a single iclog which is smaller than the current chain
 * length. We write until we cannot fit a full record into the remaining space
 * and then stop. We return the log vector that is to be written that cannot
 * wholly fit in the iclog.
 */
static int
xlog_write_partial(
	struct xfs_log_vec	*lv,
	struct xlog_write_data	*data)
{
	struct xlog_op_header	*ophdr;
	int			index = 0;
	uint32_t		rlen;
	int			error;

	/* walk the logvec, copying until we run out of space in the iclog */
	for (index = 0; index < lv->lv_niovecs; index++) {
		struct xfs_log_iovec	*reg = &lv->lv_iovecp[index];
		uint32_t		reg_offset = 0;

		/*
		 * The first region of a continuation must have a non-zero
		 * length otherwise log recovery will just skip over it and
		 * start recovering from the next opheader it finds. Because we
		 * mark the next opheader as a continuation, recovery will then
		 * incorrectly add the continuation to the previous region and
		 * that breaks stuff.
		 *
		 * Hence if there isn't space for region data after the
		 * opheader, then we need to start afresh with a new iclog.
		 */
		if (xlog_write_space_left(data) <=
					sizeof(struct xlog_op_header)) {
			error = xlog_write_get_more_iclog_space(data);
			if (error)
				return error;
		}

		ophdr = reg->i_addr;
		rlen = min_t(uint32_t, reg->i_len, xlog_write_space_left(data));

		ophdr->oh_tid = cpu_to_be32(data->ticket->t_tid);
		ophdr->oh_len = cpu_to_be32(rlen - sizeof(struct xlog_op_header));
		if (rlen != reg->i_len)
			ophdr->oh_flags |= XLOG_CONTINUE_TRANS;

		xlog_write_iovec(data, reg->i_addr, rlen);

		/* If we wrote the whole region, move to the next. */
		if (rlen == reg->i_len)
			continue;

		/*
		 * We now have a partially written iovec, but it can span
		 * multiple iclogs so we loop here. First we release the iclog
		 * we currently have, then we get a new iclog and add a new
		 * opheader. Then we continue copying from where we were until
		 * we either complete the iovec or fill the iclog. If we
		 * complete the iovec, then we increment the index and go right
		 * back to the top of the outer loop. if we fill the iclog, we
		 * run the inner loop again.
		 *
		 * This is complicated by the tail of a region using all the
		 * space in an iclog and hence requiring us to release the iclog
		 * and get a new one before returning to the outer loop. We must
		 * always guarantee that we exit this inner loop with at least
		 * space for log transaction opheaders left in the current
		 * iclog, hence we cannot just terminate the loop at the end
		 * of the of the continuation. So we loop while there is no
		 * space left in the current iclog, and check for the end of the
		 * continuation after getting a new iclog.
		 */
		do {
			/*
			 * Ensure we include the continuation opheader in the
			 * space we need in the new iclog by adding that size
			 * to the length we require. This continuation opheader
			 * needs to be accounted to the ticket as the space it
			 * consumes hasn't been accounted to the lv we are
			 * writing.
			 */
			data->bytes_left += sizeof(struct xlog_op_header);
			error = xlog_write_get_more_iclog_space(data);
			if (error)
				return error;

			ophdr = xlog_write_space_advance(data,
					sizeof(struct xlog_op_header));
			ophdr->oh_tid = cpu_to_be32(data->ticket->t_tid);
			ophdr->oh_clientid = XFS_TRANSACTION;
			ophdr->oh_res2 = 0;
			ophdr->oh_flags = XLOG_WAS_CONT_TRANS;

			data->ticket->t_curr_res -=
				sizeof(struct xlog_op_header);

			/*
			 * If rlen fits in the iclog, then end the region
			 * continuation. Otherwise we're going around again.
			 */
			reg_offset += rlen;
			rlen = reg->i_len - reg_offset;
			if (rlen <= xlog_write_space_left(data))
				ophdr->oh_flags |= XLOG_END_TRANS;
			else
				ophdr->oh_flags |= XLOG_CONTINUE_TRANS;

			rlen = min_t(uint32_t, rlen,
					xlog_write_space_left(data));
			ophdr->oh_len = cpu_to_be32(rlen);

			xlog_write_iovec(data, reg->i_addr + reg_offset, rlen);
		} while (ophdr->oh_flags & XLOG_CONTINUE_TRANS);
	}

	return 0;
}

/*
 * Write some region out to in-core log
 *
 * This will be called when writing externally provided regions or when
 * writing out a commit record for a given transaction.
 *
 * General algorithm:
 *	1. Find total length of this write.  This may include adding to the
 *		lengths passed in.
 *	2. Check whether we violate the tickets reservation.
 *	3. While writing to this iclog
 *	    A. Reserve as much space in this iclog as can get
 *	    B. If this is first write, save away start lsn
 *	    C. While writing this region:
 *		1. If first write of transaction, write start record
 *		2. Write log operation header (header per region)
 *		3. Find out if we can fit entire region into this iclog
 *		4. Potentially, verify destination memcpy ptr
 *		5. Memcpy (partial) region
 *		6. If partial copy, release iclog; otherwise, continue
 *			copying more regions into current iclog
 *	4. Mark want sync bit (in simulation mode)
 *	5. Release iclog for potential flush to on-disk log.
 *
 * ERRORS:
 * 1.	Panic if reservation is overrun.  This should never happen since
 *	reservation amounts are generated internal to the filesystem.
 * NOTES:
 * 1. Tickets are single threaded data structures.
 * 2. The XLOG_END_TRANS & XLOG_CONTINUE_TRANS flags are passed down to the
 *	syncing routine.  When a single log_write region needs to span
 *	multiple in-core logs, the XLOG_CONTINUE_TRANS bit should be set
 *	on all log operation writes which don't contain the end of the
 *	region.  The XLOG_END_TRANS bit is used for the in-core log
 *	operation which contains the end of the continued log_write region.
 * 3. When xlog_state_get_iclog_space() grabs the rest of the current iclog,
 *	we don't really know exactly how much space will be used.  As a result,
 *	we don't update ic_offset until the end when we know exactly how many
 *	bytes have been written out.
 */
int
xlog_write(
	struct xlog		*log,
	struct xfs_cil_ctx	*ctx,
	struct list_head	*lv_chain,
	struct xlog_ticket	*ticket,
	uint32_t		len)

{
	struct xfs_log_vec	*lv;
	struct xlog_write_data	data = {
		.ticket		= ticket,
		.bytes_left	= len,
	};
	int			error;

	if (ticket->t_curr_res < 0) {
		xfs_alert_tag(log->l_mp, XFS_PTAG_LOGRES,
		     "ctx ticket reservation ran out. Need to up reservation");
		xlog_print_tic_res(log->l_mp, ticket);
		xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR);
	}

	error = xlog_state_get_iclog_space(log, &data);
	if (error)
		return error;

	ASSERT(xlog_write_space_left(&data) > 0);

	/*
	 * If we have a context pointer, pass it the first iclog we are
	 * writing to so it can record state needed for iclog write
	 * ordering.
	 */
	if (ctx)
		xlog_cil_set_ctx_write_state(ctx, data.iclog);

	list_for_each_entry(lv, lv_chain, lv_list) {
		/*
		 * If the entire log vec does not fit in the iclog, punt it to
		 * the partial copy loop which can handle this case.
		 */
		if (lv->lv_niovecs &&
		    lv->lv_bytes > xlog_write_space_left(&data)) {
			error = xlog_write_partial(lv, &data);
			if (error) {
				/*
				 * We have no iclog to release, so just return
				 * the error immediately.
				 */
				return error;
			}
		} else {
			xlog_write_full(lv, &data);
		}
	}
	ASSERT(data.bytes_left == 0);

	/*
	 * We've already been guaranteed that the last writes will fit inside
	 * the current iclog, and hence it will already have the space used by
	 * those writes accounted to it. Hence we do not need to update the
	 * iclog with the number of bytes written here.
	 */
	spin_lock(&log->l_icloglock);
	xlog_state_finish_copy(log, data.iclog, data.record_cnt, 0);
	error = xlog_state_release_iclog(log, data.iclog, ticket);
	spin_unlock(&log->l_icloglock);

	return error;
}

static void
xlog_state_activate_iclog(
	struct xlog_in_core	*iclog,
	int			*iclogs_changed)
{
	ASSERT(list_empty_careful(&iclog->ic_callbacks));
	trace_xlog_iclog_activate(iclog, _RET_IP_);

	/*
	 * If the number of ops in this iclog indicate it just contains the
	 * dummy transaction, we can change state into IDLE (the second time
	 * around). Otherwise we should change the state into NEED a dummy.
	 * We don't need to cover the dummy.
	 */
	if (*iclogs_changed == 0 &&
	    iclog->ic_header->h_num_logops == cpu_to_be32(XLOG_COVER_OPS)) {
		*iclogs_changed = 1;
	} else {
		/*
		 * We have two dirty iclogs so start over.  This could also be
		 * num of ops indicating this is not the dummy going out.
		 */
		*iclogs_changed = 2;
	}

	iclog->ic_state	= XLOG_STATE_ACTIVE;
	iclog->ic_offset = 0;
	iclog->ic_header->h_num_logops = 0;
	memset(iclog->ic_header->h_cycle_data, 0,
		sizeof(iclog->ic_header->h_cycle_data));
	iclog->ic_header->h_lsn = 0;
	iclog->ic_header->h_tail_lsn = 0;
}

/*
 * Loop through all iclogs and mark all iclogs currently marked DIRTY as
 * ACTIVE after iclog I/O has completed.
 */
static void
xlog_state_activate_iclogs(
	struct xlog		*log,
	int			*iclogs_changed)
{
	struct xlog_in_core	*iclog = log->l_iclog;

	do {
		if (iclog->ic_state == XLOG_STATE_DIRTY)
			xlog_state_activate_iclog(iclog, iclogs_changed);
		/*
		 * The ordering of marking iclogs ACTIVE must be maintained, so
		 * an iclog doesn't become ACTIVE beyond one that is SYNCING.
		 */
		else if (iclog->ic_state != XLOG_STATE_ACTIVE)
			break;
	} while ((iclog = iclog->ic_next) != log->l_iclog);
}

static int
xlog_covered_state(
	int			prev_state,
	int			iclogs_changed)
{
	/*
	 * We go to NEED for any non-covering writes. We go to NEED2 if we just
	 * wrote the first covering record (DONE). We go to IDLE if we just
	 * wrote the second covering record (DONE2) and remain in IDLE until a
	 * non-covering write occurs.
	 */
	switch (prev_state) {
	case XLOG_STATE_COVER_IDLE:
		if (iclogs_changed == 1)
			return XLOG_STATE_COVER_IDLE;
		fallthrough;
	case XLOG_STATE_COVER_NEED:
	case XLOG_STATE_COVER_NEED2:
		break;
	case XLOG_STATE_COVER_DONE:
		if (iclogs_changed == 1)
			return XLOG_STATE_COVER_NEED2;
		break;
	case XLOG_STATE_COVER_DONE2:
		if (iclogs_changed == 1)
			return XLOG_STATE_COVER_IDLE;
		break;
	default:
		ASSERT(0);
	}

	return XLOG_STATE_COVER_NEED;
}

STATIC void
xlog_state_clean_iclog(
	struct xlog		*log,
	struct xlog_in_core	*dirty_iclog)
{
	int			iclogs_changed = 0;

	trace_xlog_iclog_clean(dirty_iclog, _RET_IP_);

	dirty_iclog->ic_state = XLOG_STATE_DIRTY;

	xlog_state_activate_iclogs(log, &iclogs_changed);
	wake_up_all(&dirty_iclog->ic_force_wait);

	if (iclogs_changed) {
		log->l_covered_state = xlog_covered_state(log->l_covered_state,
				iclogs_changed);
	}
}

STATIC xfs_lsn_t
xlog_get_lowest_lsn(
	struct xlog		*log)
{
	struct xlog_in_core	*iclog = log->l_iclog;
	xfs_lsn_t		lowest_lsn = 0, lsn;

	do {
		if (iclog->ic_state == XLOG_STATE_ACTIVE ||
		    iclog->ic_state == XLOG_STATE_DIRTY)
			continue;

		lsn = be64_to_cpu(iclog->ic_header->h_lsn);
		if ((lsn && !lowest_lsn) || XFS_LSN_CMP(lsn, lowest_lsn) < 0)
			lowest_lsn = lsn;
	} while ((iclog = iclog->ic_next) != log->l_iclog);

	return lowest_lsn;
}

/*
 * Return true if we need to stop processing, false to continue to the next
 * iclog. The caller will need to run callbacks if the iclog is returned in the
 * XLOG_STATE_CALLBACK state.
 */
static bool
xlog_state_iodone_process_iclog(
	struct xlog		*log,
	struct xlog_in_core	*iclog)
{
	xfs_lsn_t		lowest_lsn;
	xfs_lsn_t		header_lsn;

	switch (iclog->ic_state) {
	case XLOG_STATE_ACTIVE:
	case XLOG_STATE_DIRTY:
		/*
		 * Skip all iclogs in the ACTIVE & DIRTY states:
		 */
		return false;
	case XLOG_STATE_DONE_SYNC:
		/*
		 * Now that we have an iclog that is in the DONE_SYNC state, do
		 * one more check here to see if we have chased our tail around.
		 * If this is not the lowest lsn iclog, then we will leave it
		 * for another completion to process.
		 */
		header_lsn = be64_to_cpu(iclog->ic_header->h_lsn);
		lowest_lsn = xlog_get_lowest_lsn(log);
		if (lowest_lsn && XFS_LSN_CMP(lowest_lsn, header_lsn) < 0)
			return false;
		/*
		 * If there are no callbacks on this iclog, we can mark it clean
		 * immediately and return. Otherwise we need to run the
		 * callbacks.
		 */
		if (list_empty(&iclog->ic_callbacks)) {
			xlog_state_clean_iclog(log, iclog);
			return false;
		}
		trace_xlog_iclog_callback(iclog, _RET_IP_);
		iclog->ic_state = XLOG_STATE_CALLBACK;
		return false;
	default:
		/*
		 * Can only perform callbacks in order.  Since this iclog is not
		 * in the DONE_SYNC state, we skip the rest and just try to
		 * clean up.
		 */
		return true;
	}
}

/*
 * Loop over all the iclogs, running attached callbacks on them. Return true if
 * we ran any callbacks, indicating that we dropped the icloglock. We don't need
 * to handle transient shutdown state here at all because
 * xlog_state_shutdown_callbacks() will be run to do the necessary shutdown
 * cleanup of the callbacks.
 */
static bool
xlog_state_do_iclog_callbacks(
	struct xlog		*log)
		__releases(&log->l_icloglock)
		__acquires(&log->l_icloglock)
{
	struct xlog_in_core	*first_iclog = log->l_iclog;
	struct xlog_in_core	*iclog = first_iclog;
	bool			ran_callback = false;

	do {
		LIST_HEAD(cb_list);

		if (xlog_state_iodone_process_iclog(log, iclog))
			break;
		if (iclog->ic_state != XLOG_STATE_CALLBACK) {
			iclog = iclog->ic_next;
			continue;
		}
		list_splice_init(&iclog->ic_callbacks, &cb_list);
		spin_unlock(&log->l_icloglock);

		trace_xlog_iclog_callbacks_start(iclog, _RET_IP_);
		xlog_cil_process_committed(&cb_list);
		trace_xlog_iclog_callbacks_done(iclog, _RET_IP_);
		ran_callback = true;

		spin_lock(&log->l_icloglock);
		xlog_state_clean_iclog(log, iclog);
		iclog = iclog->ic_next;
	} while (iclog != first_iclog);

	return ran_callback;
}


/*
 * Loop running iclog completion callbacks until there are no more iclogs in a
 * state that can run callbacks.
 */
STATIC void
xlog_state_do_callback(
	struct xlog		*log)
{
	int			flushcnt = 0;
	int			repeats = 0;

	spin_lock(&log->l_icloglock);
	while (xlog_state_do_iclog_callbacks(log)) {
		if (xlog_is_shutdown(log))
			break;

		if (++repeats > 5000) {
			flushcnt += repeats;
			repeats = 0;
			xfs_warn(log->l_mp,
				"%s: possible infinite loop (%d iterations)",
				__func__, flushcnt);
		}
	}

	if (log->l_iclog->ic_state == XLOG_STATE_ACTIVE)
		wake_up_all(&log->l_flush_wait);

	spin_unlock(&log->l_icloglock);
}


/*
 * Finish transitioning this iclog to the dirty state.
 *
 * Callbacks could take time, so they are done outside the scope of the
 * global state machine log lock.
 */
STATIC void
xlog_state_done_syncing(
	struct xlog_in_core	*iclog)
{
	struct xlog		*log = iclog->ic_log;

	spin_lock(&log->l_icloglock);
	ASSERT(atomic_read(&iclog->ic_refcnt) == 0);
	trace_xlog_iclog_sync_done(iclog, _RET_IP_);

	/*
	 * If we got an error, either on the first buffer, or in the case of
	 * split log writes, on the second, we shut down the file system and
	 * no iclogs should ever be attempted to be written to disk again.
	 */
	if (!xlog_is_shutdown(log)) {
		ASSERT(iclog->ic_state == XLOG_STATE_SYNCING);
		iclog->ic_state = XLOG_STATE_DONE_SYNC;
	}

	/*
	 * Someone could be sleeping prior to writing out the next
	 * iclog buffer, we wake them all, one will get to do the
	 * I/O, the others get to wait for the result.
	 */
	wake_up_all(&iclog->ic_write_wait);
	spin_unlock(&log->l_icloglock);
	xlog_state_do_callback(log);
}

/*
 * If the head of the in-core log ring is not (ACTIVE or DIRTY), then we must
 * sleep.  We wait on the flush queue on the head iclog as that should be
 * the first iclog to complete flushing. Hence if all iclogs are syncing,
 * we will wait here and all new writes will sleep until a sync completes.
 *
 * The in-core logs are used in a circular fashion. They are not used
 * out-of-order even when an iclog past the head is free.
 *
 * return:
 *	* log_offset where xlog_write() can start writing into the in-core
 *		log's data space.
 *	* in-core log pointer to which xlog_write() should write.
 *	* boolean indicating this is a continued write to an in-core log.
 *		If this is the last write, then the in-core log's offset field
 *		needs to be incremented, depending on the amount of data which
 *		is copied.
 */
STATIC int
xlog_state_get_iclog_space(
	struct xlog		*log,
	struct xlog_write_data	*data)
{
	int			log_offset;
	struct xlog_rec_header	*head;
	struct xlog_in_core	*iclog;

restart:
	spin_lock(&log->l_icloglock);
	if (xlog_is_shutdown(log)) {
		spin_unlock(&log->l_icloglock);
		return -EIO;
	}

	iclog = log->l_iclog;
	if (iclog->ic_state != XLOG_STATE_ACTIVE) {
		XFS_STATS_INC(log->l_mp, xs_log_noiclogs);

		/* Wait for log writes to have flushed */
		xlog_wait(&log->l_flush_wait, &log->l_icloglock);
		goto restart;
	}

	head = iclog->ic_header;

	atomic_inc(&iclog->ic_refcnt);	/* prevents sync */
	log_offset = iclog->ic_offset;

	trace_xlog_iclog_get_space(iclog, _RET_IP_);

	/* On the 1st write to an iclog, figure out lsn.  This works
	 * if iclogs marked XLOG_STATE_WANT_SYNC always write out what they are
	 * committing to.  If the offset is set, that's how many blocks
	 * must be written.
	 */
	if (log_offset == 0) {
		data->ticket->t_curr_res -= log->l_iclog_hsize;
		head->h_cycle = cpu_to_be32(log->l_curr_cycle);
		head->h_lsn = cpu_to_be64(
			xlog_assign_lsn(log->l_curr_cycle, log->l_curr_block));
		ASSERT(log->l_curr_block >= 0);
	}

	/* If there is enough room to write everything, then do it.  Otherwise,
	 * claim the rest of the region and make sure the XLOG_STATE_WANT_SYNC
	 * bit is on, so this will get flushed out.  Don't update ic_offset
	 * until you know exactly how many bytes get copied.  Therefore, wait
	 * until later to update ic_offset.
	 *
	 * xlog_write() algorithm assumes that at least 2 xlog_op_header's
	 * can fit into remaining data section.
	 */
	if (iclog->ic_size - iclog->ic_offset <
	    2 * sizeof(struct xlog_op_header)) {
		int		error = 0;

		xlog_state_switch_iclogs(log, iclog, iclog->ic_size);

		/*
		 * If we are the only one writing to this iclog, sync it to
		 * disk.  We need to do an atomic compare and decrement here to
		 * avoid racing with concurrent atomic_dec_and_lock() calls in
		 * xlog_state_release_iclog() when there is more than one
		 * reference to the iclog.
		 */
		if (!atomic_add_unless(&iclog->ic_refcnt, -1, 1))
			error = xlog_state_release_iclog(log, iclog,
					data->ticket);
		spin_unlock(&log->l_icloglock);
		if (error)
			return error;
		goto restart;
	}

	/* Do we have enough room to write the full amount in the remainder
	 * of this iclog?  Or must we continue a write on the next iclog and
	 * mark this iclog as completely taken?  In the case where we switch
	 * iclogs (to mark it taken), this particular iclog will release/sync
	 * to disk in xlog_write().
	 */
	if (data->bytes_left <= iclog->ic_size - iclog->ic_offset)
		iclog->ic_offset += data->bytes_left;
	else
		xlog_state_switch_iclogs(log, iclog, iclog->ic_size);
	data->iclog = iclog;

	ASSERT(iclog->ic_offset <= iclog->ic_size);
	spin_unlock(&log->l_icloglock);

	data->log_offset = log_offset;
	return 0;
}

/*
 * The first cnt-1 times a ticket goes through here we don't need to move the
 * grant write head because the permanent reservation has reserved cnt times the
 * unit amount.  Release part of current permanent unit reservation and reset
 * current reservation to be one units worth.  Also move grant reservation head
 * forward.
 */
void
xfs_log_ticket_regrant(
	struct xlog		*log,
	struct xlog_ticket	*ticket)
{
	trace_xfs_log_ticket_regrant(log, ticket);

	if (ticket->t_cnt > 0)
		ticket->t_cnt--;

	xlog_grant_sub_space(&log->l_reserve_head, ticket->t_curr_res);
	xlog_grant_sub_space(&log->l_write_head, ticket->t_curr_res);
	ticket->t_curr_res = ticket->t_unit_res;

	trace_xfs_log_ticket_regrant_sub(log, ticket);

	/* just return if we still have some of the pre-reserved space */
	if (!ticket->t_cnt) {
		xlog_grant_add_space(&log->l_reserve_head, ticket->t_unit_res);
		trace_xfs_log_ticket_regrant_exit(log, ticket);
	}

	xfs_log_ticket_put(ticket);
}

/*
 * Give back the space left from a reservation.
 *
 * All the information we need to make a correct determination of space left
 * is present.  For non-permanent reservations, things are quite easy.  The
 * count should have been decremented to zero.  We only need to deal with the
 * space remaining in the current reservation part of the ticket.  If the
 * ticket contains a permanent reservation, there may be left over space which
 * needs to be released.  A count of N means that N-1 refills of the current
 * reservation can be done before we need to ask for more space.  The first
 * one goes to fill up the first current reservation.  Once we run out of
 * space, the count will stay at zero and the only space remaining will be
 * in the current reservation field.
 */
void
xfs_log_ticket_ungrant(
	struct xlog		*log,
	struct xlog_ticket	*ticket)
{
	int			bytes;

	trace_xfs_log_ticket_ungrant(log, ticket);

	if (ticket->t_cnt > 0)
		ticket->t_cnt--;

	trace_xfs_log_ticket_ungrant_sub(log, ticket);

	/*
	 * If this is a permanent reservation ticket, we may be able to free
	 * up more space based on the remaining count.
	 */
	bytes = ticket->t_curr_res;
	if (ticket->t_cnt > 0) {
		ASSERT(ticket->t_flags & XLOG_TIC_PERM_RESERV);
		bytes += ticket->t_unit_res*ticket->t_cnt;
	}

	xlog_grant_sub_space(&log->l_reserve_head, bytes);
	xlog_grant_sub_space(&log->l_write_head, bytes);

	trace_xfs_log_ticket_ungrant_exit(log, ticket);

	xfs_log_space_wake(log->l_mp);
	xfs_log_ticket_put(ticket);
}

/*
 * This routine will mark the current iclog in the ring as WANT_SYNC and move
 * the current iclog pointer to the next iclog in the ring.
 */
void
xlog_state_switch_iclogs(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	int			eventual_size)
{
	ASSERT(iclog->ic_state == XLOG_STATE_ACTIVE);
	assert_spin_locked(&log->l_icloglock);
	trace_xlog_iclog_switch(iclog, _RET_IP_);

	if (!eventual_size)
		eventual_size = iclog->ic_offset;
	iclog->ic_state = XLOG_STATE_WANT_SYNC;
	iclog->ic_header->h_prev_block = cpu_to_be32(log->l_prev_block);
	log->l_prev_block = log->l_curr_block;
	log->l_prev_cycle = log->l_curr_cycle;

	/* roll log?: ic_offset changed later */
	log->l_curr_block += BTOBB(eventual_size)+BTOBB(log->l_iclog_hsize);

	/* Round up to next log-sunit */
	if (log->l_iclog_roundoff > BBSIZE) {
		uint32_t sunit_bb = BTOBB(log->l_iclog_roundoff);
		log->l_curr_block = roundup(log->l_curr_block, sunit_bb);
	}

	if (log->l_curr_block >= log->l_logBBsize) {
		/*
		 * Rewind the current block before the cycle is bumped to make
		 * sure that the combined LSN never transiently moves forward
		 * when the log wraps to the next cycle. This is to support the
		 * unlocked sample of these fields from xlog_valid_lsn(). Most
		 * other cases should acquire l_icloglock.
		 */
		log->l_curr_block -= log->l_logBBsize;
		ASSERT(log->l_curr_block >= 0);
		smp_wmb();
		log->l_curr_cycle++;
		if (log->l_curr_cycle == XLOG_HEADER_MAGIC_NUM)
			log->l_curr_cycle++;
	}
	ASSERT(iclog == log->l_iclog);
	log->l_iclog = iclog->ic_next;
}

/*
 * Force the iclog to disk and check if the iclog has been completed before
 * xlog_force_iclog() returns. This can happen on synchronous (e.g.
 * pmem) or fast async storage because we drop the icloglock to issue the IO.
 * If completion has already occurred, tell the caller so that it can avoid an
 * unnecessary wait on the iclog.
 */
static int
xlog_force_and_check_iclog(
	struct xlog_in_core	*iclog,
	bool			*completed)
{
	xfs_lsn_t		lsn = be64_to_cpu(iclog->ic_header->h_lsn);
	int			error;

	*completed = false;
	error = xlog_force_iclog(iclog);
	if (error)
		return error;

	/*
	 * If the iclog has already been completed and reused the header LSN
	 * will have been rewritten by completion
	 */
	if (be64_to_cpu(iclog->ic_header->h_lsn) != lsn)
		*completed = true;
	return 0;
}

/*
 * Write out all data in the in-core log as of this exact moment in time.
 *
 * Data may be written to the in-core log during this call.  However,
 * we don't guarantee this data will be written out.  A change from past
 * implementation means this routine will *not* write out zero length LRs.
 *
 * Basically, we try and perform an intelligent scan of the in-core logs.
 * If we determine there is no flushable data, we just return.  There is no
 * flushable data if:
 *
 *	1. the current iclog is active and has no data; the previous iclog
 *		is in the active or dirty state.
 *	2. the current iclog is dirty, and the previous iclog is in the
 *		active or dirty state.
 *
 * We may sleep if:
 *
 *	1. the current iclog is not in the active nor dirty state.
 *	2. the current iclog dirty, and the previous iclog is not in the
 *		active nor dirty state.
 *	3. the current iclog is active, and there is another thread writing
 *		to this particular iclog.
 *	4. a) the current iclog is active and has no other writers
 *	   b) when we return from flushing out this iclog, it is still
 *		not in the active nor dirty state.
 */
int
xfs_log_force(
	struct xfs_mount	*mp,
	uint			flags)
{
	struct xlog		*log = mp->m_log;
	struct xlog_in_core	*iclog;

	XFS_STATS_INC(mp, xs_log_force);
	trace_xfs_log_force(mp, 0, _RET_IP_);

	xlog_cil_force(log);

	spin_lock(&log->l_icloglock);
	if (xlog_is_shutdown(log))
		goto out_error;

	iclog = log->l_iclog;
	trace_xlog_iclog_force(iclog, _RET_IP_);

	if (iclog->ic_state == XLOG_STATE_DIRTY ||
	    (iclog->ic_state == XLOG_STATE_ACTIVE &&
	     atomic_read(&iclog->ic_refcnt) == 0 && iclog->ic_offset == 0)) {
		/*
		 * If the head is dirty or (active and empty), then we need to
		 * look at the previous iclog.
		 *
		 * If the previous iclog is active or dirty we are done.  There
		 * is nothing to sync out. Otherwise, we attach ourselves to the
		 * previous iclog and go to sleep.
		 */
		iclog = iclog->ic_prev;
	} else if (iclog->ic_state == XLOG_STATE_ACTIVE) {
		if (atomic_read(&iclog->ic_refcnt) == 0) {
			/* We have exclusive access to this iclog. */
			bool	completed;

			if (xlog_force_and_check_iclog(iclog, &completed))
				goto out_error;

			if (completed)
				goto out_unlock;
		} else {
			/*
			 * Someone else is still writing to this iclog, so we
			 * need to ensure that when they release the iclog it
			 * gets synced immediately as we may be waiting on it.
			 */
			xlog_state_switch_iclogs(log, iclog, 0);
		}
	}

	/*
	 * The iclog we are about to wait on may contain the checkpoint pushed
	 * by the above xlog_cil_force() call, but it may not have been pushed
	 * to disk yet. Like the ACTIVE case above, we need to make sure caches
	 * are flushed when this iclog is written.
	 */
	if (iclog->ic_state == XLOG_STATE_WANT_SYNC)
		iclog->ic_flags |= XLOG_ICL_NEED_FLUSH | XLOG_ICL_NEED_FUA;

	if (flags & XFS_LOG_SYNC)
		return xlog_wait_on_iclog(iclog);
out_unlock:
	spin_unlock(&log->l_icloglock);
	return 0;
out_error:
	spin_unlock(&log->l_icloglock);
	return -EIO;
}

/*
 * Force the log to a specific LSN.
 *
 * If an iclog with that lsn can be found:
 *	If it is in the DIRTY state, just return.
 *	If it is in the ACTIVE state, move the in-core log into the WANT_SYNC
 *		state and go to sleep or return.
 *	If it is in any other state, go to sleep or return.
 *
 * Synchronous forces are implemented with a wait queue.  All callers trying
 * to force a given lsn to disk must wait on the queue attached to the
 * specific in-core log.  When given in-core log finally completes its write
 * to disk, that thread will wake up all threads waiting on the queue.
 */
static int
xlog_force_lsn(
	struct xlog		*log,
	xfs_lsn_t		lsn,
	uint			flags,
	int			*log_flushed,
	bool			already_slept)
{
	struct xlog_in_core	*iclog;
	bool			completed;

	spin_lock(&log->l_icloglock);
	if (xlog_is_shutdown(log))
		goto out_error;

	iclog = log->l_iclog;
	while (be64_to_cpu(iclog->ic_header->h_lsn) != lsn) {
		trace_xlog_iclog_force_lsn(iclog, _RET_IP_);
		iclog = iclog->ic_next;
		if (iclog == log->l_iclog)
			goto out_unlock;
	}

	switch (iclog->ic_state) {
	case XLOG_STATE_ACTIVE:
		/*
		 * We sleep here if we haven't already slept (e.g. this is the
		 * first time we've looked at the correct iclog buf) and the
		 * buffer before us is going to be sync'ed.  The reason for this
		 * is that if we are doing sync transactions here, by waiting
		 * for the previous I/O to complete, we can allow a few more
		 * transactions into this iclog before we close it down.
		 *
		 * Otherwise, we mark the buffer WANT_SYNC, and bump up the
		 * refcnt so we can release the log (which drops the ref count).
		 * The state switch keeps new transaction commits from using
		 * this buffer.  When the current commits finish writing into
		 * the buffer, the refcount will drop to zero and the buffer
		 * will go out then.
		 */
		if (!already_slept &&
		    (iclog->ic_prev->ic_state == XLOG_STATE_WANT_SYNC ||
		     iclog->ic_prev->ic_state == XLOG_STATE_SYNCING)) {
			xlog_wait(&iclog->ic_prev->ic_write_wait,
					&log->l_icloglock);
			return -EAGAIN;
		}
		if (xlog_force_and_check_iclog(iclog, &completed))
			goto out_error;
		if (log_flushed)
			*log_flushed = 1;
		if (completed)
			goto out_unlock;
		break;
	case XLOG_STATE_WANT_SYNC:
		/*
		 * This iclog may contain the checkpoint pushed by the
		 * xlog_cil_force_seq() call, but there are other writers still
		 * accessing it so it hasn't been pushed to disk yet. Like the
		 * ACTIVE case above, we need to make sure caches are flushed
		 * when this iclog is written.
		 */
		iclog->ic_flags |= XLOG_ICL_NEED_FLUSH | XLOG_ICL_NEED_FUA;
		break;
	default:
		/*
		 * The entire checkpoint was written by the CIL force and is on
		 * its way to disk already. It will be stable when it
		 * completes, so we don't need to manipulate caches here at all.
		 * We just need to wait for completion if necessary.
		 */
		break;
	}

	if (flags & XFS_LOG_SYNC)
		return xlog_wait_on_iclog(iclog);
out_unlock:
	spin_unlock(&log->l_icloglock);
	return 0;
out_error:
	spin_unlock(&log->l_icloglock);
	return -EIO;
}

/*
 * Force the log to a specific checkpoint sequence.
 *
 * First force the CIL so that all the required changes have been flushed to the
 * iclogs. If the CIL force completed it will return a commit LSN that indicates
 * the iclog that needs to be flushed to stable storage. If the caller needs
 * a synchronous log force, we will wait on the iclog with the LSN returned by
 * xlog_cil_force_seq() to be completed.
 */
int
xfs_log_force_seq(
	struct xfs_mount	*mp,
	xfs_csn_t		seq,
	uint			flags,
	int			*log_flushed)
{
	struct xlog		*log = mp->m_log;
	xfs_lsn_t		lsn;
	int			ret;
	ASSERT(seq != 0);

	XFS_STATS_INC(mp, xs_log_force);
	trace_xfs_log_force(mp, seq, _RET_IP_);

	lsn = xlog_cil_force_seq(log, seq);
	if (lsn == NULLCOMMITLSN)
		return 0;

	ret = xlog_force_lsn(log, lsn, flags, log_flushed, false);
	if (ret == -EAGAIN) {
		XFS_STATS_INC(mp, xs_log_force_sleep);
		ret = xlog_force_lsn(log, lsn, flags, log_flushed, true);
	}
	return ret;
}

/*
 * Free a used ticket when its refcount falls to zero.
 */
void
xfs_log_ticket_put(
	struct xlog_ticket	*ticket)
{
	ASSERT(atomic_read(&ticket->t_ref) > 0);
	if (atomic_dec_and_test(&ticket->t_ref))
		kmem_cache_free(xfs_log_ticket_cache, ticket);
}

struct xlog_ticket *
xfs_log_ticket_get(
	struct xlog_ticket	*ticket)
{
	ASSERT(atomic_read(&ticket->t_ref) > 0);
	atomic_inc(&ticket->t_ref);
	return ticket;
}

/*
 * Figure out the total log space unit (in bytes) that would be
 * required for a log ticket.
 */
static int
xlog_calc_unit_res(
	struct xlog		*log,
	int			unit_bytes,
	int			*niclogs)
{
	int			iclog_space;
	uint			num_headers;

	/*
	 * Permanent reservations have up to 'cnt'-1 active log operations
	 * in the log.  A unit in this case is the amount of space for one
	 * of these log operations.  Normal reservations have a cnt of 1
	 * and their unit amount is the total amount of space required.
	 *
	 * The following lines of code account for non-transaction data
	 * which occupy space in the on-disk log.
	 *
	 * Normal form of a transaction is:
	 * <oph><trans-hdr><start-oph><reg1-oph><reg1><reg2-oph>...<commit-oph>
	 * and then there are LR hdrs, split-recs and roundoff at end of syncs.
	 *
	 * We need to account for all the leadup data and trailer data
	 * around the transaction data.
	 * And then we need to account for the worst case in terms of using
	 * more space.
	 * The worst case will happen if:
	 * - the placement of the transaction happens to be such that the
	 *   roundoff is at its maximum
	 * - the transaction data is synced before the commit record is synced
	 *   i.e. <transaction-data><roundoff> | <commit-rec><roundoff>
	 *   Therefore the commit record is in its own Log Record.
	 *   This can happen as the commit record is called with its
	 *   own region to xlog_write().
	 *   This then means that in the worst case, roundoff can happen for
	 *   the commit-rec as well.
	 *   The commit-rec is smaller than padding in this scenario and so it is
	 *   not added separately.
	 */

	/* for trans header */
	unit_bytes += sizeof(struct xlog_op_header);
	unit_bytes += sizeof(struct xfs_trans_header);

	/* for start-rec */
	unit_bytes += sizeof(struct xlog_op_header);

	/*
	 * for LR headers - the space for data in an iclog is the size minus
	 * the space used for the headers. If we use the iclog size, then we
	 * undercalculate the number of headers required.
	 *
	 * Furthermore - the addition of op headers for split-recs might
	 * increase the space required enough to require more log and op
	 * headers, so take that into account too.
	 *
	 * IMPORTANT: This reservation makes the assumption that if this
	 * transaction is the first in an iclog and hence has the LR headers
	 * accounted to it, then the remaining space in the iclog is
	 * exclusively for this transaction.  i.e. if the transaction is larger
	 * than the iclog, it will be the only thing in that iclog.
	 * Fundamentally, this means we must pass the entire log vector to
	 * xlog_write to guarantee this.
	 */
	iclog_space = log->l_iclog_size - log->l_iclog_hsize;
	num_headers = howmany(unit_bytes, iclog_space);

	/* for split-recs - ophdrs added when data split over LRs */
	unit_bytes += sizeof(struct xlog_op_header) * num_headers;

	/* add extra header reservations if we overrun */
	while (!num_headers ||
	       howmany(unit_bytes, iclog_space) > num_headers) {
		unit_bytes += sizeof(struct xlog_op_header);
		num_headers++;
	}
	unit_bytes += log->l_iclog_hsize * num_headers;

	/* for commit-rec LR header - note: padding will subsume the ophdr */
	unit_bytes += log->l_iclog_hsize;

	/* roundoff padding for transaction data and one for commit record */
	unit_bytes += 2 * log->l_iclog_roundoff;

	if (niclogs)
		*niclogs = num_headers;
	return unit_bytes;
}

int
xfs_log_calc_unit_res(
	struct xfs_mount	*mp,
	int			unit_bytes)
{
	return xlog_calc_unit_res(mp->m_log, unit_bytes, NULL);
}

/*
 * Allocate and initialise a new log ticket.
 */
struct xlog_ticket *
xlog_ticket_alloc(
	struct xlog		*log,
	int			unit_bytes,
	int			cnt,
	bool			permanent)
{
	struct xlog_ticket	*tic;
	int			unit_res;

	tic = kmem_cache_zalloc(xfs_log_ticket_cache,
			GFP_KERNEL | __GFP_NOFAIL);

	unit_res = xlog_calc_unit_res(log, unit_bytes, &tic->t_iclog_hdrs);

	atomic_set(&tic->t_ref, 1);
	tic->t_task		= current;
	INIT_LIST_HEAD(&tic->t_queue);
	tic->t_unit_res		= unit_res;
	tic->t_curr_res		= unit_res;
	tic->t_cnt		= cnt;
	tic->t_ocnt		= cnt;
	tic->t_tid		= get_random_u32();
	if (permanent)
		tic->t_flags |= XLOG_TIC_PERM_RESERV;

	return tic;
}

#if defined(DEBUG)
static void
xlog_verify_dump_tail(
	struct xlog		*log,
	struct xlog_in_core	*iclog)
{
	xfs_alert(log->l_mp,
"ran out of log space tail 0x%llx/0x%llx, head lsn 0x%llx, head 0x%x/0x%x, prev head 0x%x/0x%x",
			iclog ? be64_to_cpu(iclog->ic_header->h_tail_lsn) : -1,
			atomic64_read(&log->l_tail_lsn),
			log->l_ailp->ail_head_lsn,
			log->l_curr_cycle, log->l_curr_block,
			log->l_prev_cycle, log->l_prev_block);
	xfs_alert(log->l_mp,
"write grant 0x%llx, reserve grant 0x%llx, tail_space 0x%llx, size 0x%x, iclog flags 0x%x",
			atomic64_read(&log->l_write_head.grant),
			atomic64_read(&log->l_reserve_head.grant),
			log->l_tail_space, log->l_logsize,
			iclog ? iclog->ic_flags : -1);
}

/* Check if the new iclog will fit in the log. */
STATIC void
xlog_verify_tail_lsn(
	struct xlog		*log,
	struct xlog_in_core	*iclog)
{
	xfs_lsn_t	tail_lsn = be64_to_cpu(iclog->ic_header->h_tail_lsn);
	int		blocks;

	if (CYCLE_LSN(tail_lsn) == log->l_prev_cycle) {
		blocks = log->l_logBBsize -
				(log->l_prev_block - BLOCK_LSN(tail_lsn));
		if (blocks < BTOBB(iclog->ic_offset) +
					BTOBB(log->l_iclog_hsize)) {
			xfs_emerg(log->l_mp,
					"%s: ran out of log space", __func__);
			xlog_verify_dump_tail(log, iclog);
		}
		return;
	}

	if (CYCLE_LSN(tail_lsn) + 1 != log->l_prev_cycle) {
		xfs_emerg(log->l_mp, "%s: head has wrapped tail.", __func__);
		xlog_verify_dump_tail(log, iclog);
		return;
	}
	if (BLOCK_LSN(tail_lsn) == log->l_prev_block) {
		xfs_emerg(log->l_mp, "%s: tail wrapped", __func__);
		xlog_verify_dump_tail(log, iclog);
		return;
	}

	blocks = BLOCK_LSN(tail_lsn) - log->l_prev_block;
	if (blocks < BTOBB(iclog->ic_offset) + 1) {
		xfs_emerg(log->l_mp, "%s: ran out of iclog space", __func__);
		xlog_verify_dump_tail(log, iclog);
	}
}

/*
 * Perform a number of checks on the iclog before writing to disk.
 *
 * 1. Make sure the iclogs are still circular
 * 2. Make sure we have a good magic number
 * 3. Make sure we don't have magic numbers in the data
 * 4. Check fields of each log operation header for:
 *	A. Valid client identifier
 *	B. tid ptr value falls in valid ptr space (user space code)
 *	C. Length in log record header is correct according to the
 *		individual operation headers within record.
 * 5. When a bwrite will occur within 5 blocks of the front of the physical
 *	log, check the preceding blocks of the physical log to make sure all
 *	the cycle numbers agree with the current cycle number.
 */
STATIC void
xlog_verify_iclog(
	struct xlog		*log,
	struct xlog_in_core	*iclog,
	int			count)
{
	struct xlog_rec_header	*rhead = iclog->ic_header;
	struct xlog_in_core	*icptr;
	void			*base_ptr, *ptr;
	ptrdiff_t		field_offset;
	uint8_t			clientid;
	int			len, i, op_len;
	int			idx;

	/* check validity of iclog pointers */
	spin_lock(&log->l_icloglock);
	icptr = log->l_iclog;
	for (i = 0; i < log->l_iclog_bufs; i++, icptr = icptr->ic_next)
		ASSERT(icptr);

	if (icptr != log->l_iclog)
		xfs_emerg(log->l_mp, "%s: corrupt iclog ring", __func__);
	spin_unlock(&log->l_icloglock);

	/* check log magic numbers */
	if (rhead->h_magicno != cpu_to_be32(XLOG_HEADER_MAGIC_NUM))
		xfs_emerg(log->l_mp, "%s: invalid magic num", __func__);

	base_ptr = ptr = rhead;
	for (ptr += BBSIZE; ptr < base_ptr + count; ptr += BBSIZE) {
		if (*(__be32 *)ptr == cpu_to_be32(XLOG_HEADER_MAGIC_NUM))
			xfs_emerg(log->l_mp, "%s: unexpected magic num",
				__func__);
	}

	/* check fields */
	len = be32_to_cpu(rhead->h_num_logops);
	base_ptr = ptr = iclog->ic_datap;
	for (i = 0; i < len; i++) {
		struct xlog_op_header	*ophead = ptr;
		void			*p = &ophead->oh_clientid;

		/* clientid is only 1 byte */
		field_offset = p - base_ptr;
		if (field_offset & 0x1ff) {
			clientid = ophead->oh_clientid;
		} else {
			idx = BTOBBT((void *)&ophead->oh_clientid - iclog->ic_datap);
			clientid = xlog_get_client_id(*xlog_cycle_data(rhead, idx));
		}
		if (clientid != XFS_TRANSACTION && clientid != XFS_LOG) {
			xfs_warn(log->l_mp,
				"%s: op %d invalid clientid %d op "PTR_FMT" offset 0x%lx",
				__func__, i, clientid, ophead,
				(unsigned long)field_offset);
		}

		/* check length */
		p = &ophead->oh_len;
		field_offset = p - base_ptr;
		if (field_offset & 0x1ff) {
			op_len = be32_to_cpu(ophead->oh_len);
		} else {
			idx = BTOBBT((void *)&ophead->oh_len - iclog->ic_datap);
			op_len = be32_to_cpu(*xlog_cycle_data(rhead, idx));
		}
		ptr += sizeof(struct xlog_op_header) + op_len;
	}
}
#endif

/*
 * Perform a forced shutdown on the log.
 *
 * This can be called from low level log code to trigger a shutdown, or from the
 * high level mount shutdown code when the mount shuts down.
 *
 * Our main objectives here are to make sure that:
 *	a. if the shutdown was not due to a log IO error, flush the logs to
 *	   disk. Anything modified after this is ignored.
 *	b. the log gets atomically marked 'XLOG_IO_ERROR' for all interested
 *	   parties to find out. Nothing new gets queued after this is done.
 *	c. Tasks sleeping on log reservations, pinned objects and
 *	   other resources get woken up.
 *	d. The mount is also marked as shut down so that log triggered shutdowns
 *	   still behave the same as if they called xfs_forced_shutdown().
 *
 * Return true if the shutdown cause was a log IO error and we actually shut the
 * log down.
 */
bool
xlog_force_shutdown(
	struct xlog	*log,
	uint32_t	shutdown_flags)
{
	bool		log_error = (shutdown_flags & SHUTDOWN_LOG_IO_ERROR);

	if (!log)
		return false;

	/*
	 * Ensure that there is only ever one log shutdown being processed.
	 * If we allow the log force below on a second pass after shutting
	 * down the log, we risk deadlocking the CIL push as it may require
	 * locks on objects the current shutdown context holds (e.g. taking
	 * buffer locks to abort buffers on last unpin of buf log items).
	 */
	if (test_and_set_bit(XLOG_SHUTDOWN_STARTED, &log->l_opstate))
		return false;

	/*
	 * Flush all the completed transactions to disk before marking the log
	 * being shut down. We need to do this first as shutting down the log
	 * before the force will prevent the log force from flushing the iclogs
	 * to disk.
	 *
	 * When we are in recovery, there are no transactions to flush, and
	 * we don't want to touch the log because we don't want to perturb the
	 * current head/tail for future recovery attempts. Hence we need to
	 * avoid a log force in this case.
	 *
	 * If we are shutting down due to a log IO error, then we must avoid
	 * trying to write the log as that may just result in more IO errors and
	 * an endless shutdown/force loop.
	 */
	if (!log_error && !xlog_in_recovery(log))
		xfs_log_force(log->l_mp, XFS_LOG_SYNC);

	/*
	 * Atomically set the shutdown state. If the shutdown state is already
	 * set, there someone else is performing the shutdown and so we are done
	 * here. This should never happen because we should only ever get called
	 * once by the first shutdown caller.
	 *
	 * Much of the log state machine transitions assume that shutdown state
	 * cannot change once they hold the log->l_icloglock. Hence we need to
	 * hold that lock here, even though we use the atomic test_and_set_bit()
	 * operation to set the shutdown state.
	 */
	spin_lock(&log->l_icloglock);
	if (test_and_set_bit(XLOG_IO_ERROR, &log->l_opstate)) {
		spin_unlock(&log->l_icloglock);
		ASSERT(0);
		return false;
	}
	spin_unlock(&log->l_icloglock);

	/*
	 * If this log shutdown also sets the mount shutdown state, issue a
	 * shutdown warning message.
	 */
	if (!xfs_set_shutdown(log->l_mp)) {
		xfs_alert_tag(log->l_mp, XFS_PTAG_SHUTDOWN_LOGERROR,
"Filesystem has been shut down due to log error (0x%x).",
				shutdown_flags);
		xfs_alert(log->l_mp,
"Please unmount the filesystem and rectify the problem(s).");
		if (xfs_error_level >= XFS_ERRLEVEL_HIGH)
			xfs_stack_trace();
		/*
		 * (D-FENCED-VICTIM-NONCONTAINMENT-498, churn arm): when
		 * the FIRST shutdown of this mount originates in the log (a log
		 * write bounced — e.g. RESERVATION CONFLICT on a fenced node, or
		 * any log I/O error), the mount shutdown bit is set HERE and
		 * xfs_do_force_shutdown never runs for this mount — every later
		 * caller (the fence_notify self-withdraw included) returns early
		 * on xfs_set_shutdown.  The cluster withdrawal
		 * (mxfs_dlm_shutdown_withdraw: fence new acquires, stop the
		 * disklock heartbeat so peers reclaim our slots) therefore never
		 * ran: test20 kept heartbeating (bouncing -52) for 61 s holding
		 * its grants until the peers' SLOT_TAKEOVER.  A dead FS must not
		 * stay a cluster member whichever path shut it down.  Queued work,
		 * idempotent with the xfs_do_force_shutdown call.
		 */
		if (log->l_mp->m_mxfs_dlm)
			mxfs_dlm_shutdown_withdraw(log->l_mp);
	}

	/*
	 * We don't want anybody waiting for log reservations after this. That
	 * means we have to wake up everybody queued up on reserveq as well as
	 * writeq.  In addition, we make sure in xlog_{re}grant_log_space that
	 * we don't enqueue anything once the SHUTDOWN flag is set, and this
	 * action is protected by the grant locks.
	 */
	xlog_grant_head_wake_all(&log->l_reserve_head);
	xlog_grant_head_wake_all(&log->l_write_head);

	/*
	 * Wake up everybody waiting on xfs_log_force. Wake the CIL push first
	 * as if the log writes were completed. The abort handling in the log
	 * item committed callback functions will do this again under lock to
	 * avoid races.
	 */
	spin_lock(&log->l_cilp->xc_push_lock);
	wake_up_all(&log->l_cilp->xc_start_wait);
	wake_up_all(&log->l_cilp->xc_commit_wait);
	spin_unlock(&log->l_cilp->xc_push_lock);

	spin_lock(&log->l_icloglock);
	xlog_state_shutdown_callbacks(log);
	spin_unlock(&log->l_icloglock);

	wake_up_var(&log->l_opstate);
	if (IS_ENABLED(CONFIG_XFS_RT) && xfs_has_zoned(log->l_mp))
		xfs_zoned_wake_all(log->l_mp);

	return log_error;
}

STATIC int
xlog_iclogs_empty(
	struct xlog		*log)
{
	struct xlog_in_core	*iclog = log->l_iclog;

	do {
		/* endianness does not matter here, zero is zero in
		 * any language.
		 */
		if (iclog->ic_header->h_num_logops)
			return 0;
		iclog = iclog->ic_next;
	} while (iclog != log->l_iclog);

	return 1;
}

/*
 * Verify that an LSN stamped into a piece of metadata is valid. This is
 * intended for use in read verifiers on v5 superblocks.
 */
bool
xfs_log_check_lsn(
	struct xfs_mount	*mp,
	xfs_lsn_t		lsn)
{
	struct xlog		*log = mp->m_log;
	bool			valid;

	/*
	 * norecovery mode skips mount-time log processing and unconditionally
	 * resets the in-core LSN. We can't validate in this mode, but
	 * modifications are not allowed anyways so just return true.
	 */
	if (xfs_has_norecovery(mp))
		return true;

	/*
	 * Some metadata LSNs are initialized to NULL (e.g., the agfl). This is
	 * handled by recovery and thus safe to ignore here.
	 */
	if (lsn == NULLCOMMITLSN)
		return true;

	/*
	 * Multi-node (DLM active): each node has its own per-node log
	 * slice with independent LSN counters.  Metadata blocks carry
	 * LSNs from whichever node last wrote them.  Comparing a
	 * cross-node LSN against the local log counter is meaningless —
	 * they are independent sequences from different physical logs.
	 * Skip the check; per-node logs + DLM fencing + AIL push
	 * provide the correctness guarantees instead.
	 *
	 * Gate on m_mxfs_dlm_was_active, NOT m_mxfs_dlm: put_super tears
	 * the DLM down before xfs_unmountfs, and the quiesce-time summary
	 * counter recompute (and any other late read) still encounters
	 * peer-stamped LSNs after that point (run14d: AGF read at
	 * quiesce failed -EFSCORRUPTED on "LSN (1:5) ahead of (1:0)").
	 */
	if (mp->m_mxfs_dlm_was_active)
		return true;

	valid = xlog_valid_lsn(mp->m_log, lsn);

	/* warn the user about what's gone wrong before verifier failure */
	if (!valid) {
		spin_lock(&log->l_icloglock);
		xfs_warn(mp,
"Corruption warning: Metadata has LSN (%d:%d) ahead of current LSN (%d:%d). "
"Please unmount and run xfs_repair (>= v4.3) to resolve.",
			 CYCLE_LSN(lsn), BLOCK_LSN(lsn),
			 log->l_curr_cycle, log->l_curr_block);
		spin_unlock(&log->l_icloglock);
	}

	return valid;
}
