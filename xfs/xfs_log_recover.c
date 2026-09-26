// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_log_recover.h"
#include "xfs_icreate_item.h"
#include "xfs_trans_priv.h"
#include "xfs_alloc.h"
#include "xfs_ialloc.h"
#include "xfs_trace.h"
#include "xfs_icache.h"
#include "xfs_error.h"
#include "xfs_buf_item.h"
#include "xfs_ag.h"
#include "xfs_quota.h"
#include "xfs_reflink.h"
#include "xfs_relmark_item.h"	/* clean-release markers -> REDUNDANT_CLEAN */
#include "xfs_mxfs_icensus.h"	/* intent/done census -> INTENTS_UNDISCHARGED */
#include "../dlm/v5_mount.h"	/* mxfs_v5_dlm_is_single_node (iunlink recovery scoping) */
#include "../dlm/disklock.h"	/* MXFS_RECOV_STAGE_* (shadow evaluator capability check) */
#include <linux/hash.h>		/* hash_64 (shadow evaluator manifest cache) */

/* D-FOREIGN-REPLAY-UNGATED-IMAGES containment knob (xfs_mxfs_dlm.c) */
extern int mxfs_foreign_replay_untagged_apply;
/* D-529 whole-txn verdict fault injection (xfs_mxfs_dlm.c) */
extern int mxfs_dbg_fr_taint_items_over;
/* (#1, ruling): token-enforcement knob + its use-time
 * domain/proof predicates (all defined in xfs_mxfs_dlm.c) */
extern int mxfs_foreign_replay_token_enforce;
extern int mxfs_fua_disable;
extern int mxfs_target_cache_protected;
extern int mxfs_release_proof_enforce;
/* (design review Q5): serializes the enforce/F2-param setters with
 * the preflight's configuration sample */
extern struct mutex mxfs_fr_cfg_lock;
/* 0.89.18: the partial-replay cut's knobs (xfs_mxfs_dlm.c) — see
 * mxfs_replay_cut_partial() below and
 * docs/rulings/fence-matrix-remaining-gates-and-partial-replay.md */
extern int mxfs_dbg_replay_cut_prefix;
extern int mxfs_dbg_replay_cut_slot;
extern unsigned long long mxfs_dbg_replay_cut_epoch;
extern int mxfs_dbg_replay_cut_hold_ms;

#define BLK_AVG(blk1, blk2)	((blk1+blk2) >> 1)

STATIC int
xlog_find_zeroed(
	struct xlog	*,
	xfs_daddr_t	*);
STATIC int
xlog_clear_stale_blocks(
	struct xlog	*,
	xfs_lsn_t);
STATIC int
xlog_do_recovery_pass(
        struct xlog *, xfs_daddr_t, xfs_daddr_t, int, xfs_daddr_t *);

/*
 * Sector aligned buffer routines for buffer create/read/write/access
 */

/*
 * Verify the log-relative block number and length in basic blocks are valid for
 * an operation involving the given XFS log buffer. Returns true if the fields
 * are valid, false otherwise.
 */
static inline bool
xlog_verify_bno(
	struct xlog	*log,
	xfs_daddr_t	blk_no,
	int		bbcount)
{
	if (blk_no < 0 || blk_no >= log->l_logBBsize)
		return false;
	if (bbcount <= 0 || (blk_no + bbcount) > log->l_logBBsize)
		return false;
	return true;
}

/*
 * Allocate a buffer to hold log data.  The buffer needs to be able to map to
 * a range of nbblks basic blocks at any valid offset within the log.
 */
static char *
xlog_alloc_buffer(
	struct xlog	*log,
	int		nbblks)
{
	/*
	 * Pass log block 0 since we don't have an addr yet, buffer will be
	 * verified on read.
	 */
	if (XFS_IS_CORRUPT(log->l_mp, !xlog_verify_bno(log, 0, nbblks))) {
		xfs_warn(log->l_mp, "Invalid block length (0x%x) for buffer",
			nbblks);
		return NULL;
	}

	/*
	 * We do log I/O in units of log sectors (a power-of-2 multiple of the
	 * basic block size), so we round up the requested size to accommodate
	 * the basic blocks required for complete log sectors.
	 *
	 * In addition, the buffer may be used for a non-sector-aligned block
	 * offset, in which case an I/O of the requested size could extend
	 * beyond the end of the buffer.  If the requested size is only 1 basic
	 * block it will never straddle a sector boundary, so this won't be an
	 * issue.  Nor will this be a problem if the log I/O is done in basic
	 * blocks (sector size 1).  But otherwise we extend the buffer by one
	 * extra log sector to ensure there's space to accommodate this
	 * possibility.
	 */
	if (nbblks > 1 && log->l_sectBBsize > 1)
		nbblks += log->l_sectBBsize;
	nbblks = round_up(nbblks, log->l_sectBBsize);
	return kvzalloc(BBTOB(nbblks), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
}

/*
 * Return the address of the start of the given block number's data
 * in a log buffer.  The buffer covers a log sector-aligned region.
 */
static inline unsigned int
xlog_align(
	struct xlog	*log,
	xfs_daddr_t	blk_no)
{
	return BBTOB(blk_no & ((xfs_daddr_t)log->l_sectBBsize - 1));
}

static int
xlog_do_io(
	struct xlog		*log,
	xfs_daddr_t		blk_no,
	unsigned int		nbblks,
	char			*data,
	enum req_op		op)
{
	int			error;

	if (XFS_IS_CORRUPT(log->l_mp, !xlog_verify_bno(log, blk_no, nbblks))) {
		xfs_warn(log->l_mp,
			 "Invalid log block/length (0x%llx, 0x%x) for buffer",
			 blk_no, nbblks);
		return -EFSCORRUPTED;
	}

	blk_no = round_down(blk_no, log->l_sectBBsize);
	nbblks = round_up(nbblks, log->l_sectBBsize);
	ASSERT(nbblks > 0);

	/*
	 * (D-527): when a foreign-replay shadow xlog carries a
	 * stabilized slice snapshot, every recovery READ is served from it
	 * and every WRITE is mirrored into it before writing through, so
	 * the whole recovery (head/tail scan, both passes) sees ONE
	 * immutable image of the slice with no TOCTOU between validation
	 * and replay.  The rounding above already matches what the bdev
	 * path would transfer, so the mirrored bytes equal the platter's.
	 */
	if (log->l_mxfs_slice_snap) {
		unsigned int off = BBTOB(blk_no);
		unsigned int len = BBTOB(nbblks);

		if (off + len > log->l_mxfs_snap_bytes) {
			xfs_warn(log->l_mp,
	"MXFS: P-FRSTAB-RANGE snapshot I/O beyond slice (off=%u len=%u snap=%u)",
				 off, len, log->l_mxfs_snap_bytes);
			return -EFSCORRUPTED;
		}
		if (op == REQ_OP_READ) {
			memcpy(data, log->l_mxfs_slice_snap + off, len);
			return 0;
		}
		memcpy(log->l_mxfs_slice_snap + off, data, len);
	}

	error = xfs_rw_bdev(log->l_targ->bt_bdev,
			log->l_targ->bt_sector_offset +
			log->l_logBBstart + blk_no,
			BBTOB(nbblks), data, op);
	if (error && !xlog_is_shutdown(log)) {
		xfs_alert(log->l_mp,
			  "log recovery %s I/O error at daddr 0x%llx len %d error %d",
			  op == REQ_OP_WRITE ? "write" : "read",
			  blk_no, nbblks, error);
	}
	return error;
}

STATIC int
xlog_bread_noalign(
	struct xlog	*log,
	xfs_daddr_t	blk_no,
	int		nbblks,
	char		*data)
{
	return xlog_do_io(log, blk_no, nbblks, data, REQ_OP_READ);
}

STATIC int
xlog_bread(
	struct xlog	*log,
	xfs_daddr_t	blk_no,
	int		nbblks,
	char		*data,
	char		**offset)
{
	int		error;

	error = xlog_do_io(log, blk_no, nbblks, data, REQ_OP_READ);
	if (!error)
		*offset = data + xlog_align(log, blk_no);
	return error;
}

STATIC int
xlog_bwrite(
	struct xlog	*log,
	xfs_daddr_t	blk_no,
	int		nbblks,
	char		*data)
{
	return xlog_do_io(log, blk_no, nbblks, data, REQ_OP_WRITE);
}

/*
 * (D-FOREIGN-REPLAY-UNSTABLE-SLICE-READ-FALSE-TORN-527, design-consult
 * ruling): capture the victim's whole log slice into one immutable
 * in-memory snapshot, accepting it only after the slice PROVES STABLE —
 * mxfs_fr_stab_passes consecutive full-slice re-reads with zero differing
 * bytes.  A fenced-but-recently-live victim's writes that were admitted
 * before the PREEMPT AND ABORT can land on the backing store AFTER fence
 * certification (target task-abort does not cancel already-submitted
 * backing aio, and SCSI gives no cross-command ordering), so a single
 * live read pass can see record-aligned holes filled with CRC-valid
 * previous-life twin records; recovery then silently drops the alien-tid
 * regions and mis-assembles items (measured: replay_test1.txt, slot 29,
 * -117 on a slice that decodes 100% clean minutes later).
 *
 * Every compare pass folds the newer bytes into the snapshot, so the
 * buffer converges on the latest platter state; instability observed
 * here is also the in-vivo PROOF of post-certification landings and is
 * logged per pass (P-FRSTAB-UNSTABLE).  A slice still changing at the
 * deadline is a quiesce failure, NOT a torn log: return -EBUSY so the
 * attempt aborts with verdict reason NONE (slice stays dirty, a later
 * election retries) — never a terminal verdict from an unproven image.
 */
int mxfs_fr_stab_interval_ms = 2000;
int mxfs_fr_stab_passes = 2;
int mxfs_fr_stab_deadline_ms = 45000;
/*
 * (design-consult ruling frstab-
 * pipeline-across-slices, option A): the whole-cluster bootstrap replays 31
 * slices serially and each pays the two 2 s stability intervals (4.4 s of
 * a 4.5 s per-slice cost, 136 s of the mount).  The barrier now PREFETCHES
 * the NEXT victim's snapshot on a worker while the current slice's proof
 * and replay run, so the intervals overlap.  Every slice still performs
 * its own pass 0 + `need` sleep-separated compare passes under its own
 * deadline (started when ITS attempt starts), a mismatch folds and resets
 * exactly as inline, the consumer adopts the buffer only after the worker
 * has COMPLETED (no asynchronous compare can touch a buffer under replay),
 * and a failed or missing prefetch falls back to the inline proof — never
 * to live reads.  0 disables (inline only).
 */
/*
 * (chain 36 on 0.52.0): the single-entry prefetch never engaged — the
 * barrier arms slot k+1 BEFORE it replays slot k, and arming dropped the
 * entry for k, so 30 of 31 proofs ran inline (mount wall 298 s, 143 s of it
 * the serial 4.6 s/slice proofs).  The knob is now the pipeline DEPTH: up to
 * that many victims' proofs run concurrently on workers (each holds a 64 MiB
 * snapshot + 4 MiB bounce — 3 ≈ 200 MiB on a 2.3 GB node), consumed in the
 * barrier's order.  0 disables (inline only); capped at MXFS_SNAP_PF_MAX.
 */
int mxfs_fr_stab_prefetch = 3;

/*
 * The stability proof itself, on a raw {targ, log-relative start, bytes}
 * so a worker can run it without a shadow xlog.  Returns 0 with *snap_out
 * (kvmalloc'd, caller frees); -EBUSY not quiesced; -ENOMEM; read errno.
 */
static int
mxfs_slice_stabilize(
	struct xfs_mount	*mp,
	struct xfs_buftarg	*targ,
	xfs_daddr_t		logBBstart,
	unsigned int		bytes,
	uint32_t		slot,
	char			**snap_out,
	bool			*unstable_seen,
	int			*passes_out,
	unsigned int		*wall_ms)
{
	const unsigned int	chunk = 4 << 20;	/* sector-multiple */
	unsigned long		deadline = jiffies +
			msecs_to_jiffies(READ_ONCE(mxfs_fr_stab_deadline_ms));
	int			need = READ_ONCE(mxfs_fr_stab_passes);
	unsigned long		t0 = jiffies;
	char			*snap, *bounce;
	unsigned int		off, len;
	int			pass = 0, stable = 0;
	int			error;

	*snap_out = NULL;
	*unstable_seen = false;
	*passes_out = 0;
	*wall_ms = 0;
	if (need < 1)
		need = 1;

	snap = kvzalloc(bytes, GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	bounce = kvzalloc(chunk, GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!snap || !bounce) {
		kvfree(snap);
		kvfree(bounce);
		xfs_alert(mp,
	"MXFS: P-FRSTAB-ALLOC slot=%u slice snapshot allocation failed (%u bytes) — aborting elected recovery (slice stays dirty, retryable); NEVER replaying from live reads",
			  slot, bytes);
		return -ENOMEM;
	}

	/* pass 0: full sequential read into the snapshot */
	for (off = 0; off < bytes; off += chunk) {
		len = min(chunk, bytes - off);
		error = xfs_rw_bdev(targ->bt_bdev,
				targ->bt_sector_offset + logBBstart + BTOBB(off),
				len, snap + off, REQ_OP_READ);
		if (error)
			goto out_ioerr;
	}

	while (stable < need) {
		unsigned int	ndiff = 0;
		long		first_bb = -1;

		msleep(READ_ONCE(mxfs_fr_stab_interval_ms));
		for (off = 0; off < bytes; off += chunk) {
			len = min(chunk, bytes - off);
			error = xfs_rw_bdev(targ->bt_bdev,
					targ->bt_sector_offset + logBBstart +
					BTOBB(off),
					len, bounce, REQ_OP_READ);
			if (error)
				goto out_ioerr;
			if (memcmp(snap + off, bounce, len)) {
				ndiff++;
				if (first_bb < 0)
					first_bb = BTOBB(off);
				memcpy(snap + off, bounce, len);
			}
		}
		pass++;
		if (ndiff) {
			stable = 0;
			*unstable_seen = true;
			xfs_notice(mp,
	"MXFS: P-FRSTAB-UNSTABLE slot=%u pass=%d diff_chunks=%u first_bb=%ld — the fenced victim's slice CHANGED under us after fence certification (in-flight victim I/O still landing); waiting for quiesce",
				   slot, pass, ndiff, first_bb);
		} else {
			stable++;
		}
		if (stable < need && time_after(jiffies, deadline)) {
			kvfree(snap);
			kvfree(bounce);
			xfs_alert(mp,
	"MXFS: P-FRSTAB-NOT-QUIESCED slot=%u passes=%d deadline_ms=%d — slice still changing at the stabilization deadline; aborting elected recovery (slice stays dirty, retryable).  This is a fence/drain failure, NOT a torn log",
				  slot, pass, READ_ONCE(mxfs_fr_stab_deadline_ms));
			*passes_out = pass;
			return -EBUSY;
		}
	}

	kvfree(bounce);
	*snap_out = snap;
	*passes_out = pass;
	*wall_ms = jiffies_to_msecs(jiffies - t0);
	return 0;

out_ioerr:
	kvfree(snap);
	kvfree(bounce);
	xfs_alert(mp,
	"MXFS: P-FRSTAB-IOERR slot=%u read error %d during slice snapshot — aborting elected recovery (slice stays dirty, retryable)",
		  slot, error);
	*passes_out = pass;
	return error;
}

/* Up to MXFS_SNAP_PF_MAX prefetched proofs in flight per module (one mount per node). */
#define MXFS_SNAP_PF_MAX	8
struct mxfs_snap_pf {
	struct work_struct	work;
	struct xfs_mount	*mp;
	struct xfs_buftarg	*targ;
	uint32_t		slot;
	xfs_daddr_t		logBBstart;
	unsigned int		bytes;
	char			*snap;
	bool			unstable_seen;
	int			passes;
	unsigned int		wall_ms;
	int			rc;
	unsigned long		t_start;
	struct completion	done;
};
static struct mxfs_snap_pf	*mxfs_snap_pf[MXFS_SNAP_PF_MAX];
static DEFINE_MUTEX(mxfs_snap_pf_lock);

static void
mxfs_snap_pf_fn(
	struct work_struct	*work)
{
	struct mxfs_snap_pf	*pf = container_of(work, struct mxfs_snap_pf, work);

	pf->rc = mxfs_slice_stabilize(pf->mp, pf->targ, pf->logBBstart,
				      pf->bytes, pf->slot, &pf->snap,
				      &pf->unstable_seen, &pf->passes,
				      &pf->wall_ms);
	complete(&pf->done);
}

/* caller holds mxfs_snap_pf_lock; waits for the worker, frees everything */
static void
mxfs_snap_pf_drop_locked(int i)
{
	struct mxfs_snap_pf	*pf = mxfs_snap_pf[i];

	if (!pf)
		return;
	mxfs_snap_pf[i] = NULL;
	wait_for_completion(&pf->done);
	kvfree(pf->snap);
	kfree(pf);
}

/*
 * Start proving the snapshot of dead slot @slot of @mp on a worker.  Called
 * by the mount-cohort barrier for the next victims it will replay, up to the
 * pipeline depth.  An entry for the same (mp, slot) is left alone; entries
 * of another mount are dropped; a full ring arms nothing (the consumer then
 * proves inline).  Read-only on the LUN.
 */
void
mxfs_xlog_snap_prefetch(
	struct xfs_mount	*mp,
	uint32_t		slot)
{
	struct mxfs_snap_pf	*pf;
	uint32_t		slice;
	int			depth = READ_ONCE(mxfs_fr_stab_prefetch);
	int			i, free = -1, inflight = 0;

	if (depth <= 0)
		return;
	if (depth > MXFS_SNAP_PF_MAX)
		depth = MXFS_SNAP_PF_MAX;
	if (mxfs_log_slice_of_slot(mp, slot, &slice))
		return;
	mutex_lock(&mxfs_snap_pf_lock);
	for (i = 0; i < MXFS_SNAP_PF_MAX; i++) {
		if (!mxfs_snap_pf[i])
			continue;
		if (mxfs_snap_pf[i]->mp != mp) {
			mxfs_snap_pf_drop_locked(i);	/* another mount's leftover */
			continue;
		}
		if (mxfs_snap_pf[i]->slot == slot) {
			mutex_unlock(&mxfs_snap_pf_lock);
			return;				/* already armed */
		}
		inflight++;
	}
	for (i = 0; i < MXFS_SNAP_PF_MAX; i++)
		if (!mxfs_snap_pf[i]) {
			free = i;
			break;
		}
	if (free < 0 || inflight >= depth) {
		mutex_unlock(&mxfs_snap_pf_lock);
		return;					/* pipeline full */
	}
	pf = kzalloc(sizeof(*pf), GFP_KERNEL);
	if (!pf) {
		mutex_unlock(&mxfs_snap_pf_lock);
		return;
	}
	pf->mp = mp;
	pf->targ = mp->m_logdev_targp;
	pf->slot = slot;
	pf->logBBstart = XFS_FSB_TO_DADDR(mp, mp->m_sb.sb_logstart) +
			 (xfs_daddr_t)slice * mp->m_mxfs_log_slice_bblks;
	pf->bytes = BBTOB(mp->m_mxfs_log_slice_bblks);
	pf->t_start = jiffies;
	init_completion(&pf->done);
	INIT_WORK(&pf->work, mxfs_snap_pf_fn);
	mxfs_snap_pf[free] = pf;
	queue_work(system_unbound_wq, &pf->work);
	mutex_unlock(&mxfs_snap_pf_lock);
	xfs_notice(mp,
	"MXFS: P-FRSTAB-PREFETCH slot=%u bytes=%u inflight=%d depth=%d — stability proof of a coming victim's slice started on a worker",
		   slot, pf->bytes, inflight + 1, depth);
}

/* Drop any prefetch belonging to @mp (log unmount / barrier exit). */
void
mxfs_xlog_snap_prefetch_cancel(
	struct xfs_mount	*mp)
{
	int			i;

	mutex_lock(&mxfs_snap_pf_lock);
	for (i = 0; i < MXFS_SNAP_PF_MAX; i++)
		if (mxfs_snap_pf[i] && mxfs_snap_pf[i]->mp == mp)
			mxfs_snap_pf_drop_locked(i);
	mutex_unlock(&mxfs_snap_pf_lock);
}

int
mxfs_xlog_slice_snapshot(
	struct xlog		*log)
{
	struct xfs_mount	*mp = log->l_mp;
	unsigned int		bytes = BBTOB(log->l_logBBsize);
	struct mxfs_snap_pf	*pf = NULL;
	char			*snap;
	bool			unstable;
	int			passes;
	unsigned int		wall_ms;
	int			error;

	ASSERT(xlog_is_mxfs_foreign_replay(log));

	/* a prefetched proof for exactly this slice?  take it (worker done) */
	mutex_lock(&mxfs_snap_pf_lock);
	{
		int i;

		for (i = 0; i < MXFS_SNAP_PF_MAX; i++) {
			struct mxfs_snap_pf *c = mxfs_snap_pf[i];

			if (c && c->mp == mp &&
			    c->slot == log->l_mxfs_victim_slot &&
			    c->logBBstart == log->l_logBBstart &&
			    c->bytes == bytes && c->targ == log->l_targ) {
				pf = c;
				mxfs_snap_pf[i] = NULL;
				break;
			}
		}
	}
	mutex_unlock(&mxfs_snap_pf_lock);
	if (pf) {
		unsigned long	tw = jiffies;

		wait_for_completion(&pf->done);
		if (pf->rc == 0) {
			log->l_mxfs_slice_snap = pf->snap;
			log->l_mxfs_snap_bytes = pf->bytes;
			log->l_mxfs_snap_unstable_seen = pf->unstable_seen;
			mxfs_xfs_probe(mp,
	"MXFS: P-FRSTAB-STABLE slot=%u passes=%d unstable_seen=%d wall_ms=%u prefetched=1 age_ms=%u waited_ms=%u — slice snapshot immutable (proven on the worker); recovery reads now served from it",
				   log->l_mxfs_victim_slot, pf->passes,
				   pf->unstable_seen, pf->wall_ms,
				   jiffies_to_msecs(jiffies - pf->t_start),
				   jiffies_to_msecs(jiffies - tw));
			kfree(pf);
			return 0;
		}
		error = pf->rc;
		kvfree(pf->snap);
		kfree(pf);
		xfs_notice(mp,
	"MXFS: P-FRSTAB-PREFETCH-FAILED slot=%u rc=%d — the worker's proof failed; retrying the proof inline",
			   log->l_mxfs_victim_slot, error);
	}

	error = mxfs_slice_stabilize(mp, log->l_targ, log->l_logBBstart, bytes,
				     log->l_mxfs_victim_slot, &snap, &unstable,
				     &passes, &wall_ms);
	if (error)
		return error;
	log->l_mxfs_slice_snap = snap;
	log->l_mxfs_snap_bytes = bytes;
	log->l_mxfs_snap_unstable_seen = unstable;
	mxfs_xfs_probe(mp,
	"MXFS: P-FRSTAB-STABLE slot=%u passes=%d unstable_seen=%d wall_ms=%u — slice snapshot immutable; recovery reads now served from it",
		   log->l_mxfs_victim_slot, passes, unstable, wall_ms);
	return 0;
}

#ifdef DEBUG
/*
 * dump debug superblock and log record information
 */
STATIC void
xlog_header_check_dump(
	struct xfs_mount		*mp,
	struct xlog_rec_header		*head)
{
	xfs_debug(mp, "%s:  SB : uuid = %pU, fmt = %d",
		__func__, &mp->m_sb.sb_uuid, XLOG_FMT);
	xfs_debug(mp, "    log : uuid = %pU, fmt = %d",
		&head->h_fs_uuid, be32_to_cpu(head->h_fmt));
}
#else
#define xlog_header_check_dump(mp, head)
#endif

/*
 * check log record header for recovery
 */
STATIC int
xlog_header_check_recover(
	struct xfs_mount	*mp,
	struct xlog_rec_header	*head)
{
	ASSERT(head->h_magicno == cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM));

	/*
	 * IRIX doesn't write the h_fmt field and leaves it zeroed
	 * (XLOG_FMT_UNKNOWN). This stops us from trying to recover
	 * a dirty log created in IRIX.
	 */
	if (XFS_IS_CORRUPT(mp, head->h_fmt != cpu_to_be32(XLOG_FMT))) {
		xfs_warn(mp,
	"dirty log written in incompatible format - can't recover");
		xlog_header_check_dump(mp, head);
		return -EFSCORRUPTED;
	}
	if (XFS_IS_CORRUPT(mp, !uuid_equal(&mp->m_sb.sb_uuid,
					   &head->h_fs_uuid))) {
		xfs_warn(mp,
	"dirty log entry has mismatched uuid - can't recover");
		xlog_header_check_dump(mp, head);
		return -EFSCORRUPTED;
	}
	return 0;
}

/*
 * read the head block of the log and check the header
 */
STATIC int
xlog_header_check_mount(
	struct xfs_mount	*mp,
	struct xlog_rec_header	*head)
{
	ASSERT(head->h_magicno == cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM));

	if (uuid_is_null(&head->h_fs_uuid)) {
		/*
		 * IRIX doesn't write the h_fs_uuid or h_fmt fields. If
		 * h_fs_uuid is null, we assume this log was last mounted
		 * by IRIX and continue.
		 */
		xfs_warn(mp, "null uuid in log - IRIX style log");
	} else if (XFS_IS_CORRUPT(mp, !uuid_equal(&mp->m_sb.sb_uuid,
						  &head->h_fs_uuid))) {
		xfs_warn(mp, "log has mismatched uuid - can't recover");
		xlog_header_check_dump(mp, head);
		return -EFSCORRUPTED;
	}
	return 0;
}

/*
 * This routine finds (to an approximation) the first block in the physical
 * log which contains the given cycle.  It uses a binary search algorithm.
 * Note that the algorithm can not be perfect because the disk will not
 * necessarily be perfect.
 */
STATIC int
xlog_find_cycle_start(
	struct xlog	*log,
	char		*buffer,
	xfs_daddr_t	first_blk,
	xfs_daddr_t	*last_blk,
	uint		cycle)
{
	char		*offset;
	xfs_daddr_t	mid_blk;
	xfs_daddr_t	end_blk;
	uint		mid_cycle;
	int		error;

	end_blk = *last_blk;
	mid_blk = BLK_AVG(first_blk, end_blk);
	while (mid_blk != first_blk && mid_blk != end_blk) {
		error = xlog_bread(log, mid_blk, 1, buffer, &offset);
		if (error)
			return error;
		mid_cycle = xlog_get_cycle(offset);
		if (mid_cycle == cycle)
			end_blk = mid_blk;   /* last_half_cycle == mid_cycle */
		else
			first_blk = mid_blk; /* first_half_cycle == mid_cycle */
		mid_blk = BLK_AVG(first_blk, end_blk);
	}
	ASSERT((mid_blk == first_blk && mid_blk+1 == end_blk) ||
	       (mid_blk == end_blk && mid_blk-1 == first_blk));

	*last_blk = end_blk;

	return 0;
}

/*
 * Check that a range of blocks does not contain stop_on_cycle_no.
 * Fill in *new_blk with the block offset where such a block is
 * found, or with -1 (an invalid block number) if there is no such
 * block in the range.  The scan needs to occur from front to back
 * and the pointer into the region must be updated since a later
 * routine will need to perform another test.
 */
STATIC int
xlog_find_verify_cycle(
	struct xlog	*log,
	xfs_daddr_t	start_blk,
	int		nbblks,
	uint		stop_on_cycle_no,
	xfs_daddr_t	*new_blk)
{
	xfs_daddr_t	i, j;
	uint		cycle;
	char		*buffer;
	xfs_daddr_t	bufblks;
	char		*buf = NULL;
	int		error = 0;

	/*
	 * Greedily allocate a buffer big enough to handle the full
	 * range of basic blocks we'll be examining.  If that fails,
	 * try a smaller size.  We need to be able to read at least
	 * a log sector, or we're out of luck.
	 */
	bufblks = roundup_pow_of_two(nbblks);
	while (bufblks > log->l_logBBsize)
		bufblks >>= 1;
	while (!(buffer = xlog_alloc_buffer(log, bufblks))) {
		bufblks >>= 1;
		if (bufblks < log->l_sectBBsize)
			return -ENOMEM;
	}

	for (i = start_blk; i < start_blk + nbblks; i += bufblks) {
		int	bcount;

		bcount = min(bufblks, (start_blk + nbblks - i));

		error = xlog_bread(log, i, bcount, buffer, &buf);
		if (error)
			goto out;

		for (j = 0; j < bcount; j++) {
			cycle = xlog_get_cycle(buf);
			if (cycle == stop_on_cycle_no) {
				*new_blk = i+j;
				goto out;
			}

			buf += BBSIZE;
		}
	}

	*new_blk = -1;

out:
	kvfree(buffer);
	return error;
}

static inline int
xlog_logrec_hblks(struct xlog *log, struct xlog_rec_header *rh)
{
	if (xfs_has_logv2(log->l_mp)) {
		int	h_size = be32_to_cpu(rh->h_size);

		if ((be32_to_cpu(rh->h_version) & XLOG_VERSION_2) &&
		    h_size > XLOG_HEADER_CYCLE_SIZE)
			return DIV_ROUND_UP(h_size, XLOG_HEADER_CYCLE_SIZE);
	}
	return 1;
}

/*
 * Potentially backup over partial log record write.
 *
 * In the typical case, last_blk is the number of the block directly after
 * a good log record.  Therefore, we subtract one to get the block number
 * of the last block in the given buffer.  extra_bblks contains the number
 * of blocks we would have read on a previous read.  This happens when the
 * last log record is split over the end of the physical log.
 *
 * extra_bblks is the number of blocks potentially verified on a previous
 * call to this routine.
 */
STATIC int
xlog_find_verify_log_record(
	struct xlog		*log,
	xfs_daddr_t		start_blk,
	xfs_daddr_t		*last_blk,
	int			extra_bblks)
{
	xfs_daddr_t		i;
	char			*buffer;
	char			*offset = NULL;
	struct xlog_rec_header	*head = NULL;
	int			error = 0;
	int			smallmem = 0;
	int			num_blks = *last_blk - start_blk;
	int			xhdrs;

	ASSERT(start_blk != 0 || *last_blk != start_blk);

	buffer = xlog_alloc_buffer(log, num_blks);
	if (!buffer) {
		buffer = xlog_alloc_buffer(log, 1);
		if (!buffer)
			return -ENOMEM;
		smallmem = 1;
	} else {
		error = xlog_bread(log, start_blk, num_blks, buffer, &offset);
		if (error)
			goto out;
		offset += ((num_blks - 1) << BBSHIFT);
	}

	for (i = (*last_blk) - 1; i >= 0; i--) {
		if (i < start_blk) {
			/* valid log record not found */
			xfs_warn(log->l_mp,
		"Log inconsistent (didn't find previous header)");
			ASSERT(0);
			error = -EFSCORRUPTED;
			goto out;
		}

		if (smallmem) {
			error = xlog_bread(log, i, 1, buffer, &offset);
			if (error)
				goto out;
		}

		head = (struct xlog_rec_header *)offset;

		if (head->h_magicno == cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM))
			break;

		if (!smallmem)
			offset -= BBSIZE;
	}

	/*
	 * We hit the beginning of the physical log & still no header.  Return
	 * to caller.  If caller can handle a return of -1, then this routine
	 * will be called again for the end of the physical log.
	 */
	if (i == -1) {
		error = 1;
		goto out;
	}

	/*
	 * We have the final block of the good log (the first block
	 * of the log record _before_ the head. So we check the uuid.
	 */
	if ((error = xlog_header_check_mount(log->l_mp, head)))
		goto out;

	/*
	 * We may have found a log record header before we expected one.
	 * last_blk will be the 1st block # with a given cycle #.  We may end
	 * up reading an entire log record.  In this case, we don't want to
	 * reset last_blk.  Only when last_blk points in the middle of a log
	 * record do we update last_blk.
	 */
	xhdrs = xlog_logrec_hblks(log, head);

	if (*last_blk - i + extra_bblks !=
	    BTOBB(be32_to_cpu(head->h_len)) + xhdrs)
		*last_blk = i;

out:
	kvfree(buffer);
	return error;
}

/*
 * Head is defined to be the point of the log where the next log write
 * could go.  This means that incomplete LR writes at the end are
 * eliminated when calculating the head.  We aren't guaranteed that previous
 * LR have complete transactions.  We only know that a cycle number of
 * current cycle number -1 won't be present in the log if we start writing
 * from our current block number.
 *
 * last_blk contains the block number of the first block with a given
 * cycle number.
 *
 * Return: zero if normal, non-zero if error.
 */
STATIC int
xlog_find_head(
	struct xlog	*log,
	xfs_daddr_t	*return_head_blk)
{
	char		*buffer;
	char		*offset;
	xfs_daddr_t	new_blk, first_blk, start_blk, last_blk, head_blk;
	int		num_scan_bblks;
	uint		first_half_cycle, last_half_cycle;
	uint		stop_on_cycle;
	int		error, log_bbnum = log->l_logBBsize;

	/* Is the end of the log device zeroed? */
	error = xlog_find_zeroed(log, &first_blk);
	if (error < 0) {
		xfs_warn(log->l_mp, "empty log check failed");
		return error;
	}
	if (error == 1) {
		*return_head_blk = first_blk;

		/* Is the whole lot zeroed? */
		if (!first_blk) {
			/* Linux XFS shouldn't generate totally zeroed logs -
			 * mkfs etc write a dummy unmount record to a fresh
			 * log so we can store the uuid in there
			 */
			xfs_warn(log->l_mp, "totally zeroed log");
		}

		return 0;
	}

	first_blk = 0;			/* get cycle # of 1st block */
	buffer = xlog_alloc_buffer(log, 1);
	if (!buffer)
		return -ENOMEM;

	error = xlog_bread(log, 0, 1, buffer, &offset);
	if (error)
		goto out_free_buffer;

	first_half_cycle = xlog_get_cycle(offset);

	last_blk = head_blk = log_bbnum - 1;	/* get cycle # of last block */
	error = xlog_bread(log, last_blk, 1, buffer, &offset);
	if (error)
		goto out_free_buffer;

	last_half_cycle = xlog_get_cycle(offset);
	ASSERT(last_half_cycle != 0);

	/*
	 * If the 1st half cycle number is equal to the last half cycle number,
	 * then the entire log is stamped with the same cycle number.  In this
	 * case, head_blk can't be set to zero (which makes sense).  The below
	 * math doesn't work out properly with head_blk equal to zero.  Instead,
	 * we set it to log_bbnum which is an invalid block number, but this
	 * value makes the math correct.  If head_blk doesn't changed through
	 * all the tests below, *head_blk is set to zero at the very end rather
	 * than log_bbnum.  In a sense, log_bbnum and zero are the same block
	 * in a circular file.
	 */
	if (first_half_cycle == last_half_cycle) {
		/*
		 * In this case we believe that the entire log should have
		 * cycle number last_half_cycle.  We need to scan backwards
		 * from the end verifying that there are no holes still
		 * containing last_half_cycle - 1.  If we find such a hole,
		 * then the start of that hole will be the new head.  The
		 * simple case looks like
		 *        x | x ... | x - 1 | x
		 * Another case that fits this picture would be
		 *        x | x + 1 | x ... | x
		 * In this case the head really is somewhere at the end of the
		 * log, as one of the latest writes at the beginning was
		 * incomplete.
		 * One more case is
		 *        x | x + 1 | x ... | x - 1 | x
		 * This is really the combination of the above two cases, and
		 * the head has to end up at the start of the x-1 hole at the
		 * end of the log.
		 *
		 * In the 256k log case, we will read from the beginning to the
		 * end of the log and search for cycle numbers equal to x-1.
		 * We don't worry about the x+1 blocks that we encounter,
		 * because we know that they cannot be the head since the log
		 * started with x.
		 */
		head_blk = log_bbnum;
		stop_on_cycle = last_half_cycle - 1;
	} else {
		/*
		 * In this case we want to find the first block with cycle
		 * number matching last_half_cycle.  We expect the log to be
		 * some variation on
		 *        x + 1 ... | x ... | x
		 * The first block with cycle number x (last_half_cycle) will
		 * be where the new head belongs.  First we do a binary search
		 * for the first occurrence of last_half_cycle.  The binary
		 * search may not be totally accurate, so then we scan back
		 * from there looking for occurrences of last_half_cycle before
		 * us.  If that backwards scan wraps around the beginning of
		 * the log, then we look for occurrences of last_half_cycle - 1
		 * at the end of the log.  The cases we're looking for look
		 * like
		 *                               v binary search stopped here
		 *        x + 1 ... | x | x + 1 | x ... | x
		 *                   ^ but we want to locate this spot
		 * or
		 *        <---------> less than scan distance
		 *        x + 1 ... | x ... | x - 1 | x
		 *                           ^ we want to locate this spot
		 */
		stop_on_cycle = last_half_cycle;
		error = xlog_find_cycle_start(log, buffer, first_blk, &head_blk,
				last_half_cycle);
		if (error)
			goto out_free_buffer;
	}

	/*
	 * Now validate the answer.  Scan back some number of maximum possible
	 * blocks and make sure each one has the expected cycle number.  The
	 * maximum is determined by the total possible amount of buffering
	 * in the in-core log.  The following number can be made tighter if
	 * we actually look at the block size of the filesystem.
	 */
	num_scan_bblks = min_t(int, log_bbnum, XLOG_TOTAL_REC_SHIFT(log));
	if (head_blk >= num_scan_bblks) {
		/*
		 * We are guaranteed that the entire check can be performed
		 * in one buffer.
		 */
		start_blk = head_blk - num_scan_bblks;
		if ((error = xlog_find_verify_cycle(log,
						start_blk, num_scan_bblks,
						stop_on_cycle, &new_blk)))
			goto out_free_buffer;
		if (new_blk != -1)
			head_blk = new_blk;
	} else {		/* need to read 2 parts of log */
		/*
		 * We are going to scan backwards in the log in two parts.
		 * First we scan the physical end of the log.  In this part
		 * of the log, we are looking for blocks with cycle number
		 * last_half_cycle - 1.
		 * If we find one, then we know that the log starts there, as
		 * we've found a hole that didn't get written in going around
		 * the end of the physical log.  The simple case for this is
		 *        x + 1 ... | x ... | x - 1 | x
		 *        <---------> less than scan distance
		 * If all of the blocks at the end of the log have cycle number
		 * last_half_cycle, then we check the blocks at the start of
		 * the log looking for occurrences of last_half_cycle.  If we
		 * find one, then our current estimate for the location of the
		 * first occurrence of last_half_cycle is wrong and we move
		 * back to the hole we've found.  This case looks like
		 *        x + 1 ... | x | x + 1 | x ...
		 *                               ^ binary search stopped here
		 * Another case we need to handle that only occurs in 256k
		 * logs is
		 *        x + 1 ... | x ... | x+1 | x ...
		 *                   ^ binary search stops here
		 * In a 256k log, the scan at the end of the log will see the
		 * x + 1 blocks.  We need to skip past those since that is
		 * certainly not the head of the log.  By searching for
		 * last_half_cycle-1 we accomplish that.
		 */
		ASSERT(head_blk <= INT_MAX &&
			(xfs_daddr_t) num_scan_bblks >= head_blk);
		start_blk = log_bbnum - (num_scan_bblks - head_blk);
		if ((error = xlog_find_verify_cycle(log, start_blk,
					num_scan_bblks - (int)head_blk,
					(stop_on_cycle - 1), &new_blk)))
			goto out_free_buffer;
		if (new_blk != -1) {
			head_blk = new_blk;
			goto validate_head;
		}

		/*
		 * Scan beginning of log now.  The last part of the physical
		 * log is good.  This scan needs to verify that it doesn't find
		 * the last_half_cycle.
		 */
		start_blk = 0;
		ASSERT(head_blk <= INT_MAX);
		if ((error = xlog_find_verify_cycle(log,
					start_blk, (int)head_blk,
					stop_on_cycle, &new_blk)))
			goto out_free_buffer;
		if (new_blk != -1)
			head_blk = new_blk;
	}

validate_head:
	/*
	 * Now we need to make sure head_blk is not pointing to a block in
	 * the middle of a log record.
	 */
	num_scan_bblks = XLOG_REC_SHIFT(log);
	if (head_blk >= num_scan_bblks) {
		start_blk = head_blk - num_scan_bblks; /* don't read head_blk */

		/* start ptr at last block ptr before head_blk */
		error = xlog_find_verify_log_record(log, start_blk, &head_blk, 0);
		if (error == 1)
			error = -EIO;
		if (error)
			goto out_free_buffer;
	} else {
		start_blk = 0;
		ASSERT(head_blk <= INT_MAX);
		error = xlog_find_verify_log_record(log, start_blk, &head_blk, 0);
		if (error < 0)
			goto out_free_buffer;
		if (error == 1) {
			/* We hit the beginning of the log during our search */
			start_blk = log_bbnum - (num_scan_bblks - head_blk);
			new_blk = log_bbnum;
			ASSERT(start_blk <= INT_MAX &&
				(xfs_daddr_t) log_bbnum-start_blk >= 0);
			ASSERT(head_blk <= INT_MAX);
			error = xlog_find_verify_log_record(log, start_blk,
							&new_blk, (int)head_blk);
			if (error == 1)
				error = -EIO;
			if (error)
				goto out_free_buffer;
			if (new_blk != log_bbnum)
				head_blk = new_blk;
		} else if (error)
			goto out_free_buffer;
	}

	kvfree(buffer);
	if (head_blk == log_bbnum)
		*return_head_blk = 0;
	else
		*return_head_blk = head_blk;
	/*
	 * When returning here, we have a good block number.  Bad block
	 * means that during a previous crash, we didn't have a clean break
	 * from cycle number N to cycle number N-1.  In this case, we need
	 * to find the first block with cycle number N-1.
	 */
	return 0;

out_free_buffer:
	kvfree(buffer);
	if (error)
		xfs_warn(log->l_mp, "failed to find log head");
	return error;
}

/*
 * Seek backwards in the log for log record headers.
 *
 * Given a starting log block, walk backwards until we find the provided number
 * of records or hit the provided tail block. The return value is the number of
 * records encountered or a negative error code. The log block and buffer
 * pointer of the last record seen are returned in rblk and rhead respectively.
 */
STATIC int
xlog_rseek_logrec_hdr(
	struct xlog		*log,
	xfs_daddr_t		head_blk,
	xfs_daddr_t		tail_blk,
	int			count,
	char			*buffer,
	xfs_daddr_t		*rblk,
	struct xlog_rec_header	**rhead,
	bool			*wrapped)
{
	int			i;
	int			error;
	int			found = 0;
	char			*offset = NULL;
	xfs_daddr_t		end_blk;

	*wrapped = false;

	/*
	 * Walk backwards from the head block until we hit the tail or the first
	 * block in the log.
	 */
	end_blk = head_blk > tail_blk ? tail_blk : 0;
	for (i = (int) head_blk - 1; i >= end_blk; i--) {
		error = xlog_bread(log, i, 1, buffer, &offset);
		if (error)
			goto out_error;

		if (*(__be32 *) offset == cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM)) {
			*rblk = i;
			*rhead = (struct xlog_rec_header *) offset;
			if (++found == count)
				break;
		}
	}

	/*
	 * If we haven't hit the tail block or the log record header count,
	 * start looking again from the end of the physical log. Note that
	 * callers can pass head == tail if the tail is not yet known.
	 */
	if (tail_blk >= head_blk && found != count) {
		for (i = log->l_logBBsize - 1; i >= (int) tail_blk; i--) {
			error = xlog_bread(log, i, 1, buffer, &offset);
			if (error)
				goto out_error;

			if (*(__be32 *)offset ==
			    cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM)) {
				*wrapped = true;
				*rblk = i;
				*rhead = (struct xlog_rec_header *) offset;
				if (++found == count)
					break;
			}
		}
	}

	return found;

out_error:
	return error;
}

/*
 * Seek forward in the log for log record headers.
 *
 * Given head and tail blocks, walk forward from the tail block until we find
 * the provided number of records or hit the head block. The return value is the
 * number of records encountered or a negative error code. The log block and
 * buffer pointer of the last record seen are returned in rblk and rhead
 * respectively.
 */
STATIC int
xlog_seek_logrec_hdr(
	struct xlog		*log,
	xfs_daddr_t		head_blk,
	xfs_daddr_t		tail_blk,
	int			count,
	char			*buffer,
	xfs_daddr_t		*rblk,
	struct xlog_rec_header	**rhead,
	bool			*wrapped)
{
	int			i;
	int			error;
	int			found = 0;
	char			*offset = NULL;
	xfs_daddr_t		end_blk;

	*wrapped = false;

	/*
	 * Walk forward from the tail block until we hit the head or the last
	 * block in the log.
	 */
	end_blk = head_blk > tail_blk ? head_blk : log->l_logBBsize - 1;
	for (i = (int) tail_blk; i <= end_blk; i++) {
		error = xlog_bread(log, i, 1, buffer, &offset);
		if (error)
			goto out_error;

		if (*(__be32 *) offset == cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM)) {
			*rblk = i;
			*rhead = (struct xlog_rec_header *) offset;
			if (++found == count)
				break;
		}
	}

	/*
	 * If we haven't hit the head block or the log record header count,
	 * start looking again from the start of the physical log.
	 */
	if (tail_blk > head_blk && found != count) {
		for (i = 0; i < (int) head_blk; i++) {
			error = xlog_bread(log, i, 1, buffer, &offset);
			if (error)
				goto out_error;

			if (*(__be32 *)offset ==
			    cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM)) {
				*wrapped = true;
				*rblk = i;
				*rhead = (struct xlog_rec_header *) offset;
				if (++found == count)
					break;
			}
		}
	}

	return found;

out_error:
	return error;
}

/*
 * Calculate distance from head to tail (i.e., unused space in the log).
 */
static inline int
xlog_tail_distance(
	struct xlog	*log,
	xfs_daddr_t	head_blk,
	xfs_daddr_t	tail_blk)
{
	if (head_blk < tail_blk)
		return tail_blk - head_blk;

	return tail_blk + (log->l_logBBsize - head_blk);
}

/*
 * Verify the log tail. This is particularly important when torn or incomplete
 * writes have been detected near the front of the log and the head has been
 * walked back accordingly.
 *
 * We also have to handle the case where the tail was pinned and the head
 * blocked behind the tail right before a crash. If the tail had been pushed
 * immediately prior to the crash and the subsequent checkpoint was only
 * partially written, it's possible it overwrote the last referenced tail in the
 * log with garbage. This is not a coherency problem because the tail must have
 * been pushed before it can be overwritten, but appears as log corruption to
 * recovery because we have no way to know the tail was updated if the
 * subsequent checkpoint didn't write successfully.
 *
 * Therefore, CRC check the log from tail to head. If a failure occurs and the
 * offending record is within max iclog bufs from the head, walk the tail
 * forward and retry until a valid tail is found or corruption is detected out
 * of the range of a possible overwrite.
 */
STATIC int
xlog_verify_tail(
	struct xlog		*log,
	xfs_daddr_t		head_blk,
	xfs_daddr_t		*tail_blk,
	int			hsize)
{
	struct xlog_rec_header	*thead;
	char			*buffer;
	xfs_daddr_t		first_bad;
	int			error = 0;
	bool			wrapped;
	xfs_daddr_t		tmp_tail;
	xfs_daddr_t		orig_tail = *tail_blk;

	buffer = xlog_alloc_buffer(log, 1);
	if (!buffer)
		return -ENOMEM;

	/*
	 * Make sure the tail points to a record (returns positive count on
	 * success).
	 */
	error = xlog_seek_logrec_hdr(log, head_blk, *tail_blk, 1, buffer,
			&tmp_tail, &thead, &wrapped);
	if (error < 0)
		goto out;
	if (*tail_blk != tmp_tail)
		*tail_blk = tmp_tail;

	/*
	 * Run a CRC check from the tail to the head. We can't just check
	 * MAX_ICLOGS records past the tail because the tail may point to stale
	 * blocks cleared during the search for the head/tail. These blocks are
	 * overwritten with zero-length records and thus record count is not a
	 * reliable indicator of the iclog state before a crash.
	 */
	first_bad = 0;
	error = xlog_do_recovery_pass(log, head_blk, *tail_blk,
				      XLOG_RECOVER_CRCPASS, &first_bad);
	while ((error == -EFSBADCRC || error == -EFSCORRUPTED) && first_bad) {
		int	tail_distance;

		/*
		 * Is corruption within range of the head? If so, retry from
		 * the next record. Otherwise return an error.
		 */
		tail_distance = xlog_tail_distance(log, head_blk, first_bad);
		if (tail_distance > BTOBB(XLOG_MAX_ICLOGS * hsize))
			break;

		/* skip to the next record; returns positive count on success */
		error = xlog_seek_logrec_hdr(log, head_blk, first_bad, 2,
				buffer, &tmp_tail, &thead, &wrapped);
		if (error < 0)
			goto out;

		*tail_blk = tmp_tail;
		first_bad = 0;
		error = xlog_do_recovery_pass(log, head_blk, *tail_blk,
					      XLOG_RECOVER_CRCPASS, &first_bad);
	}

	if (!error && *tail_blk != orig_tail)
		xfs_warn(log->l_mp,
		"Tail block (0x%llx) overwrite detected. Updated to 0x%llx",
			 orig_tail, *tail_blk);
out:
	kvfree(buffer);
	return error;
}

/*
 * Detect and trim torn writes from the head of the log.
 *
 * Storage without sector atomicity guarantees can result in torn writes in the
 * log in the event of a crash. Our only means to detect this scenario is via
 * CRC verification. While we can't always be certain that CRC verification
 * failure is due to a torn write vs. an unrelated corruption, we do know that
 * only a certain number (XLOG_MAX_ICLOGS) of log records can be written out at
 * one time. Therefore, CRC verify up to XLOG_MAX_ICLOGS records at the head of
 * the log and treat failures in this range as torn writes as a matter of
 * policy. In the event of CRC failure, the head is walked back to the last good
 * record in the log and the tail is updated from that record and verified.
 */
STATIC int
xlog_verify_head(
	struct xlog		*log,
	xfs_daddr_t		*head_blk,	/* in/out: unverified head */
	xfs_daddr_t		*tail_blk,	/* out: tail block */
	char			*buffer,
	xfs_daddr_t		*rhead_blk,	/* start blk of last record */
	struct xlog_rec_header	**rhead,	/* ptr to last record */
	bool			*wrapped)	/* last rec. wraps phys. log */
{
	struct xlog_rec_header	*tmp_rhead;
	char			*tmp_buffer;
	xfs_daddr_t		first_bad;
	xfs_daddr_t		tmp_rhead_blk;
	int			found;
	int			error;
	bool			tmp_wrapped;

	/*
	 * Check the head of the log for torn writes. Search backwards from the
	 * head until we hit the tail or the maximum number of log record I/Os
	 * that could have been in flight at one time. Use a temporary buffer so
	 * we don't trash the rhead/buffer pointers from the caller.
	 */
	tmp_buffer = xlog_alloc_buffer(log, 1);
	if (!tmp_buffer)
		return -ENOMEM;
	error = xlog_rseek_logrec_hdr(log, *head_blk, *tail_blk,
				      XLOG_MAX_ICLOGS, tmp_buffer,
				      &tmp_rhead_blk, &tmp_rhead, &tmp_wrapped);
	kvfree(tmp_buffer);
	if (error < 0)
		return error;

	/*
	 * Now run a CRC verification pass over the records starting at the
	 * block found above to the current head. If a CRC failure occurs, the
	 * log block of the first bad record is saved in first_bad.
	 */
	error = xlog_do_recovery_pass(log, *head_blk, tmp_rhead_blk,
				      XLOG_RECOVER_CRCPASS, &first_bad);
	if ((error == -EFSBADCRC || error == -EFSCORRUPTED) && first_bad) {
		/*
		 * We've hit a potential torn write. Reset the error and warn
		 * about it.
		 */
		error = 0;
		xfs_warn(log->l_mp,
"Torn write (CRC failure) detected at log block 0x%llx. Truncating head block from 0x%llx.",
			 first_bad, *head_blk);

		/*
		 * Get the header block and buffer pointer for the last good
		 * record before the bad record.
		 *
		 * Note that xlog_find_tail() clears the blocks at the new head
		 * (i.e., the records with invalid CRC) if the cycle number
		 * matches the current cycle.
		 */
		found = xlog_rseek_logrec_hdr(log, first_bad, *tail_blk, 1,
				buffer, rhead_blk, rhead, wrapped);
		if (found < 0)
			return found;
		if (found == 0)		/* XXX: right thing to do here? */
			return -EIO;

		/*
		 * Reset the head block to the starting block of the first bad
		 * log record and set the tail block based on the last good
		 * record.
		 *
		 * Bail out if the updated head/tail match as this indicates
		 * possible corruption outside of the acceptable
		 * (XLOG_MAX_ICLOGS) range. This is a job for xfs_repair...
		 */
		*head_blk = first_bad;
		*tail_blk = BLOCK_LSN(be64_to_cpu((*rhead)->h_tail_lsn));
		if (*head_blk == *tail_blk) {
			ASSERT(0);
			return 0;
		}
	}
	if (error)
		return error;

	return xlog_verify_tail(log, *head_blk, tail_blk,
				be32_to_cpu((*rhead)->h_size));
}

/*
 * We need to make sure we handle log wrapping properly, so we can't use the
 * calculated logbno directly. Make sure it wraps to the correct bno inside the
 * log.
 *
 * The log is limited to 32 bit sizes, so we use the appropriate modulus
 * operation here and cast it back to a 64 bit daddr on return.
 */
static inline xfs_daddr_t
xlog_wrap_logbno(
	struct xlog		*log,
	xfs_daddr_t		bno)
{
	int			mod;

	div_s64_rem(bno, log->l_logBBsize, &mod);
	return mod;
}

/*
 * Check whether the head of the log points to an unmount record. In other
 * words, determine whether the log is clean. If so, update the in-core state
 * appropriately.
 */
static int
xlog_check_unmount_rec(
	struct xlog		*log,
	xfs_daddr_t		*head_blk,
	xfs_daddr_t		*tail_blk,
	struct xlog_rec_header	*rhead,
	xfs_daddr_t		rhead_blk,
	char			*buffer,
	bool			*clean)
{
	struct xlog_op_header	*op_head;
	xfs_daddr_t		umount_data_blk;
	xfs_daddr_t		after_umount_blk;
	int			hblks;
	int			error;
	char			*offset;

	*clean = false;

	/*
	 * Look for unmount record. If we find it, then we know there was a
	 * clean unmount. Since 'i' could be the last block in the physical
	 * log, we convert to a log block before comparing to the head_blk.
	 *
	 * Save the current tail lsn to use to pass to xlog_clear_stale_blocks()
	 * below. We won't want to clear the unmount record if there is one, so
	 * we pass the lsn of the unmount record rather than the block after it.
	 */
	hblks = xlog_logrec_hblks(log, rhead);
	after_umount_blk = xlog_wrap_logbno(log,
			rhead_blk + hblks + BTOBB(be32_to_cpu(rhead->h_len)));

	if (*head_blk == after_umount_blk &&
	    be32_to_cpu(rhead->h_num_logops) == 1) {
		umount_data_blk = xlog_wrap_logbno(log, rhead_blk + hblks);
		error = xlog_bread(log, umount_data_blk, 1, buffer, &offset);
		if (error)
			return error;

		op_head = (struct xlog_op_header *)offset;
		if (op_head->oh_flags & XLOG_UNMOUNT_TRANS) {
			/*
			 * Set tail and last sync so that newly written log
			 * records will point recovery to after the current
			 * unmount record.
			 */
			xlog_assign_atomic_lsn(&log->l_tail_lsn,
					log->l_curr_cycle, after_umount_blk);
			log->l_ailp->ail_head_lsn =
					atomic64_read(&log->l_tail_lsn);
			*tail_blk = after_umount_blk;

			*clean = true;
		}
	}

	return 0;
}

static void
xlog_set_state(
	struct xlog		*log,
	xfs_daddr_t		head_blk,
	struct xlog_rec_header	*rhead,
	xfs_daddr_t		rhead_blk,
	bool			bump_cycle)
{
	/*
	 * Reset log values according to the state of the log when we
	 * crashed.  In the case where head_blk == 0, we bump curr_cycle
	 * one because the next write starts a new cycle rather than
	 * continuing the cycle of the last good log record.  At this
	 * point we have guaranteed that all partial log records have been
	 * accounted for.  Therefore, we know that the last good log record
	 * written was complete and ended exactly on the end boundary
	 * of the physical log.
	 */
	log->l_prev_block = rhead_blk;
	log->l_curr_block = (int)head_blk;
	log->l_curr_cycle = be32_to_cpu(rhead->h_cycle);
	if (bump_cycle)
		log->l_curr_cycle++;
	atomic64_set(&log->l_tail_lsn, be64_to_cpu(rhead->h_tail_lsn));
	log->l_ailp->ail_head_lsn = be64_to_cpu(rhead->h_lsn);
}

/*
 * Find the sync block number or the tail of the log.
 *
 * This will be the block number of the last record to have its
 * associated buffers synced to disk.  Every log record header has
 * a sync lsn embedded in it.  LSNs hold block numbers, so it is easy
 * to get a sync block number.  The only concern is to figure out which
 * log record header to believe.
 *
 * The following algorithm uses the log record header with the largest
 * lsn.  The entire log record does not need to be valid.  We only care
 * that the header is valid.
 *
 * We could speed up search by using current head_blk buffer, but it is not
 * available.
 */
STATIC int
xlog_find_tail(
	struct xlog		*log,
	xfs_daddr_t		*head_blk,
	xfs_daddr_t		*tail_blk)
{
	struct xlog_rec_header	*rhead;
	char			*offset = NULL;
	char			*buffer;
	int			error;
	xfs_daddr_t		rhead_blk;
	xfs_lsn_t		tail_lsn;
	bool			wrapped = false;
	bool			clean = false;

	/*
	 * Find previous log record
	 */
	if ((error = xlog_find_head(log, head_blk)))
		return error;
	ASSERT(*head_blk < INT_MAX);

	buffer = xlog_alloc_buffer(log, 1);
	if (!buffer)
		return -ENOMEM;
	if (*head_blk == 0) {				/* special case */
		error = xlog_bread(log, 0, 1, buffer, &offset);
		if (error)
			goto done;

		if (xlog_get_cycle(offset) == 0) {
			*tail_blk = 0;
			/* leave all other log inited values alone */
			/*
			 * mxfs: a freshly-mkfs'd log is zeroed (cycle 0 at
			 * block 0), so this fresh-log special case is taken
			 * and ail_head_lsn is left at 0.  l_tail_lsn was
			 * already seeded to 0x100000000 (cycle 1, block 0) in
			 * xlog_alloc_log, but ail_head_lsn was not.  The first
			 * CIL checkpoint commit then calls
			 * xlog_grant_return_space(old_head=0, new=cycle1_lsn);
			 * xlog_lsn_sub() sees hi_cycle(1) != lo_cycle(0), takes
			 * the cross-cycle branch, and the uint32 (lo_block -
			 * hi_block) underflows -> a garbage ~-4GB diff is fed
			 * to xlog_grant_sub_space(), which (atomic64_sub of a
			 * negative) ADDS ~4GB to the reservation grant.  Every
			 * subsequent log reservation then wedges forever in
			 * xlog_grant_head_wait (free_bytes clamped to 0).
			 * Upstream mkfs.xfs avoids this by stamping the log
			 * with cycle 1 + an unmount record so this path is not
			 * taken.  Seed ail_head_lsn to match l_tail_lsn so the
			 * first checkpoint computes a correct same-cycle diff.
			 */
			log->l_ailp->ail_head_lsn =
					atomic64_read(&log->l_tail_lsn);
			goto done;
		}
	}

	/*
	 * Search backwards through the log looking for the log record header
	 * block. This wraps all the way back around to the head so something is
	 * seriously wrong if we can't find it.
	 */
	error = xlog_rseek_logrec_hdr(log, *head_blk, *head_blk, 1, buffer,
				      &rhead_blk, &rhead, &wrapped);
	if (error < 0)
		goto done;
	if (!error) {
		xfs_warn(log->l_mp, "%s: couldn't find sync record", __func__);
		error = -EFSCORRUPTED;
		goto done;
	}
	*tail_blk = BLOCK_LSN(be64_to_cpu(rhead->h_tail_lsn));

	/*
	 * Set the log state based on the current head record.
	 */
	xlog_set_state(log, *head_blk, rhead, rhead_blk, wrapped);
	tail_lsn = atomic64_read(&log->l_tail_lsn);

	/*
	 * Look for an unmount record at the head of the log. This sets the log
	 * state to determine whether recovery is necessary.
	 */
	error = xlog_check_unmount_rec(log, head_blk, tail_blk, rhead,
				       rhead_blk, buffer, &clean);
	if (error)
		goto done;

	/*
	 * Verify the log head if the log is not clean (e.g., we have anything
	 * but an unmount record at the head). This uses CRC verification to
	 * detect and trim torn writes. If discovered, CRC failures are
	 * considered torn writes and the log head is trimmed accordingly.
	 *
	 * Note that we can only run CRC verification when the log is dirty
	 * because there's no guarantee that the log data behind an unmount
	 * record is compatible with the current architecture.
	 */
	if (!clean) {
		xfs_daddr_t	orig_head = *head_blk;

		error = xlog_verify_head(log, head_blk, tail_blk, buffer,
					 &rhead_blk, &rhead, &wrapped);
		if (error)
			goto done;

		/* update in-core state again if the head changed */
		if (*head_blk != orig_head) {
			xlog_set_state(log, *head_blk, rhead, rhead_blk,
				       wrapped);
			tail_lsn = atomic64_read(&log->l_tail_lsn);
			error = xlog_check_unmount_rec(log, head_blk, tail_blk,
						       rhead, rhead_blk, buffer,
						       &clean);
			if (error)
				goto done;
		}
	}

	/*
	 * Note that the unmount was clean. If the unmount was not clean, we
	 * need to know this to rebuild the superblock counters from the perag
	 * headers if we have a filesystem using non-persistent counters.
	 */
	if (clean)
		xfs_set_clean(log->l_mp);

	/*
	 * (D-0354 lap 2 diagnostics): the replay window geometry this
	 * mount / foreign replay will use.  tail_blk comes from the head
	 * record's own h_tail_lsn (or the block after an unmount record when
	 * the log is clean); a tail at or before a PREVIOUS incarnation's last
	 * record is exactly the hazard the P308 incarnation boundary closes.
	 */
	if (log->l_mp->m_mxfs_dlm)
		mxfs_xfs_probe(log->l_mp,
	"MXFS: P309-LOGTAIL %s head_blk=%lld tail_blk=%lld tail_lsn=0x%llx head_rec_lsn=0x%llx cycle=%d clean=%d",
			   xlog_is_mxfs_foreign_replay(log) ? "foreign" :
			   xlog_is_mxfs_adopted_slice(log) ? "adopted" : "own",
			   (long long)*head_blk, (long long)*tail_blk,
			   (unsigned long long)atomic64_read(&log->l_tail_lsn),
			   (unsigned long long)log->l_ailp->ail_head_lsn,
			   log->l_curr_cycle, clean ? 1 : 0);

	/*
	 * Make sure that there are no blocks in front of the head
	 * with the same cycle number as the head.  This can happen
	 * because we allow multiple outstanding log writes concurrently,
	 * and the later writes might make it out before earlier ones.
	 *
	 * We use the lsn from before modifying it so that we'll never
	 * overwrite the unmount record after a clean unmount.
	 *
	 * Do this only if we are going to recover the filesystem
	 *
	 * NOTE: This used to say "if (!readonly)"
	 * However on Linux, we can & do recover a read-only filesystem.
	 * We only skip recovery if NORECOVERY is specified on mount,
	 * in which case we would not be here.
	 *
	 * But... if the -device- itself is readonly, just skip this.
	 * We can't recover this device anyway, so it won't matter.
	 */
	if (!xfs_readonly_buftarg(log->l_targ))
		error = xlog_clear_stale_blocks(log, tail_lsn);

done:
	kvfree(buffer);

	if (error)
		xfs_warn(log->l_mp, "failed to locate log tail");
	return error;
}

/*
 * Is the log zeroed at all?
 *
 * The last binary search should be changed to perform an X block read
 * once X becomes small enough.  You can then search linearly through
 * the X blocks.  This will cut down on the number of reads we need to do.
 *
 * If the log is partially zeroed, this routine will pass back the blkno
 * of the first block with cycle number 0.  It won't have a complete LR
 * preceding it.
 *
 * Return:
 *	0  => the log is completely written to
 *	1 => use *blk_no as the first block of the log
 *	<0 => error has occurred
 */
STATIC int
xlog_find_zeroed(
	struct xlog	*log,
	xfs_daddr_t	*blk_no)
{
	char		*buffer;
	char		*offset;
	uint	        first_cycle, last_cycle;
	xfs_daddr_t	new_blk, last_blk, start_blk;
	xfs_daddr_t     num_scan_bblks;
	int	        error, log_bbnum = log->l_logBBsize;
	int		ret = 1;

	*blk_no = 0;

	/* check totally zeroed log */
	buffer = xlog_alloc_buffer(log, 1);
	if (!buffer)
		return -ENOMEM;
	error = xlog_bread(log, 0, 1, buffer, &offset);
	if (error)
		goto out_free_buffer;

	first_cycle = xlog_get_cycle(offset);
	if (first_cycle == 0) {		/* completely zeroed log */
		*blk_no = 0;
		goto out_free_buffer;
	}

	/* check partially zeroed log */
	error = xlog_bread(log, log_bbnum-1, 1, buffer, &offset);
	if (error)
		goto out_free_buffer;

	last_cycle = xlog_get_cycle(offset);
	if (last_cycle != 0) {		/* log completely written to */
		ret = 0;
		goto out_free_buffer;
	}

	/* we have a partially zeroed log */
	last_blk = log_bbnum-1;
	error = xlog_find_cycle_start(log, buffer, 0, &last_blk, 0);
	if (error)
		goto out_free_buffer;

	/*
	 * Validate the answer.  Because there is no way to guarantee that
	 * the entire log is made up of log records which are the same size,
	 * we scan over the defined maximum blocks.  At this point, the maximum
	 * is not chosen to mean anything special.   XXXmiken
	 */
	num_scan_bblks = XLOG_TOTAL_REC_SHIFT(log);
	ASSERT(num_scan_bblks <= INT_MAX);

	if (last_blk < num_scan_bblks)
		num_scan_bblks = last_blk;
	start_blk = last_blk - num_scan_bblks;

	/*
	 * We search for any instances of cycle number 0 that occur before
	 * our current estimate of the head.  What we're trying to detect is
	 *        1 ... | 0 | 1 | 0...
	 *                       ^ binary search ends here
	 */
	if ((error = xlog_find_verify_cycle(log, start_blk,
					 (int)num_scan_bblks, 0, &new_blk)))
		goto out_free_buffer;
	if (new_blk != -1)
		last_blk = new_blk;

	/*
	 * Potentially backup over partial log record write.  We don't need
	 * to search the end of the log because we know it is zero.
	 */
	error = xlog_find_verify_log_record(log, start_blk, &last_blk, 0);
	if (error == 1)
		error = -EIO;
	if (error)
		goto out_free_buffer;

	*blk_no = last_blk;
out_free_buffer:
	kvfree(buffer);
	if (error)
		return error;
	return ret;
}

/*
 * These are simple subroutines used by xlog_clear_stale_blocks() below
 * to initialize a buffer full of empty log record headers and write
 * them into the log.
 */
STATIC void
xlog_add_record(
	struct xlog		*log,
	char			*buf,
	int			cycle,
	int			block,
	int			tail_cycle,
	int			tail_block)
{
	struct xlog_rec_header	*recp = (struct xlog_rec_header *)buf;

	memset(buf, 0, BBSIZE);
	recp->h_magicno = cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM);
	recp->h_cycle = cpu_to_be32(cycle);
	recp->h_version = cpu_to_be32(
			xfs_has_logv2(log->l_mp) ? 2 : 1);
	recp->h_lsn = cpu_to_be64(xlog_assign_lsn(cycle, block));
	recp->h_tail_lsn = cpu_to_be64(xlog_assign_lsn(tail_cycle, tail_block));
	recp->h_fmt = cpu_to_be32(XLOG_FMT);
	memcpy(&recp->h_fs_uuid, &log->l_mp->m_sb.sb_uuid, sizeof(uuid_t));
}

STATIC int
xlog_write_log_records(
	struct xlog	*log,
	int		cycle,
	int		start_block,
	int		blocks,
	int		tail_cycle,
	int		tail_block)
{
	char		*offset;
	char		*buffer;
	int		balign, ealign;
	int		sectbb = log->l_sectBBsize;
	int		end_block = start_block + blocks;
	int		bufblks;
	int		error = 0;
	int		i, j = 0;

	/*
	 * Greedily allocate a buffer big enough to handle the full
	 * range of basic blocks to be written.  If that fails, try
	 * a smaller size.  We need to be able to write at least a
	 * log sector, or we're out of luck.
	 */
	bufblks = roundup_pow_of_two(blocks);
	while (bufblks > log->l_logBBsize)
		bufblks >>= 1;
	while (!(buffer = xlog_alloc_buffer(log, bufblks))) {
		bufblks >>= 1;
		if (bufblks < sectbb)
			return -ENOMEM;
	}

	/* We may need to do a read at the start to fill in part of
	 * the buffer in the starting sector not covered by the first
	 * write below.
	 */
	balign = round_down(start_block, sectbb);
	if (balign != start_block) {
		error = xlog_bread_noalign(log, start_block, 1, buffer);
		if (error)
			goto out_free_buffer;

		j = start_block - balign;
	}

	for (i = start_block; i < end_block; i += bufblks) {
		int		bcount, endcount;

		bcount = min(bufblks, end_block - start_block);
		endcount = bcount - j;

		/* We may need to do a read at the end to fill in part of
		 * the buffer in the final sector not covered by the write.
		 * If this is the same sector as the above read, skip it.
		 */
		ealign = round_down(end_block, sectbb);
		if (j == 0 && (start_block + endcount > ealign)) {
			error = xlog_bread_noalign(log, ealign, sectbb,
					buffer + BBTOB(ealign - start_block));
			if (error)
				break;

		}

		offset = buffer + xlog_align(log, start_block);
		for (; j < endcount; j++) {
			xlog_add_record(log, offset, cycle, i+j,
					tail_cycle, tail_block);
			offset += BBSIZE;
		}
		error = xlog_bwrite(log, start_block, endcount, buffer);
		if (error)
			break;
		start_block += endcount;
		j = 0;
	}

out_free_buffer:
	kvfree(buffer);
	return error;
}

/*
 * This routine is called to blow away any incomplete log writes out
 * in front of the log head.  We do this so that we won't become confused
 * if we come up, write only a little bit more, and then crash again.
 * If we leave the partial log records out there, this situation could
 * cause us to think those partial writes are valid blocks since they
 * have the current cycle number.  We get rid of them by overwriting them
 * with empty log records with the old cycle number rather than the
 * current one.
 *
 * The tail lsn is passed in rather than taken from
 * the log so that we will not write over the unmount record after a
 * clean unmount in a 512 block log.  Doing so would leave the log without
 * any valid log records in it until a new one was written.  If we crashed
 * during that time we would not be able to recover.
 */
STATIC int
xlog_clear_stale_blocks(
	struct xlog	*log,
	xfs_lsn_t	tail_lsn)
{
	int		tail_cycle, head_cycle;
	int		tail_block, head_block;
	int		tail_distance, max_distance;
	int		distance;
	int		error;

	tail_cycle = CYCLE_LSN(tail_lsn);
	tail_block = BLOCK_LSN(tail_lsn);
	head_cycle = log->l_curr_cycle;
	head_block = log->l_curr_block;

	/*
	 * Figure out the distance between the new head of the log
	 * and the tail.  We want to write over any blocks beyond the
	 * head that we may have written just before the crash, but
	 * we don't want to overwrite the tail of the log.
	 */
	if (head_cycle == tail_cycle) {
		/*
		 * The tail is behind the head in the physical log,
		 * so the distance from the head to the tail is the
		 * distance from the head to the end of the log plus
		 * the distance from the beginning of the log to the
		 * tail.
		 */
		if (XFS_IS_CORRUPT(log->l_mp,
				   head_block < tail_block ||
				   head_block >= log->l_logBBsize))
			return -EFSCORRUPTED;
		tail_distance = tail_block + (log->l_logBBsize - head_block);
	} else {
		/*
		 * The head is behind the tail in the physical log,
		 * so the distance from the head to the tail is just
		 * the tail block minus the head block.
		 */
		if (XFS_IS_CORRUPT(log->l_mp,
				   head_block >= tail_block ||
				   head_cycle != tail_cycle + 1))
			return -EFSCORRUPTED;
		tail_distance = tail_block - head_block;
	}

	/*
	 * If the head is right up against the tail, we can't clear
	 * anything.
	 */
	if (tail_distance <= 0) {
		ASSERT(tail_distance == 0);
		return 0;
	}

	max_distance = XLOG_TOTAL_REC_SHIFT(log);
	/*
	 * Take the smaller of the maximum amount of outstanding I/O
	 * we could have and the distance to the tail to clear out.
	 * We take the smaller so that we don't overwrite the tail and
	 * we don't waste all day writing from the head to the tail
	 * for no reason.
	 */
	max_distance = min(max_distance, tail_distance);

	if ((head_block + max_distance) <= log->l_logBBsize) {
		/*
		 * We can stomp all the blocks we need to without
		 * wrapping around the end of the log.  Just do it
		 * in a single write.  Use the cycle number of the
		 * current cycle minus one so that the log will look like:
		 *     n ... | n - 1 ...
		 */
		error = xlog_write_log_records(log, (head_cycle - 1),
				head_block, max_distance, tail_cycle,
				tail_block);
		if (error)
			return error;
	} else {
		/*
		 * We need to wrap around the end of the physical log in
		 * order to clear all the blocks.  Do it in two separate
		 * I/Os.  The first write should be from the head to the
		 * end of the physical log, and it should use the current
		 * cycle number minus one just like above.
		 */
		distance = log->l_logBBsize - head_block;
		error = xlog_write_log_records(log, (head_cycle - 1),
				head_block, distance, tail_cycle,
				tail_block);

		if (error)
			return error;

		/*
		 * Now write the blocks at the start of the physical log.
		 * This writes the remainder of the blocks we want to clear.
		 * It uses the current cycle number since we're now on the
		 * same cycle as the head so that we get:
		 *    n ... n ... | n - 1 ...
		 *    ^^^^^ blocks we're writing
		 */
		distance = max_distance - (log->l_logBBsize - head_block);
		error = xlog_write_log_records(log, head_cycle, 0, distance,
				tail_cycle, tail_block);
		if (error)
			return error;
	}

	return 0;
}

/*
 * Release the recovered intent item in the AIL that matches the given intent
 * type and intent id.
 */
void
xlog_recover_release_intent(
	struct xlog			*log,
	unsigned short			intent_type,
	uint64_t			intent_id)
{
	struct xfs_defer_pending	*dfp, *n;

	list_for_each_entry_safe(dfp, n, &log->r_dfops, dfp_list) {
		struct xfs_log_item	*lip = dfp->dfp_intent;

		if (lip->li_type != intent_type)
			continue;
		if (!lip->li_ops->iop_match(lip, intent_id))
			continue;

		ASSERT(xlog_item_is_intent(lip));

		xfs_defer_cancel_recovery(log->l_mp, dfp);
	}
}

int
xlog_recover_iget(
	struct xfs_mount	*mp,
	xfs_ino_t		ino,
	struct xfs_inode	**ipp)
{
	int			error;

	error = xfs_iget(mp, NULL, ino, 0, 0, ipp);
	if (error)
		return error;

	error = xfs_qm_dqattach(*ipp);
	if (error) {
		xfs_irele(*ipp);
		return error;
	}

	if (VFS_I(*ipp)->i_nlink == 0)
		xfs_iflags_set(*ipp, XFS_IRECOVERY);

	return 0;
}

/*
 * Get an inode so that we can recover a log operation.
 *
 * Log intent items that target inodes effectively contain a file handle.
 * Check that the generation number matches the intent item like we do for
 * other file handles.  Log intent items defined after this validation weakness
 * was identified must use this function.
 */
int
xlog_recover_iget_handle(
	struct xfs_mount	*mp,
	xfs_ino_t		ino,
	uint32_t		gen,
	struct xfs_inode	**ipp)
{
	struct xfs_inode	*ip;
	int			error;

	error = xlog_recover_iget(mp, ino, &ip);
	if (error)
		return error;

	if (VFS_I(ip)->i_generation != gen) {
		xfs_irele(ip);
		return -EFSCORRUPTED;
	}

	*ipp = ip;
	return 0;
}

/******************************************************************************
 *
 *		Log recover routines
 *
 ******************************************************************************
 */
static const struct xlog_recover_item_ops *xlog_recover_item_ops[] = {
	&xlog_buf_item_ops,
	&xlog_inode_item_ops,
	&xlog_dquot_item_ops,
	&xlog_quotaoff_item_ops,
	&xlog_icreate_item_ops,
	&xlog_efi_item_ops,
	&xlog_efd_item_ops,
	&xlog_rui_item_ops,
	&xlog_rud_item_ops,
	&xlog_cui_item_ops,
	&xlog_cud_item_ops,
	&xlog_bui_item_ops,
	&xlog_bud_item_ops,
	&xlog_attri_item_ops,
	&xlog_attrd_item_ops,
	&xlog_xmi_item_ops,
	&xlog_xmd_item_ops,
	&xlog_rtefi_item_ops,
	&xlog_rtefd_item_ops,
	&xlog_rtrui_item_ops,
	&xlog_rtrud_item_ops,
	&xlog_rtcui_item_ops,
	&xlog_rtcud_item_ops,
	&xlog_mxfs_relmark_item_ops,	/* clean-release marker */
};

static const struct xlog_recover_item_ops *
xlog_find_item_ops(
	struct xlog_recover_item		*item)
{
	unsigned int				i;

	for (i = 0; i < ARRAY_SIZE(xlog_recover_item_ops); i++)
		if (ITEM_TYPE(item) == xlog_recover_item_ops[i]->item_type)
			return xlog_recover_item_ops[i];

	return NULL;
}

/*
 * Sort the log items in the transaction.
 *
 * The ordering constraints are defined by the inode allocation and unlink
 * behaviour. The rules are:
 *
 *	1. Every item is only logged once in a given transaction. Hence it
 *	   represents the last logged state of the item. Hence ordering is
 *	   dependent on the order in which operations need to be performed so
 *	   required initial conditions are always met.
 *
 *	2. Cancelled buffers are recorded in pass 1 in a separate table and
 *	   there's nothing to replay from them so we can simply cull them
 *	   from the transaction. However, we can't do that until after we've
 *	   replayed all the other items because they may be dependent on the
 *	   cancelled buffer and replaying the cancelled buffer can remove it
 *	   form the cancelled buffer table. Hence they have to be done last.
 *
 *	3. Inode allocation buffers must be replayed before inode items that
 *	   read the buffer and replay changes into it. For filesystems using the
 *	   ICREATE transactions, this means XFS_LI_ICREATE objects need to get
 *	   treated the same as inode allocation buffers as they create and
 *	   initialise the buffers directly.
 *
 *	4. Inode unlink buffers must be replayed after inode items are replayed.
 *	   This ensures that inodes are completely flushed to the inode buffer
 *	   in a "free" state before we remove the unlinked inode list pointer.
 *
 * Hence the ordering needs to be inode allocation buffers first, inode items
 * second, inode unlink buffers third and cancelled buffers last.
 *
 * But there's a problem with that - we can't tell an inode allocation buffer
 * apart from a regular buffer, so we can't separate them. We can, however,
 * tell an inode unlink buffer from the others, and so we can separate them out
 * from all the other buffers and move them to last.
 *
 * Hence, 4 lists, in order from head to tail:
 *	- buffer_list for all buffers except cancelled/inode unlink buffers
 *	- item_list for all non-buffer items
 *	- inode_buffer_list for inode unlink buffers
 *	- cancel_list for the cancelled buffers
 *
 * Note that we add objects to the tail of the lists so that first-to-last
 * ordering is preserved within the lists. Adding objects to the head of the
 * list means when we traverse from the head we walk them in last-to-first
 * order. For cancelled buffers and inode unlink buffers this doesn't matter,
 * but for all other items there may be specific ordering that we need to
 * preserve.
 */
STATIC int
xlog_recover_reorder_trans(
	struct xlog		*log,
	struct xlog_recover	*trans,
	int			pass)
{
	struct xlog_recover_item *item, *n;
	int			error = 0;
	LIST_HEAD(sort_list);
	LIST_HEAD(cancel_list);
	LIST_HEAD(buffer_list);
	LIST_HEAD(inode_buffer_list);
	LIST_HEAD(item_list);

	list_splice_init(&trans->r_itemq, &sort_list);
	list_for_each_entry_safe(item, n, &sort_list, ri_list) {
		enum xlog_recover_reorder	fate = XLOG_REORDER_ITEM_LIST;

		item->ri_ops = xlog_find_item_ops(item);
		if (!item->ri_ops) {
			xfs_warn(log->l_mp,
				"%s: unrecognized type of log operation (%d)",
				__func__, ITEM_TYPE(item));
			ASSERT(0);
			/*
			 * return the remaining items back to the transaction
			 * item list so they can be freed in caller.
			 */
			if (!list_empty(&sort_list))
				list_splice_init(&sort_list, &trans->r_itemq);
			error = -EFSCORRUPTED;
			break;
		}

		if (item->ri_ops->reorder)
			fate = item->ri_ops->reorder(item);

		switch (fate) {
		case XLOG_REORDER_BUFFER_LIST:
			list_move_tail(&item->ri_list, &buffer_list);
			break;
		case XLOG_REORDER_CANCEL_LIST:
			trace_xfs_log_recover_item_reorder_head(log,
					trans, item, pass);
			list_move(&item->ri_list, &cancel_list);
			break;
		case XLOG_REORDER_INODE_BUFFER_LIST:
			list_move(&item->ri_list, &inode_buffer_list);
			break;
		case XLOG_REORDER_ITEM_LIST:
			trace_xfs_log_recover_item_reorder_tail(log,
							trans, item, pass);
			list_move_tail(&item->ri_list, &item_list);
			break;
		}
	}

	ASSERT(list_empty(&sort_list));
	if (!list_empty(&buffer_list))
		list_splice(&buffer_list, &trans->r_itemq);
	if (!list_empty(&item_list))
		list_splice_tail(&item_list, &trans->r_itemq);
	if (!list_empty(&inode_buffer_list))
		list_splice_tail(&inode_buffer_list, &trans->r_itemq);
	if (!list_empty(&cancel_list))
		list_splice_tail(&cancel_list, &trans->r_itemq);
	return error;
}

void
xlog_buf_readahead(
	struct xlog		*log,
	xfs_daddr_t		blkno,
	uint			len,
	const struct xfs_buf_ops *ops)
{
	/*
	 * No readahead on a foreign-slice replay: a readahead image lands in
	 * this node's cache from an I/O completion nobody attributes, so it
	 * could escape the recovery's image retirement.  With it off, every
	 * buffer the replay populates is read synchronously by the recovery
	 * task and tagged at that read (xfs_buf_read_map).
	 */
	if (xlog_is_mxfs_foreign_replay(log))
		return;
	if (!xlog_is_buffer_cancelled(log, blkno, len))
		xfs_buf_readahead(log->l_mp->m_ddev_targp, blkno, len, ops);
}

/*
 * Create a deferred work structure for resuming and tracking the progress of a
 * log intent item that was found during recovery.
 */
void
xlog_recover_intent_item(
	struct xlog			*log,
	struct xfs_log_item		*lip,
	xfs_lsn_t			lsn,
	const struct xfs_defer_op_type	*ops)
{
	ASSERT(xlog_item_is_intent(lip));

	xfs_defer_start_recovery(lip, &log->r_dfops, ops);

	/*
	 * Insert the intent into the AIL directly and drop one reference so
	 * that finishing or canceling the work will drop the other.
	 */
	xfs_trans_ail_insert(log->l_ailp, lip, lsn);
	lip->li_ops->iop_unpin(lip, 0);
}

/*
 * step 3b (D-FOREIGN-REPLAY-UNGATED-IMAGES, authority tokens):
 * decode the authority trailer of a recovered BUFFER log item.
 *
 * step 5.2: decodes BOTH wire versions into one normalized view, and
 * returns WHICH of four things happened — NOT_BUF / UNTAGGED / MALFORMED /
 * OK.  v1 conflated the last three into a NULL return, which made
 * "this producer emitted nothing" indistinguishable from "this trailer is
 * corrupt", so report-only mode could not measure either.  Every caller
 * still fails closed on anything other than OK; the point of the split is
 * that the three failures are now COUNTED SEPARATELY (a ruling requirement),
 * and MALFORMED is the one that means something is wrong with the log
 * rather than with the producer.
 *
 * The trailer offset is RECOMPUTED from blf_map_size on every call — the
 * record comes off a dead node's on-disk slice, so no stored offset and no
 * in-core assumption about the emitting build may be trusted.  For the same
 * reason the trailer SIZE comes from the version field in the record, never
 * from this build's emit-size macro.
 */
static enum mxfs_auth_parse
mxfs_blf_parse_authority(
	struct xlog_recover_item	*item,
	struct mxfs_auth_view		*out)
{
	struct xfs_buf_log_format	*blfp;
	const char			*p;
	size_t				base, sz;
	unsigned int			ver;

	memset(out, 0, sizeof(*out));
	out->av_status = MXFS_AUTH_ST_MALFORMED;

	if (item->ri_cnt < 1 || !item->ri_buf)
		return MXFS_AUTH_PARSE_NOT_BUF;
	if (ITEM_TYPE(item) != XFS_LI_BUF)
		return MXFS_AUTH_PARSE_NOT_BUF;
	/* bounds-checks iov_len against the header + the dirty bitmap */
	if (!xfs_buf_log_check_iovec(&item->ri_buf[0]))
		return MXFS_AUTH_PARSE_MALFORMED;

	blfp = item->ri_buf[0].iov_base;
	if (!(blfp->blf_flags & XFS_BLF_MXFS_AUTHORITY))
		return MXFS_AUTH_PARSE_UNTAGGED;
	if (blfp->blf_map_size > XFS_BLF_DATAMAP_SIZE)
		return MXFS_AUTH_PARSE_MALFORMED;

	base = offsetof(struct xfs_buf_log_format, blf_data_map) +
		(size_t)blfp->blf_map_size * sizeof(blfp->blf_data_map[0]);
	p = (const char *)item->ri_buf[0].iov_base;

	/*
	 * Read the version BEFORE sizing — this record came off a dead node's
	 * on-disk slice and may have been written by any build, so the
	 * emitting build's size macro is not usable here.  Enough bytes for
	 * the version field first, then the per-version size.
	 */
	if (item->ri_buf[0].iov_len < base + sizeof(__be16))
		return MXFS_AUTH_PARSE_MALFORMED;
	ver = be16_to_cpu(*(const __be16 *)(p + base));
	sz = mxfs_blf_authority_size(ver);
	if (!sz)
		return MXFS_AUTH_PARSE_MALFORMED;
	if (item->ri_buf[0].iov_len < base + sz)
		return MXFS_AUTH_PARSE_MALFORMED;

	out->av_version = (uint16_t)ver;

	if (ver == MXFS_BLF_AUTHORITY_V1) {
		const struct mxfs_blf_authority *t1 =
			(const struct mxfs_blf_authority *)(p + base);

		/*
		 * v1 carries no status and no incarnation.  It normalizes to
		 * UNSET, never to VALID: v1 IS REPORT-ONLY AND MUST NEVER
		 * GATE AN APPLY/SKIP DECISION, so no amount of producer-side
		 * improvement may promote it here.
		 */
		out->av_class = be16_to_cpu(t1->mba_class);
		out->av_status = MXFS_AUTH_ST_UNSET;
		out->av_resource = be32_to_cpu(t1->mba_resource);
		out->av_grant_epoch = be64_to_cpu(t1->mba_grant_epoch);
		out->av_owner_slot = be32_to_cpu(t1->mba_owner_slot);
		/* mba_owner_boot was memset 0 and never filled — not read */
		return MXFS_AUTH_PARSE_OK;
	}

	{
		const struct mxfs_blf_authority_v2 *t2 =
			(const struct mxfs_blf_authority_v2 *)(p + base);
		uint32_t flags = be32_to_cpu(t2->mba_flags);
		uint32_t st = flags & MXFS_AUTH_FLAG_STATUS_MASK;

		/*
		 * Reserved bits MUST be zero.  This is the whole reason they
		 * exist: a future wire addition is REJECTED by an older
		 * enforcing node rather than silently misread as a token it
		 * fully understands.
		 */
		if (flags & MXFS_AUTH_FLAG_RESERVED_MASK)
			return MXFS_AUTH_PARSE_MALFORMED;
		if (st >= MXFS_AUTH_ST_MAX)
			return MXFS_AUTH_PARSE_MALFORMED;
		/*
		 * the CLASS names the resource TYPE that mba_resource's
		 * id belongs to, so an unrecognized class makes the resource
		 * uninterpretable — not merely unproven.  Reject rather than
		 * decode, for the same reason the reserved bits are rejected.
		 */
		if (be16_to_cpu(t2->mba_class) >= MXFS_AUTH_CLASS_MAX)
			return MXFS_AUTH_PARSE_MALFORMED;

		out->av_class = be16_to_cpu(t2->mba_class);
		out->av_status = (uint8_t)st;
		out->av_resource = be64_to_cpu(t2->mba_resource);
		out->av_grant_epoch = be64_to_cpu(t2->mba_grant_epoch);
		out->av_owner_epoch = be64_to_cpu(t2->mba_owner_epoch);
		out->av_owner_slot = be32_to_cpu(t2->mba_owner_slot);
		out->av_owner_node = be32_to_cpu(t2->mba_owner_node);

		/*
		 * v3 = v2 + the resource lineage of the authorizing
		 * binding.  A v2 record leaves av_lineage 0, and a v3 record
		 * MAY carry 0 (grant predates the lineage-minting build);
		 * the evaluator distinguishes those by av_version, so 0 is
		 * never treated as a comparable lineage value.
		 */
		if (ver == MXFS_BLF_AUTHORITY_V3) {
			const struct mxfs_blf_authority_v3 *t3 =
				(const struct mxfs_blf_authority_v3 *)(p + base);

			out->av_lineage = be64_to_cpu(t3->mba_lineage);
		}
	}

	/*
	 * (D-FOREIGN-SLICE-INTENTS-ABANDONED fix shape B, ruling Q2):
	 * the AG grant vouches for an inode-cluster image ONLY in its iunlink
	 * form — XFS_BLF_INODE_BUF, whose replay (xlog_recover_do_inode_buffer)
	 * applies nothing but di_next_unlinked.  A class-AG DINODE image
	 * without that flag would let xlog_recover_do_reg_buffer write inode
	 * CORES on the AG's authority, which no producer of this build emits;
	 * on the wire it is a corrupt or forged token and is refused as such
	 * (MALFORMED fails closed exactly like a reserved bit).
	 *
	 * (design consult, same ruling that removed the sticky
	 * XFS_BLI_INODE_ALLOC_BUF term from the producer): XFS_BLF_CANCEL is the
	 * other way an image can carry inode-buffer typing and still not be the
	 * di_next_unlinked-only form.  A staled inode cluster emits a
	 * cancellation record, and replay of a cancellation does not apply
	 * di_next_unlinked at all — it suppresses every image of that block in
	 * the pass.  The AG grant vouches for the unlinked-list mutation, not
	 * for a whole-block suppression, so a class-AG DINODE cancellation is
	 * refused here for the same reason as a non-INODE_BUF image.  The
	 * producer cannot emit one (it excludes XFS_BLI_STALE and
	 * XFS_BLI_STALE_INODE), so this is the closed-fail mirror of that
	 * exclusion against a corrupt or forged token.
	 */
	if (out->av_class == MXFS_AUTH_CLASS_AG &&
	    xfs_blft_from_flags(blfp) == XFS_BLFT_DINO_BUF &&
	    (!(blfp->blf_flags & XFS_BLF_INODE_BUF) ||
	     (blfp->blf_flags & XFS_BLF_CANCEL))) {
		static atomic_t dino_ag_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&dino_ag_n) <= 32)
			pr_warn("mxfs: P-IUNLINK-AGCLASS-SHAPE blkno=%lld len=%u flags=0x%x — class-AG DINODE image is not the INODE_BUF (di_next_unlinked-only) form, or is a cancellation; token refused as MALFORMED\n",
				(long long)blfp->blf_blkno,
				(unsigned)blfp->blf_len,
				(unsigned)blfp->blf_flags);
		out->av_status = MXFS_AUTH_ST_MALFORMED;
		return MXFS_AUTH_PARSE_MALFORMED;
	}
	return MXFS_AUTH_PARSE_OK;
}

/*
 * (#94 D-IDLE-SLICE-WSKIP-REFUSAL-AG-QUARANTINE-0130): lazily build
 * the masked-compare baseline for the counter-only SB classifier — the
 * REPLAYER's own m_sb serialized to disk format.  Under the blanket
 * ATOMIC-SKIP nothing is ever applied, so the effective SB state at every
 * replay point IS this snapshot (ruling2 Q3); a victim-side growfs
 * image then mismatches the baseline and stays refused (false refusal is
 * acceptable, false clean-skip is not).  Snapshotted ONCE per replay: the
 * only fields that drift on the live replayer are the lazy counters, and
 * those are exactly the masked ones.  kzalloc so fields xfs_sb_to_disk
 * leaves untouched (feature-gated tails) compare equal to a victim image
 * serialized over a mkfs-zeroed sector.
 */
static struct xfs_dsb *
mxfs_sb_baseline_get(
	struct xlog		*log)
{
	struct xfs_mount	*mp = log->l_mp;
	struct xfs_sb		*sbp;
	struct xfs_dsb		*dsb;

	if (log->l_mxfs_sb_baseline)
		return log->l_mxfs_sb_baseline;

	dsb = kzalloc(sizeof(*dsb), GFP_KERNEL);
	sbp = kmalloc(sizeof(*sbp), GFP_KERNEL);
	if (!dsb || !sbp) {
		kfree(dsb);
		kfree(sbp);
		return NULL;
	}
	spin_lock(&mp->m_sb_lock);
	memcpy(sbp, &mp->m_sb, sizeof(*sbp));
	spin_unlock(&mp->m_sb_lock);
	xfs_sb_to_disk(dsb, sbp);
	kfree(sbp);
	log->l_mxfs_sb_baseline = dsb;
	return dsb;
}

/*
 * Masked content compare for the counter-only SB classifier.  Returns true
 * iff the victim's SB image differs from the baseline ONLY in the lazy
 * summary counters (sb_icount/sb_ifree/sb_fdblocks — reconstructible from
 * AGF/AGI) and the derived-at-write fields (sb_crc is computed by the write
 * verifier, sb_lsn stamped at buffer submit; both are meaningless in a
 * logged image).  Implemented as memcmp over the four UNMASKED ranges so
 * any field this build does not know about fails closed.  sb_frextents is
 * deliberately NOT masked: no rt device in any MXFS configuration, so a
 * frextents delta is evidence of something else and must refuse.  Bytes of
 * the sector beyond sizeof(struct xfs_dsb) are not compared — no consumer
 * interprets them.
 */
static bool
mxfs_dsb_counter_only_diff(
	const struct xfs_dsb	*base,
	const struct xfs_dsb	*img,
	size_t			*diff_off)
{
	static const struct {
		size_t	off;
		size_t	end;
	} unmasked[] = {
		{ 0, offsetof(struct xfs_dsb, sb_icount) },
		{ offsetof(struct xfs_dsb, sb_frextents),
		  offsetof(struct xfs_dsb, sb_crc) },
		{ offsetof(struct xfs_dsb, sb_spino_align),
		  offsetof(struct xfs_dsb, sb_lsn) },
		{ offsetof(struct xfs_dsb, sb_meta_uuid),
		  sizeof(struct xfs_dsb) },
	};
	int			i;
	size_t			o;

	for (i = 0; i < ARRAY_SIZE(unmasked); i++) {
		if (!memcmp((const char *)base + unmasked[i].off,
			    (const char *)img + unmasked[i].off,
			    unmasked[i].end - unmasked[i].off))
			continue;
		for (o = unmasked[i].off; o < unmasked[i].end; o++) {
			if (((const char *)base)[o] != ((const char *)img)[o])
				break;
		}
		*diff_off = o;
		return false;
	}
	return true;
}

/*
 * (#94, rulings): counter-only SB clean-skip classifier for
 * the blanket ATOMIC-SKIP.  A skipped foreign transaction is refusal-grade
 * ONLY if skipping it can omit NON-RECONSTRUCTIBLE state; routine lazy
 * SB-counter logging (xfs_log_sb from the percpu-counter sync path) is
 * reconstructible from AGF/AGI, and every mxfs mount recomputes the summary
 * counters from per-AG data unconditionally (xfs_check_summary_counts).
 * Without this carve-out ANY fenced node whose slice retains a routine SB
 * sync — i.e. any node that went idle after activity — deterministically
 * arms the -117 terminal refusal and quarantines AG0 cluster-wide.
 *
 * STRICT eligibility, every item of the transaction must pass ALL of:
 *   - XFS_LI_BUF whose token parses PARSE_OK with av_class == CLASS_SB
 *     (st may be UNPROVEN: SB images carry no grant epoch to name, by
 *     design — pal/linux/xfs_buf_item.c producer classify.  UNTAGGED /
 *     MALFORMED stay refusal-grade);
 *   - the image is the PRIMARY superblock: blf_blkno == XFS_SB_DADDR,
 *     one-sector length, BLFT SB, exactly one logged region starting at
 *     buffer offset 0 (xfs_log_sb logs the whole buffer) and covering at
 *     least the dsb, magic intact;
 *   - masked content compare against the replayer-side baseline shows the
 *     image differs ONLY in the whitelisted counter/derived fields.
 * Anything else — mixed transactions, secondary SBs, growfs/feature/
 * geometry deltas, unparseable tokens, allocation failure — stays on the
 * existing refusal path.  Returns a VERDICT CODE, not a bool (design review
 * review item 3/4): 0 = eligible, nonzero = the FIRST reason the txn was
 * not — printed by both the refusal notice and the P227-TOKENSUM sample so
 * a systematic false-mismatch (which would silently restore the old
 * always-quarantine behavior) is visible on the rig, not inferred.
 *
 * CLASSIFIED EXACTLY ONCE per transaction, in xlog_recover_items_pass2,
 * BEFORE the report call; the verdict is passed down.  Pass-2 replay is
 * single-threaded (see the shadow-evaluator locking argument above), so the
 * lazy baseline install has exactly one call site and no concurrency.
 */
#define MXFS_SBCLEAN_OK		0	/* eligible: clean-skip */
#define MXFS_SBCLEAN_TOKEN	1	/* item token not PARSE_OK / non-buf */
#define MXFS_SBCLEAN_CLASS	2	/* token class != CLASS_SB */
#define MXFS_SBCLEAN_STATUS	3	/* token status != UNPROVEN */
#define MXFS_SBCLEAN_NOTSB	4	/* not the primary-SB image shape */
#define MXFS_SBCLEAN_FRAMING	5	/* region/bitmap/magic framing */
#define MXFS_SBCLEAN_BASELINE	6	/* baseline allocation failed */
#define MXFS_SBCLEAN_CONTENT	7	/* non-counter content mismatch */
#define MXFS_SBCLEAN_EMPTY	8	/* no items */

static int
mxfs_sb_counter_only_txn(
	struct xlog			*log,
	struct list_head		*item_list)
{
	struct xlog_recover_item	*item;
	int				n_sb = 0;

	list_for_each_entry(item, item_list, ri_list) {
		struct xfs_buf_log_format	*blfp;
		struct mxfs_auth_view		av;
		const struct xfs_dsb		*img;
		const struct xfs_dsb		*base;
		int				nbits;
		size_t				doff;

		if (mxfs_blf_parse_authority(item, &av) != MXFS_AUTH_PARSE_OK)
			return MXFS_SBCLEAN_TOKEN;
		if (av.av_class != MXFS_AUTH_CLASS_SB)
			return MXFS_SBCLEAN_CLASS;
		/*
		 * design review item 2: the producer stamps SB images
		 * UNPROVEN and nothing else — a parsed CLASS_SB token with
		 * any OTHER status (including VALID) is not the shape this
		 * carve-out reasoned about and must not ride it.
		 */
		if (av.av_status != MXFS_AUTH_ST_UNPROVEN)
			return MXFS_SBCLEAN_STATUS;
		/* parser bounds-checked ri_buf[0] via check_iovec */
		blfp = item->ri_buf[0].iov_base;
		if (blfp->blf_blkno != XFS_SB_DADDR)
			return MXFS_SBCLEAN_NOTSB;
		if (blfp->blf_len != XFS_FSS_TO_BB(log->l_mp, 1))
			return MXFS_SBCLEAN_NOTSB;
		if (xfs_blft_from_flags(blfp) != XFS_BLFT_SB_BUF)
			return MXFS_SBCLEAN_NOTSB;
		if (blfp->blf_flags & (XFS_BLF_CANCEL | XFS_BLF_INODE_BUF |
				       XFS_BLF_UDQUOT_BUF |
				       XFS_BLF_PDQUOT_BUF |
				       XFS_BLF_GDQUOT_BUF))
			return MXFS_SBCLEAN_NOTSB;
		/*
		 * design review item 1: require the EXACT producer
		 * framing, not merely a compatible prefix.  xfs_log_sb
		 * dirties bytes [0, sizeof(dsb)) of the SB buffer — one
		 * contiguous chunk run from bit 0 of exactly the chunks
		 * covering the dsb, no other dirty bits, and one data
		 * region whose length matches that run (the log rounds
		 * iovec lengths, so allow [sizeof(dsb), run bytes]).
		 */
		if (item->ri_cnt != 2)
			return MXFS_SBCLEAN_FRAMING;
		nbits = xfs_contig_bits(blfp->blf_data_map,
					blfp->blf_map_size, 0);
		if (nbits != DIV_ROUND_UP(sizeof(struct xfs_dsb),
					  XFS_BLF_CHUNK))
			return MXFS_SBCLEAN_FRAMING;
		if (xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size,
				 nbits) != -1)
			return MXFS_SBCLEAN_FRAMING;
		if (item->ri_buf[1].iov_len < sizeof(struct xfs_dsb) ||
		    item->ri_buf[1].iov_len >
		    (size_t)nbits * XFS_BLF_CHUNK)
			return MXFS_SBCLEAN_FRAMING;
		img = item->ri_buf[1].iov_base;
		if (img->sb_magicnum != cpu_to_be32(MXFS_SB_MAGIC))
			return MXFS_SBCLEAN_FRAMING;
		base = mxfs_sb_baseline_get(log);
		if (!base)
			return MXFS_SBCLEAN_BASELINE;
		if (!mxfs_dsb_counter_only_diff(base, img, &doff)) {
			size_t	po = min(doff, sizeof(struct xfs_dsb) - 16);

			xfs_notice(log->l_mp,
	"MXFS foreign replay: SBCLEAN-CONTENT-DIFF off=%zu base=%16phN img=%16phN",
				   doff, (const char *)base + po,
				   (const char *)img + po);
			return MXFS_SBCLEAN_CONTENT;
		}
		n_sb++;
	}
	return n_sb ? MXFS_SBCLEAN_OK : MXFS_SBCLEAN_EMPTY;
}

/*
 * (foreign-replay step 5): SHADOW authority evaluator.  For every
 * authority token seen by untrusted replay, compute the verdict the real
 * apply/skip gate WOULD reach — v2-only, owner-slot and (when a fence
 * descriptor proves the incarnation) owner-epoch bound, checked against the
 * fenced victim's quarantine-frozen grant manifest — and count it.  REPORT
 * ONLY: no replay decision changes.  The counters exist to measure, on real
 * foreign/adopted replays, how much of the blanket ATOMIC-SKIP an exact gate
 * would lift and whether it would ever apply something the blanket skip
 * suppressed wrongly.
 *
 * Verdict stability argument (why reading the manifest DURING replay is
 * sound): would_apply/stale_epoch verdicts arise only on resources the victim
 * holds EX/PW, and those bits are frozen by fencing (the victim cannot CAS;
 * purge is ordered after IMAGES_REPLAYED; peers are refused EX on dead-bit
 * resources).  not_held verdicts on live-peer resources are stable regardless
 * of concurrent epoch churn because ex_grant_epoch is only meaningful under a
 * set holder bit.  Pass-2 replay is single-threaded, so no locking here.
 *
 * How to read the counters (design-consult review):
 *  - Per-token counters are FIRST-FAILURE terminals.  A token lands in the
 *    counter of the FIRST layer that rejects it; later layers never see it.
 *    Ordering therefore masks depth — a v1 token with a wrong owner slot
 *    counts v1 only.  The counters isolate layers, not defect prevalence.
 *  - would_apply means the exact gate WOULD AUTHORIZE the image.  It is not
 *    "would hit disk": a real gate still sits above the upstream per-buffer
 *    on-disk-LSN comparison, which runs downstream of authorization.
 *  - txn_total counts only transactions carrying at least one buf item or
 *    taint-class non-buf item; pure intent/cancel transactions are outside
 *    the ATOMIC-SKIP population and are not part of the denominator.
 *  - Until D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID lands a per-tenure unique
 *    epoch source, would_apply is an EXPLORATORY UPPER BOUND (epoch
 *    collisions across tenures of one slot inflate it).  It must not, by
 *    itself, justify switching the enforcement gate on.
 */
struct mxfs_shadow_eval {
	/* capability: the fence/recovery descriptor read once at creation */
	int		desc_rc;
	uint16_t	desc_stage;
	uint64_t	desc_victim_epoch;
	uint32_t	desc_victim_node;
	bool		capable;	/* rc==0 && stage==FENCED: manifest is
					 * frozen AND victim incarnation known */
	/* the victim's record carried MXFS_HB_FEAT_ADOPTED (pass-2
	 * fresh claim) — captured as MXFS_RECOV_F_VICTIM_ADOPTED.  With
	 * `capable` (incarnation proven) a token naming ANOTHER incarnation
	 * of this slot is a published predecessor's record: PREINC, the
	 * whole transaction skips silently instead of refusing the slice. */
	bool		victim_adopted;
	/* (#1), reshaped (design review Q3): enforcement state
	 * INHERITED from the attempt-local l_mxfs_fr_enforce_mode that only
	 * the preflight ever sets — never resampled from the global knob, so
	 * a knob or domain-param flip after the preflight point can neither
	 * arm enforcement for an unpreflighted attempt nor half-enforce a
	 * slice. */
	bool		enforce_cfg;

	/*
	 * Per-resource manifest read cache: open-addressed hash table,
	 * linear probe, insert-only.  kind==0 (MXFS_AUTH_CLASS_NONE, never
	 * a cached class) marks an empty slot.  Past the fill cap — or when
	 * the allocation failed (tbl==NULL) — lookups read the manifest
	 * directly and count in uncached_reads, so nothing is ever dropped;
	 * uncached resources merely lose the read-once determinism the
	 * cache otherwise provides (visible in the counter).
	 */
	struct mxfs_shadow_man_ent {
		uint64_t	resource;
		uint64_t	epoch;
		uint64_t	lineage;
		int		rc;
		uint8_t		kind;	/* MXFS_AUTH_CLASS_AG or _INODE */
		uint8_t		pidx;	/* 0 = current pair, 1.. = lineage */
		bool		holds;
	}		*tbl;
	unsigned int	tbl_n;

	/* per-token verdicts (every buf item lands in exactly one) */
	uint64_t	buf_items;
	uint64_t	untagged;
	uint64_t	malformed;
	uint64_t	v1_not_evidence;
	uint64_t	classless;
	uint64_t	class_sb;
	uint64_t	class_unsupported;
	uint64_t	status_not_valid;
	uint64_t	foreign_owner;
	uint64_t	resource_mismatch;
	uint64_t	wrong_incarnation;
	uint64_t	manifest_err;
	uint64_t	wrong_lineage;
	uint64_t	not_held;
	uint64_t	stale_epoch;
	uint64_t	uncapable_match;
	uint64_t	v2_no_lineage;
	uint64_t	enforceable_would_apply;
	/*
	 * (design-consult ruling): the token names a tenure the victim
	 * CLEANLY RELEASED — a durable XFS_LI_MXFS_RELMARK with the complete
	 * identity {class, resource, lineage, grant epoch, owner slot, owner
	 * incarnation} was collected from the same slice in pass 1.  The
	 * images are on the platter (Invariant-1 drain before the marker),
	 * so the disposition is SKIP SILENTLY: never applied (a successor
	 * may have written since), never refused (no quarantine).  Terminal,
	 * in csum.  Checked only after the held-at-death match fails and only
	 * under the same capability/lineage rules as the enforceable terminal.
	 */
	uint64_t	redundant_clean;
	/* terminal, in csum — a published predecessor incarnation's
	 * image on an ADOPTED, incarnation-proven victim (see victim_adopted). */
	uint64_t	preincarnation;
	/*
	 * (ruling Q-C): the pre-lineage gate's verdict, kept
	 * with UNCHANGED semantics so the P273 samples 1-3 stay comparable.
	 * NOT a terminal — a token counted here continues to its terminal
	 * (wrong_lineage / v2_no_lineage / enforceable_would_apply), so this
	 * is excluded from the conservation csum.
	 */
	uint64_t	legacy_would_apply;

	/* per-transaction rollup (the ATOMIC-SKIP unit) */
	uint64_t	txn_total;
	uint64_t	txn_all_apply;
	uint64_t	txn_buf_ok_taint_blocked;
	uint64_t	txn_mixed;
	uint64_t	txn_none;
	uint64_t	txn_nonbuf_taint;
	/* (#1): all_apply txns actually ADMITTED by the enforcement
	 * arm — always <= txn_all_apply; 0 whenever enforcement is off or a
	 * use-time predicate (foreign/capable/proto/domain/proof) failed. */
	uint64_t	txn_enforce_admitted;
	/* admissible txns that contained >= 1 REDUNDANT_CLEAN image
	 * (subset of txn_all_apply) and buffer images skipped as redundant
	 * inside ADMITTED txns. */
	uint64_t	txn_with_redundant;
	uint64_t	redundant_skipped;
	/* whole transactions skipped clean as a published
	 * predecessor incarnation's (MXFS_TXNV_PREINC, P310). */
	uint64_t	txn_preinc;

	uint64_t	uncached_reads;

	/*
	 * (docs/recovery-manifest.md): the FENCE-TIME MANIFEST.  Loaded
	 * once at evaluator creation from the envelope's rman region and
	 * validated against the FENCED descriptor's pointer; every "held
	 * {lineage, epoch} at death" answer comes from it.  The live CAW slot
	 * is then read ONCE per resource as a CURRENT-SAFETY check (the
	 * victim bit must still be present with unchanged lineage/epoch); a
	 * mismatch is a broken recovery invariant -> rman_abort (the whole
	 * attempt aborts, never a per-transaction skip).
	 */
	int		manifest_rc;	/* load result; 0 = loaded */
	bool		manifest_no_caw;
	bool		rman_abort;	/* post-seal mutation / live-check fail */
	struct mxfs_rman_entry *man_ents;
	uint32_t	man_n;
	uint32_t	*man_idx;	/* open-addressed index: entry+1, 0=empty */
	uint32_t	man_idx_mask;
	uint64_t	man_lookups;
	uint64_t	man_hits;
	uint64_t	live_checks;
	uint64_t	live_check_err;
	uint64_t	postseal_mutations;
	uint64_t	man_seq;
	/* ICREATE verdicts (P-ICREATE-AUTH) */
	uint64_t	icreate_apply, icreate_redundant, icreate_refused;
	/*
	 * (docs/whole-cluster-restart.md §6.8.5, design-consult review ruling):
	 * the adopted K's EARLIER incarnations.  A taken-over K holds, under
	 * its current certificate (victim = the fenced old owner), the log of
	 * every previous hop — the original victim and each old owner that
	 * adopted K.  One (descriptor, sealed fence-time manifest) pair per
	 * hop, from the episode's lineage; a token names its pair by the
	 * victim incarnation it carries.  Only the CURRENT pair is live-
	 * checked against K's CAW bits: a proven later incarnation was
	 * allowed to overwrite those bits, so an older pair is judged by its
	 * immutable manifest + certificate alone.
	 */
#define MXFS_SHADOW_LIN_MAX	8
	struct mxfs_shadow_lin {
		uint32_t	victim_node;
		uint64_t	victim_epoch;
		uint16_t	stage;
		uint64_t	term;
		int		manifest_rc;
		bool		no_caw;
		struct mxfs_rman_entry *ents;
		uint32_t	n;
		uint32_t	*idx;
		uint32_t	mask;
	}		lin[MXFS_SHADOW_LIN_MAX];
	unsigned int	nlin;
	uint64_t	lin_tokens;	/* tokens judged by an earlier pair */
};

#define MXFS_SHADOW_TBL_BITS	13
#define MXFS_SHADOW_TBL_SLOTS	(1u << MXFS_SHADOW_TBL_BITS)	/* ~192KB */
#define MXFS_SHADOW_TBL_FILL_CAP \
	(MXFS_SHADOW_TBL_SLOTS - MXFS_SHADOW_TBL_SLOTS / 4)

/* Open-addressed index over a sealed manifest: entry+1, 0 = empty.
 * -EPROTO on a duplicate key (no verdict may be taken from such a manifest). */
static int
mxfs_shadow_build_idx(
	struct xfs_mount		*mp,
	uint32_t			victim_slot,
	const struct mxfs_rman_entry	*ents,
	uint32_t			n,
	uint32_t			**idx_out,
	uint32_t			*mask_out)
{
	uint32_t			sz = 1, i, *idx;

	*idx_out = NULL;
	*mask_out = 0;
	if (!n)
		return 0;
	while (sz < n * 2)
		sz <<= 1;
	idx = kvzalloc(array_size(sz, sizeof(uint32_t)), GFP_NOFS);
	if (!idx)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		const struct mxfs_rman_entry *e = &ents[i];
		uint32_t h = (uint32_t)hash_64(e->id ^ ((uint64_t)e->type << 56),
					       32) & (sz - 1);

		while (idx[h]) {
			const struct mxfs_rman_entry *o = &ents[idx[h] - 1];

			if (o->type == e->type && o->id == e->id) {
				xfs_alert(mp,
	"MXFS foreign replay: P-RMAN-INVALID victim_slot=%u — duplicate manifest key type=%u id=%llu (idx %u and %u); no verdict may be taken from this manifest",
					  victim_slot, e->type,
					  (unsigned long long)e->id,
					  o->slot_idx, e->slot_idx);
				kvfree(idx);
				return -EPROTO;
			}
			h = (h + 1) & (sz - 1);
		}
		idx[h] = i + 1;
	}
	*idx_out = idx;
	*mask_out = sz - 1;
	return 0;
}

static struct mxfs_shadow_eval *
mxfs_shadow_eval_get(
	struct xlog			*log)
{
	struct xfs_mount		*mp = log->l_mp;
	struct mxfs_shadow_eval		*se = log->l_mxfs_shadow_eval;

	if (se)
		return se;
	if (log->l_mxfs_victim_slot == MXFS_XLOG_VICTIM_NONE || !mp->m_mxfs_dlm)
		return NULL;

	se = kzalloc(sizeof(*se), GFP_NOFS);
	if (!se)
		return NULL;
	/* NULL is a working state: every lookup reads direct and counts */
	se->tbl = kvzalloc(array_size(MXFS_SHADOW_TBL_SLOTS, sizeof(*se->tbl)),
			   GFP_NOFS);

	se->desc_rc = mxfs_v5_dlm_victim_recovery_read(mp->m_mxfs_dlm,
			log->l_mxfs_victim_slot, &se->desc_stage,
			&se->desc_victim_epoch, &se->desc_victim_node);
	se->capable = (se->desc_rc == 0 &&
		       se->desc_stage == MXFS_RECOV_STAGE_FENCED);
	se->victim_adopted = se->capable &&
		mxfs_v5_dlm_victim_adopted(mp->m_mxfs_dlm,
					   log->l_mxfs_victim_slot);
	se->enforce_cfg = (log->l_mxfs_fr_enforce_mode != 0);

	/*
	 * load the sealed fence-time manifest.  Only a FENCED
	 * descriptor carries a pointer (the seal CAS publishes both), so on an
	 * adopted slice / unproven descriptor there is nothing to load and the
	 * evaluator keeps answering from the live table in report-only form.
	 */
	se->manifest_rc = -ENOENT;
	if (se->capable) {
		struct mxfs_recov_manifest_ptr mptr;

		memset(&mptr, 0, sizeof(mptr));
		se->manifest_rc = mxfs_v5_dlm_victim_manifest_load(mp->m_mxfs_dlm,
				log->l_mxfs_victim_slot, se->desc_victim_node,
				se->desc_victim_epoch, &mptr, &se->man_ents,
				&se->man_n, &se->manifest_no_caw);
		se->man_seq = mptr.seq;
		if (se->manifest_rc == 0 && se->man_n)
			se->manifest_rc = mxfs_shadow_build_idx(mp,
					log->l_mxfs_victim_slot, se->man_ents,
					se->man_n, &se->man_idx, &se->man_idx_mask);
		mxfs_xfs_probe(mp,
	"MXFS foreign replay: P-RMAN-LOAD victim_slot=%u rc=%d entries=%u seq=%llu no_caw=%d",
			   log->l_mxfs_victim_slot, se->manifest_rc, se->man_n,
			   (unsigned long long)se->man_seq,
			   se->manifest_no_caw ? 1 : 0);
		/*
		 * (§6.8.5): a taken-over K — load every earlier
		 * incarnation's pair from the lineage.  Own-log (adopted) replay
		 * only; a foreign replay judges one victim.
		 */
		if (!xlog_is_mxfs_foreign_replay(log)) {
			unsigned int nl = mxfs_v5_dlm_victim_lineage_count(
					mp->m_mxfs_dlm, log->l_mxfs_victim_slot);
			unsigned int i;

			for (i = 0; i < nl && i < MXFS_SHADOW_LIN_MAX; i++) {
				struct mxfs_shadow_lin *l = &se->lin[i];
				struct mxfs_recov_manifest_ptr lptr;

				memset(&lptr, 0, sizeof(lptr));
				l->manifest_rc = mxfs_v5_dlm_victim_lineage_load(
						mp->m_mxfs_dlm, log->l_mxfs_victim_slot,
						i, &l->victim_node, &l->victim_epoch,
						&l->stage, &l->term, &lptr, &l->ents,
						&l->n, &l->no_caw);
				if (l->manifest_rc == 0 && l->n)
					l->manifest_rc = mxfs_shadow_build_idx(mp,
						log->l_mxfs_victim_slot, l->ents,
						l->n, &l->idx, &l->mask);
				xfs_notice(mp,
	"MXFS adopted replay: P-BOOT-K-COMPOSITE victim_slot=%u pair=%u victim=%u/%llu stage=%u term=%llu rc=%d entries=%u no_caw=%d — an earlier incarnation of the adopted slice; its tokens are judged by this sealed manifest and certificate, never by K's current bits",
					   log->l_mxfs_victim_slot, i + 1,
					   l->victim_node,
					   (unsigned long long)l->victim_epoch,
					   l->stage, (unsigned long long)l->term,
					   l->manifest_rc, l->n, l->no_caw ? 1 : 0);
				se->nlin = i + 1;
			}
		}
	}

	/*
	 * On an ADOPTED slice the "victim" is our own predecessor incarnation
	 * and its descriptor is normally gone (desc_rc=-ENOENT, capable=0):
	 * incarnation binding is then unavailable and every manifest lookup is
	 * expected to answer not_held (the predecessor was purged before our
	 * slot claim).  would_apply>0 there is itself a finding — an unpurged
	 * manifest.
	 */
	mxfs_xfs_probe(mp,
	"MXFS %s replay: P273-SHADOW-CAP victim_slot=%u desc_rc=%d stage=%u victim_epoch=%llu victim_node=%u capable=%d enforce_cfg=%d victim_adopted=%d",
		   xlog_is_mxfs_foreign_replay(log) ? "foreign" : "adopted",
		   log->l_mxfs_victim_slot, se->desc_rc,
		   (unsigned int)se->desc_stage,
		   (unsigned long long)se->desc_victim_epoch,
		   se->desc_victim_node, se->capable ? 1 : 0,
		   se->enforce_cfg ? 1 : 0, se->victim_adopted ? 1 : 0);

	log->l_mxfs_shadow_eval = se;
	return se;
}

static int
mxfs_shadow_manifest_lookup(
	struct xlog			*log,
	struct xfs_mount		*mp,
	struct mxfs_shadow_eval		*se,
	const struct mxfs_shadow_lin	*lp,	/* NULL = current pair */
	uint32_t			victim_slot,
	uint8_t				kind,
	uint64_t			resource,
	bool				*holds,
	uint64_t			*epoch,
	uint64_t			*lineage)
{
	struct mxfs_shadow_man_ent	*e = NULL;
	uint32_t			h, probes;
	uint8_t				pidx = lp ? (uint8_t)(lp - se->lin) + 1 : 0;
	int				man_rc = lp ? lp->manifest_rc : se->manifest_rc;
	bool				man_no_caw = lp ? lp->no_caw : se->manifest_no_caw;
	const struct mxfs_rman_entry	*man_ents = lp ? lp->ents : se->man_ents;
	const uint32_t			*man_idx = lp ? lp->idx : se->man_idx;
	uint32_t			man_mask = lp ? lp->mask : se->man_idx_mask;
	int				rc;

	if (se->tbl) {
		h = hash_64(resource ^ ((uint64_t)kind << 56) ^
			    ((uint64_t)pidx << 48), MXFS_SHADOW_TBL_BITS);
		for (probes = 0; probes < MXFS_SHADOW_TBL_SLOTS; probes++) {
			e = &se->tbl[h];
			if (!e->kind)
				break;
			if (e->kind == kind && e->resource == resource &&
			    e->pidx == pidx) {
				*holds = e->holds;
				*epoch = e->epoch;
				*lineage = e->lineage;
				return e->rc;
			}
			h = (h + 1) & (MXFS_SHADOW_TBL_SLOTS - 1);
		}
		/*
		 * Insert only into an empty slot and only under the fill
		 * cap (the cap also guarantees the probe loop above always
		 * terminates on an empty slot, never by exhaustion).
		 */
		if (!e || e->kind || se->tbl_n >= MXFS_SHADOW_TBL_FILL_CAP)
			e = NULL;
	}

	*holds = false;
	*epoch = 0;
	*lineage = 0;
	if (man_rc == 0) {
		/*
		 * the fence-time manifest is the verdict source.
		 * Absent entry == the victim held no EX/PW on this resource at
		 * fence time == definitive not-held (-ENOENT, same terminal the
		 * live "no slot" answer reached).  NO_CAW manifest == -ENODEV,
		 * exactly the pre-manifest TCP behaviour (manifest_err).
		 */
		const struct mxfs_rman_entry *e = NULL;
		uint8_t ltype = kind == MXFS_AUTH_CLASS_AG ? MXFS_LTYPE_AG :
				MXFS_LTYPE_INODE;

			se->man_lookups++;
		if (man_no_caw) {
			rc = -ENODEV;
		} else {
			if (man_idx) {
				uint32_t h = (uint32_t)hash_64(resource ^
					((uint64_t)ltype << 56), 32) & man_mask;

				while (man_idx[h]) {
					const struct mxfs_rman_entry *c =
						&man_ents[man_idx[h] - 1];

					if (c->type == ltype && c->id == resource) {
						e = c;
						break;
					}
					h = (h + 1) & man_mask;
				}
			}
			if (e) {
				bool lh = false;
				uint64_t le = 0, ll = 0;
				int lrc;

				se->man_hits++;
				*holds = true;
				*epoch = e->grant_epoch;
				*lineage = e->lineage;
				rc = 0;
				/*
				 * CURRENT-SAFETY CHECK: the live slot must still
				 * show the victim's bit with the same lineage and
				 * epoch.  Anything else means the frozen authority
				 * was mutated after the seal — a broken recovery
				 * invariant, and the attempt aborts as a whole.
				 * for an EARLIER incarnation's pair the
				 * check is skipped by ruling — a proven later
				 * incarnation was allowed to overwrite those bits.
				 */
				if (!lp)
					se->live_checks++;
				if (lp) {
					/* judged by the sealed manifest alone */
				} else {
					uint8_t lm = 0;
					uint32_t lidx = UINT32_MAX;

					lrc = mxfs_v5_dlm_victim_live_read(
						mp->m_mxfs_dlm, ltype, resource,
						victim_slot, &lh, &le, &ll, &lm,
						&lidx);
					if (lrc == 0 && lh && le == e->grant_epoch &&
					    ll == e->lineage && lm == e->mode &&
					    lidx == e->slot_idx) {
						/* consistent */
					} else if (lrc == 0 || lrc == -ENOENT) {
						se->postseal_mutations++;
						se->rman_abort = true;
						log->l_mxfs_rman_mutated = true;
						xfs_alert(mp,
	"MXFS foreign replay: P-RMAN-POSTSEAL-MUTATION victim_slot=%u kind=%u res=%llu manifest{lineage=%llu epoch=%llu mode=0x%x idx=%u} live{rc=%d holds=%d lineage=%llu epoch=%llu mode=0x%x idx=%u} — the victim's fence-time authority changed after the seal; broken recovery invariant: TERMINAL (nothing purged, evidence preserved)",
							  victim_slot, kind,
							  (unsigned long long)resource,
							  (unsigned long long)e->lineage,
							  (unsigned long long)e->grant_epoch,
							  e->mode, e->slot_idx, lrc,
							  lh ? 1 : 0,
							  (unsigned long long)ll,
							  (unsigned long long)le, lm,
							  lidx);
					} else
						lrc = lrc ? lrc : -EIO;
				}
				if (lrc == -EOPNOTSUPP) {
					/* ICLUS: no live mapping; the manifest
					 * answer stands (class is refused
					 * upstream anyway) */
				} else if (lrc != 0 && lrc != -ENOENT &&
					   !log->l_mxfs_rman_mutated) {
					se->live_check_err++;
					se->rman_abort = true;
					xfs_alert(mp,
	"MXFS foreign replay: P-RMAN-LIVECHECK-ERR victim_slot=%u kind=%u res=%llu rc=%d — the current-safety read of the live slot failed; the manifest verdict cannot be confirmed safe and the attempt ABORTS (retryable)",
						  victim_slot, kind,
						  (unsigned long long)resource, lrc);
				}
			} else {
				rc = -ENOENT;
			}
		}
	} else if (kind == MXFS_AUTH_CLASS_AG)
		rc = mxfs_v5_dlm_victim_ag_manifest_read(mp->m_mxfs_dlm,
				(uint32_t)resource, victim_slot, holds, epoch,
				lineage);
	else
		rc = mxfs_v5_dlm_victim_inode_manifest_read(mp->m_mxfs_dlm,
				resource, victim_slot, holds, epoch, lineage);

	/*
	 * Cache errors too: a per-resource answer must be deterministic across
	 * the replay so the txn rollup can't see one resource both ways.
	 */
	if (e) {
		e->resource = resource;
		e->epoch = *epoch;
		e->lineage = *lineage;
		e->rc = rc;
		e->holds = *holds;
		e->kind = kind;
		e->pidx = pidx;
		se->tbl_n++;
	} else {
		se->uncached_reads++;
	}
	return rc;
}

/*
 * Classify one parsed token exactly as an enforcing gate would.  Returns the
 * MXFS_RI_VERDICT_* disposition: APPLY iff the image would be APPLIED under
 * the exact-match rule, REDUNDANT iff the victim cleanly released
 * the tenure that produced it, REFUSE otherwise; every token lands in exactly
 * one counter.  Order matters: evidence-quality rejections (v1/class/status)
 * come before binding rejections (owner slot/incarnation) before manifest
 * verdicts, so each counter isolates one failure layer.
 */
static int
mxfs_shadow_eval_token(
	struct xlog			*log,
	struct mxfs_shadow_eval		*se,
	const struct xfs_buf_log_format	*blfp,
	const struct mxfs_auth_view	*av)
{
	struct xfs_mount		*mp = log->l_mp;
	const struct mxfs_shadow_lin	*lp = NULL;	/* earlier pair */
	bool				holds, lineage_bearing, held_match;
	uint64_t			epoch, man_lineage;
	int				rc;

	if (av->av_version == MXFS_BLF_AUTHORITY_V1) {
		/* design-consult ruling: v1 is NEVER authority evidence */
		se->v1_not_evidence++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	switch (av->av_class) {
	case MXFS_AUTH_CLASS_AG:
		/*
		 * Binding check: the claimed resource must be the AG the
		 * image physically lands in, else the token authorizes a
		 * DIFFERENT resource than the write it rides — label noise
		 * an exact gate must not credit.  (INODE class has no cheap
		 * daddr→inode reverse map; the evaluator trusts the
		 * producer's labeling there, the same trust the live apply
		 * path places in its own locking.  A realtime-device blkno
		 * would alias an AG number, but MXFS has no rtdev support.)
		 */
		if ((uint64_t)xfs_daddr_to_agno(mp, blfp->blf_blkno) !=
		    av->av_resource) {
			se->resource_mismatch++;
			return MXFS_RI_VERDICT_REFUSE;
		}
		break;
	case MXFS_AUTH_CLASS_INODE:
		break;
	case MXFS_AUTH_CLASS_SB:
		/* producer stamps SB with no resource/epoch by design */
		se->class_sb++;
		return MXFS_RI_VERDICT_REFUSE;
	case MXFS_AUTH_CLASS_NONE:
		se->classless++;
		return MXFS_RI_VERDICT_REFUSE;
	default:	/* ICLUS: no proven manifest mapping yet */
		se->class_unsupported++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	if (av->av_status != MXFS_AUTH_ST_VALID) {
		se->status_not_valid++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	if (av->av_owner_slot != log->l_mxfs_victim_slot) {
		se->foreign_owner++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	if (se->capable && av->av_owner_epoch != se->desc_victim_epoch) {
		unsigned int li;

		/*
		 * (§6.8.5): on a taken-over K the token may name an
		 * EARLIER incarnation of the slice — the original victim, or
		 * an old owner that adopted K under a term the lineage ended
		 * with K adopted.  That pair's sealed manifest + certificate
		 * judge it (no live check).  No pair ⇒ the refusals below.
		 */
		for (li = 0; li < se->nlin && !lp; li++)
			if (se->lin[li].victim_epoch == av->av_owner_epoch &&
			    se->lin[li].victim_epoch)
				lp = &se->lin[li];
		if (lp)
			se->lin_tokens++;
	}
	if (!lp && se->capable && av->av_owner_epoch != se->desc_victim_epoch) {
		/*
		 * (D-0354 lap 2, design-consult ruling): the victim durably
		 * classified its claim as a pass-2 FRESH claim, so every record
		 * of another incarnation of this slot (the owner-slot equality
		 * above already holds) was published before the victim could
		 * claim: a recovered slot is zeroed only at RECOVERY-COMPLETE, a
		 * released slot's log ends in an unmount record.  Such an image
		 * is a published predecessor's leftover inside the replay window
		 * (the empty-AIL tail fallback left it there — see the P308
		 * incarnation boundary), NOT torn victim work.  PREINC: the whole
		 * transaction skips clean (P310).  Without the certificate the
		 * refusal stands — age alone proves nothing.
		 */
		if (se->victim_adopted) {
			se->preincarnation++;
			return MXFS_RI_VERDICT_PREINC;
		}
		se->wrong_incarnation++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	rc = mxfs_shadow_manifest_lookup(log, mp, se, lp,
			log->l_mxfs_victim_slot, (uint8_t)av->av_class,
			av->av_resource, &holds, &epoch, &man_lineage);
	lineage_bearing = av->av_version >= MXFS_BLF_AUTHORITY_V3 &&
			  av->av_lineage != 0;
	/*
	 * (design-consult ruling precedence): (1) the frozen manifest says
	 * the victim HELD this exact {lineage, epoch} at death -> the
	 * held-at-death chain below decides APPLY; (2) otherwise an exact
	 * clean-release marker from the victim's own slice -> REDUNDANT_CLEAN;
	 * (3) otherwise the existing refusal terminals.  The marker check
	 * deliberately precedes the -ENOENT terminal: a cleanly released
	 * resource whose slot has since been tombstoned/recycled/re-bound
	 * answers ENOENT or wrong_lineage from the live table, and that is
	 * exactly the case the marker exists to certify.  Same capability and
	 * lineage rules as the enforceable terminal: a FENCED descriptor
	 * proves the incarnation the marker's owner_epoch is matched against,
	 * and a lineage-less token is never enforcement-ready.
	 */
	held_match = (rc == 0 && holds && epoch == av->av_grant_epoch &&
		      (!lineage_bearing || av->av_lineage == man_lineage));
	if (!held_match && se->capable && lineage_bearing &&
	    mxfs_relmark_lookup(log, (uint16_t)av->av_class, av->av_resource,
				av->av_lineage, av->av_grant_epoch,
				log->l_mxfs_victim_slot, av->av_owner_epoch)) {
		se->redundant_clean++;
		return MXFS_RI_VERDICT_REDUNDANT;
	}
	if (rc == -ENOENT) {
		/* definitive no-slot answer, not a read failure */
		se->not_held++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	if (rc != 0) {
		se->manifest_err++;
		return MXFS_RI_VERDICT_REFUSE;
	}

	/*
	 * compatibility series (ruling Q-C): the verdict the
	 * PRE-LINEAGE gate reaches, with unchanged semantics, so P273 samples
	 * 1-3 stay comparable.  Non-terminal by design — the token continues.
	 */
	if (holds && epoch == av->av_grant_epoch && se->capable)
		se->legacy_would_apply++;

	/*
	 * LINEAGE EQUALITY BEFORE THE HOLD CHECK (ruling Q-C).  A
	 * lineage mismatch means the manifest slot describes a DIFFERENT
	 * binding of this resource name than the one that issued the grant
	 * the token records — its hold bitmap and epoch are inapplicable to
	 * this token, so a holds-first order would mislabel the token as
	 * not_held.  Terminal for lineage-bearing tokens only; a lineage-less
	 * token (v2, or v3 minted before the grant's binding carried one)
	 * cannot be checked and flows on to the legacy layers unchanged.
	 * Equality only — lineage values carry no order or distance.
	 * (lineage_bearing is computed above, before the marker check.)
	 */
	if (lineage_bearing && av->av_lineage != man_lineage) {
		se->wrong_lineage++;
		return MXFS_RI_VERDICT_REFUSE;
	}

	if (!holds) {
		se->not_held++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	if (epoch != av->av_grant_epoch) {
		se->stale_epoch++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	/*
	 * Full manifest match.  Without a FENCED-stage descriptor the
	 * victim's incarnation was never proven (the owner-epoch test above
	 * was skipped), so this match cannot be credited as would-apply: an
	 * epoch collision from a PRIOR tenure of the same slot would pool
	 * into the headline number (D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID).
	 * Terminal uncapable_match keeps the would-apply family
	 * incarnation-proven — and, because adopted replay always runs
	 * !capable (the predecessor's descriptor is CONSUMED before a pass-2
	 * claim), makes it foreign-replay-only by construction.  An
	 * uncapable_match>0 on an adopted replay is the unpurged-manifest
	 * signal, preserved at full strength.
	 */
	if (!se->capable) {
		se->uncapable_match++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	/*
	 * ruling Q-C: a lineage-less full match is NOT
	 * enforcement-ready — the future gate requires v3 lineage equality,
	 * so counting it in the enforceable series would overstate readiness.
	 */
	if (!lineage_bearing) {
		se->v2_no_lineage++;
		return MXFS_RI_VERDICT_REFUSE;
	}
	se->enforceable_would_apply++;
	return MXFS_RI_VERDICT_APPLY;
}

/*
 * step 3b: REPORT-ONLY authority decode for untrusted (foreign or
 * adopted) replay.  This changes NO apply/skip decision — it proves the token
 * captured at CIL format time (step 3a) survives the log round-trip and
 * arrives at recovery with the right class/resource/epoch.
 *
 * step 5.0 — VERSION 1 IS REPORT-ONLY, PERMANENTLY.  The original
 * plan was for step 5 to swap the blanket untagged-skip for an exact
 * {class, resource, epoch} match here.  A design-consult ruling REFUTED that scope:
 * doing it on v1 tokens introduces a false APPLY, which is strictly worse
 * than the false SKIP it was meant to close.  v1 is not authority evidence
 * because it is derived from the buffer's physical location rather than the
 * resource that actually authorized the write, and mba_owner_boot is memset
 * 0 and never filled, so a record cannot be bound to a victim incarnation.
 *
 * A future exact gate must key on a v2 token (be64 resource, bound to the
 * victim slot AND incarnation) and must never accept version=1 as evidence,
 * no matter how much the producer side is improved.  step-5.1
 * producer fix (grant-state lifecycle + b_ops/BLFT conjunction) makes v1's
 * class=AG *honest*, but honest is not the same as sufficient.
 *
 * Runs under both settings of mxfs_foreign_replay_untagged_apply so the
 * foreign_replay_ab.sh A/B arms are directly comparable.
 */
/*
 * (foreign-replay step 5): teardown for the shadow authority
 * evaluator state hung on l_mxfs_shadow_eval.  EXACTLY ONE P273-SHADOW-EVAL
 * line is emitted per untrusted log, always: a full summary when the
 * evaluator ran, a state line when it never allocated (distinguishing "no
 * transactions reached pass 2" from "transactions went unevaluated", which
 * invalidates the measurement and must be visible).  Clearing
 * l_mxfs_victim_slot at the end is what makes the function idempotent for
 * both paths — the foreign replay path calls it explicitly and
 * xlog_dealloc_log calls it again as a backstop.  The evaluator that
 * allocates the state is the per-token verdict pass in
 * mxfs_report_replay_authority.
 */
void
mxfs_shadow_eval_finish(
	struct xlog			*log)
{
	struct mxfs_shadow_eval		*se = log->l_mxfs_shadow_eval;
	const char			*src = xlog_is_mxfs_foreign_replay(log) ?
						"foreign" : "adopted";
	uint64_t			csum;
	uint32_t			relmarks, relmark_overflow = 0;

	/* not an untrusted-replay log, or its summary already emitted */
	if (log->l_mxfs_victim_slot == MXFS_XLOG_VICTIM_NONE)
		return;
	relmarks = mxfs_relmark_tbl_count(log, &relmark_overflow);

	if (!se) {
		if (log->l_mxfs_shadow_missed)
			mxfs_xfs_probe(log->l_mp,
	"MXFS %s replay: P273-SHADOW-EVAL victim_slot=%u state=unevaluated missed_txns=%u",
				   src, log->l_mxfs_victim_slot,
				   log->l_mxfs_shadow_missed);
		else
			mxfs_xfs_probe(log->l_mp,
	"MXFS %s replay: P273-SHADOW-EVAL victim_slot=%u state=no_txns",
				   src, log->l_mxfs_victim_slot);
		log->l_mxfs_victim_slot = MXFS_XLOG_VICTIM_NONE;
		return;
	}

	/*
	 * Conservation: every buf item lands in exactly one terminal, so
	 * csum must equal buf.  Printed side by side so the analysis can
	 * assert it — an inequality is a counting bug in the evaluator.
	 */
	csum = se->untagged + se->malformed + se->v1_not_evidence +
	       se->classless + se->class_sb + se->class_unsupported +
	       se->status_not_valid + se->foreign_owner +
	       se->resource_mismatch + se->wrong_incarnation +
	       se->manifest_err + se->wrong_lineage + se->not_held +
	       se->stale_epoch + se->uncapable_match + se->v2_no_lineage +
	       se->enforceable_would_apply + se->redundant_clean +
	       se->preincarnation;

	/*
	 * WOULD_APPLY keeps the pre-lineage semantics (compatibility series,
	 * ruling Q-C) and is NON-TERMINAL, hence outside csum.  The
	 * enforceable series — the only one that may ever justify turning
	 * enforcement on — is ENFORCEABLE_WOULD_APPLY; nolineage counts full
	 * matches that lack the v3 lineage the future gate requires.
	 */
	mxfs_xfs_probe(log->l_mp,
	"MXFS %s replay: P273-SHADOW-EVAL victim_slot=%u capable=%d buf=%llu csum=%llu untagged=%llu malformed=%llu v1=%llu classless=%llu sb=%llu unsup=%llu badst=%llu fowner=%llu resmis=%llu winc=%llu manerr=%llu wlineage=%llu notheld=%llu staleep=%llu uncap_match=%llu nolineage=%llu WOULD_APPLY=%llu ENFORCEABLE_WOULD_APPLY=%llu REDUNDANT_CLEAN=%llu txn=%llu all_apply=%llu taint_blocked=%llu mixed=%llu none=%llu nonbuf_taint=%llu enforce_admitted=%llu txn_with_redundant=%llu redundant_skipped=%llu relmarks=%u relmark_overflow=%u uncached=%llu icreate=%llu/%llu/%llu missed_txns=%u victim_adopted=%d preinc=%llu txn_preinc=%llu",
		   src, log->l_mxfs_victim_slot, se->capable ? 1 : 0,
		   (unsigned long long)se->buf_items,
		   (unsigned long long)csum,
		   (unsigned long long)se->untagged,
		   (unsigned long long)se->malformed,
		   (unsigned long long)se->v1_not_evidence,
		   (unsigned long long)se->classless,
		   (unsigned long long)se->class_sb,
		   (unsigned long long)se->class_unsupported,
		   (unsigned long long)se->status_not_valid,
		   (unsigned long long)se->foreign_owner,
		   (unsigned long long)se->resource_mismatch,
		   (unsigned long long)se->wrong_incarnation,
		   (unsigned long long)se->manifest_err,
		   (unsigned long long)se->wrong_lineage,
		   (unsigned long long)se->not_held,
		   (unsigned long long)se->stale_epoch,
		   (unsigned long long)se->uncapable_match,
		   (unsigned long long)se->v2_no_lineage,
		   (unsigned long long)se->legacy_would_apply,
		   (unsigned long long)se->enforceable_would_apply,
		   (unsigned long long)se->redundant_clean,
		   (unsigned long long)se->txn_total,
		   (unsigned long long)se->txn_all_apply,
		   (unsigned long long)se->txn_buf_ok_taint_blocked,
		   (unsigned long long)se->txn_mixed,
		   (unsigned long long)se->txn_none,
		   (unsigned long long)se->txn_nonbuf_taint,
		   (unsigned long long)se->txn_enforce_admitted,
		   (unsigned long long)se->txn_with_redundant,
		   (unsigned long long)se->redundant_skipped,
		   relmarks, relmark_overflow,
		   (unsigned long long)se->uncached_reads,
		   (unsigned long long)se->icreate_apply,
		   (unsigned long long)se->icreate_redundant,
		   (unsigned long long)se->icreate_refused,
		   log->l_mxfs_shadow_missed,
		   se->victim_adopted ? 1 : 0,
		   (unsigned long long)se->preincarnation,
		   (unsigned long long)se->txn_preinc);
	mxfs_xfs_probe(log->l_mp,
	"MXFS %s replay: P-RMAN-EVAL victim_slot=%u manifest_rc=%d entries=%u seq=%llu no_caw=%d lookups=%llu hits=%llu live_checks=%llu live_check_err=%llu postseal_mutations=%llu abort=%d",
		   src, log->l_mxfs_victim_slot, se->manifest_rc, se->man_n,
		   (unsigned long long)se->man_seq, se->manifest_no_caw ? 1 : 0,
		   (unsigned long long)se->man_lookups,
		   (unsigned long long)se->man_hits,
		   (unsigned long long)se->live_checks,
		   (unsigned long long)se->live_check_err,
		   (unsigned long long)se->postseal_mutations,
		   se->rman_abort ? 1 : 0);
	kvfree(se->man_idx);
	kvfree(se->man_ents);	/* pal_alloc = kzalloc/vzalloc */
	{
		unsigned int li;

		for (li = 0; li < se->nlin; li++) {
			kvfree(se->lin[li].idx);
			kvfree(se->lin[li].ents);
		}
		if (se->nlin)
			xfs_notice(log->l_mp,
	"MXFS adopted replay: P-BOOT-K-COMPOSITE-EVAL victim_slot=%u pairs=%u lineage_tokens=%llu",
				   log->l_mxfs_victim_slot, se->nlin,
				   (unsigned long long)se->lin_tokens);
	}
	kvfree(se->tbl);
	kfree(se);
	log->l_mxfs_shadow_eval = NULL;
	log->l_mxfs_victim_slot = MXFS_XLOG_VICTIM_NONE;
}

/*
 * (#1, ruling): the per-transaction verdict feeds the
 * enforcement arm in xlog_recover_items_pass2.  Returns true iff THIS
 * transaction is admissible under the whole-txn rule: an evaluator exists,
 * every buffer image individually reached the enforceable terminal, and no
 * unauthorizable non-buf image (dquot/quotaoff/icreate) taints the txn.
 * The verdict is computed ONCE here, from the same evaluator state
 * (descriptor + manifest cache) the shadow series reports — shadow and
 * enforce can never disagree.  false on any evaluator-allocation failure
 * (fail closed; the miss is already tallied in l_mxfs_shadow_missed).
 */
static bool
mxfs_report_replay_authority(
	struct xlog			*log,
	struct xlog_recover		*trans,
	struct list_head		*item_list,
	int				sbverdict,
	bool				publish)
{
	static atomic_t			mxfs_tokdet_n = ATOMIC_INIT(0);
	static atomic_t			mxfs_toksum_n = ATOMIC_INIT(0);
	/*
	 * publish=false is the PURE decision (end-of-pass-1 CANCEL
	 * table decision, mxfs_cdefer_resolve): same evaluator inputs, same
	 * verdict, but every counter lands in a scratch copy of the evaluator
	 * and no telemetry line prints — pass 2 publishes exactly once.  The
	 * one fact that must survive the scratch is rman_abort (a post-seal
	 * mutation seen by the live check): it is copied back so pass 2 aborts
	 * at its first transaction boundary.
	 */
	struct mxfs_shadow_eval		*real_se = mxfs_shadow_eval_get(log);
	struct mxfs_shadow_eval		*scratch = NULL;
	struct mxfs_shadow_eval		*se = real_se;
	struct xlog_recover_item	*item;
	const char			*src = xlog_is_mxfs_foreign_replay(log) ?
						"foreign" : "adopted";
	int				n_buf = 0, n_tok = 0;
	int				n_ag = 0, n_sb = 0, n_none = 0;
	int				n_inode = 0, n_iclus = 0;
	int				n_v1 = 0, n_v2 = 0, n_v3 = 0;
	int				n_untag = 0, n_malf = 0;
	int				n_untag_cancel = 0;	/* untagged CANCEL items */
	int				n_wapply = 0, n_redund = 0;
	int				n_icreate = 0;
	bool				nonbuf_taint = false;
	bool				admissible = false;
	int				n_st[MXFS_AUTH_ST_MAX];
	/* classless images by BLFT — attributes an ATOMIC-SKIP */
	int				n_none_blft[XFS_BLFT_MAX_BUF];
	int				i;

	/*
	 * An untrusted log whose transactions pass through here without an
	 * evaluator (allocation failure — including a first-call failure
	 * followed by a later success) has a silently partial count.  Tally
	 * the misses so the final summary can disclose them.
	 */
	if (!se && log->l_mxfs_victim_slot != MXFS_XLOG_VICTIM_NONE && publish)
		log->l_mxfs_shadow_missed++;
	if (!publish && real_se) {
		scratch = kmemdup(real_se, sizeof(*real_se), GFP_KERNEL);
		/* no scratch = no evaluator for this decision: fail closed */
		se = scratch;
	}

	memset(n_st, 0, sizeof(n_st));
	memset(n_none_blft, 0, sizeof(n_none_blft));

	list_for_each_entry(item, item_list, ri_list) {
		struct mxfs_auth_view		av;
		struct xfs_buf_log_format	*blfp;
		enum mxfs_auth_parse		pr;
		int				n;

		if (ITEM_TYPE(item) != XFS_LI_BUF) {
			unsigned short t = ITEM_TYPE(item);

			/*
			 * (design review Q6): STRICT ALLOWLIST for the
			 * admissibility verdict.  The only non-buf items that
			 * do NOT taint are the ones with a proven-safe pass-2
			 * disposition of their own: XFS_LI_INODE (independent
			 * node-comparable di_changecount staleness gate — a
			 * skip there means disk is same-or-newer, a correct
			 * redo no-op, not a refusal) and the intent/done set
			 * the per-item loop always skips (P226, LSN-gated
			 * re-replay by the next mount-time claimer).
			 * EVERYTHING else — dquot/quotaoff/icreate as before,
			 * plus iunlink or any future item type — blocks
			 * all-authorized: an unknown type must never inherit
			 * admission by being absent from a blacklist.
			 */
			/*
			 * XFS_LI_MXFS_RELMARK is a clean-release
			 * marker — recovery metadata whose pass-2 disposition
			 * is a validated no-op (xlog_recover_relmark_commit_
			 * pass2).  It authorizes nothing and modifies nothing,
			 * so it cannot taint the transaction it rides in.
			 */
			/*
			 * (design-consult ruling, D-ICREATE-REPLAY-REINIT-
			 * CLOBBERS-PEER-INODES): XFS_LI_ICREATE is judged AFTER
			 * this loop from its AG-class buffer siblings (the very
			 * allocation's AGF/AGFL/AGI/inobt images) and its
			 * writer-time SYNCINIT proof — see below.  Until then it
			 * is neither admitted nor tainting.
			 */
			if (t == XFS_LI_ICREATE) {
				n_icreate++;
				item->ri_mxfs_verdict = MXFS_RI_VERDICT_REFUSE;
				continue;
			}
			if (t != XFS_LI_INODE && t != XFS_LI_MXFS_RELMARK &&
			    !(t == XFS_LI_EFI || t == XFS_LI_EFD ||
			      (t >= XFS_LI_RUI && t <= XFS_LI_CUD_RT)))
				nonbuf_taint = true;
			item->ri_mxfs_verdict = MXFS_RI_VERDICT_NONE;
			continue;
		}
		n_buf++;
		item->ri_mxfs_verdict = MXFS_RI_VERDICT_REFUSE;
		item->ri_mxfs_class = 0;
		if (se)
			se->buf_items++;
		blfp = item->ri_buf[0].iov_base;

		pr = mxfs_blf_parse_authority(item, &av);
		if (pr == MXFS_AUTH_PARSE_UNTAGGED) {
			/*
			 * (D-FOREIGN-SLICE-INTENTS-ABANDONED, chain 105
			 * s475a): with fix A's certificates installed the burst
			 * arm's rm transactions were still ATOMIC-SKIPPED on ONE
			 * untagged buffer item each (buf_items=6 tokened=5
			 * untagged=1).  Name it: a CANCEL item (xfs_trans_binval —
			 * a freed bmbt block; no data regions, never captured, so
			 * no trailer) is the hypothesis this probe decides.
			 */
			static atomic_t p_untag_n = ATOMIC_INIT(0);

			n_untag++;
			if (blfp->blf_flags & XFS_BLF_CANCEL)
				n_untag_cancel++;
			if (se)
				se->untagged++;
			if (publish && atomic_inc_return(&p_untag_n) <= 400)
				xfs_notice(log->l_mp,
		"MXFS %s replay: P227-UNTAGGED lsn=0x%llx blkno=%lld len=%u blft=%u flags=0x%x cancel=%d map_size=%u — buffer item with no authority trailer",
					   src, (unsigned long long)trans->r_lsn,
					   (long long)blfp->blf_blkno,
					   (unsigned int)blfp->blf_len,
					   (unsigned int)xfs_blft_from_flags(blfp),
					   (unsigned int)blfp->blf_flags,
					   (blfp->blf_flags & XFS_BLF_CANCEL) ? 1 : 0,
					   (unsigned int)blfp->blf_map_size);
			continue;
		}
		if (pr != MXFS_AUTH_PARSE_OK) {
			/*
			 * MALFORMED is counted SEPARATELY and never folded
			 * into "untagged" or "classless": an unusable trailer
			 * on a record that ASKED to be authority-checked is
			 * evidence about the log, not about the producer.
			 */
			n_malf++;
			if (se)
				se->malformed++;
			continue;
		}
		n_tok++;
		if (se) {
			int v = mxfs_shadow_eval_token(log, se, blfp, &av);

			item->ri_mxfs_verdict = (uint8_t)v;
			item->ri_mxfs_class = (uint8_t)av.av_class;	/* */
			if (v == MXFS_RI_VERDICT_APPLY)
				n_wapply++;
			else if (v == MXFS_RI_VERDICT_REDUNDANT)
				n_redund++;
		}
		if (av.av_version == MXFS_BLF_AUTHORITY_V1)
			n_v1++;
		else if (av.av_version == MXFS_BLF_AUTHORITY_V3)
			n_v3++;
		else
			n_v2++;
		if (av.av_status < MXFS_AUTH_ST_MAX)
			n_st[av.av_status]++;

		switch (av.av_class) {
		case MXFS_AUTH_CLASS_AG:
			n_ag++;
			break;
		case MXFS_AUTH_CLASS_SB:
			n_sb++;
			break;
		/*
		 * INODE and ICLUS are authority classes in their own right.
		 * They used to fall into the default arm below and be counted
		 * as "classless", which made the census report every correctly
		 * tokened inode/bmbt image as an image with no authority: a
		 * foreign-slice replay whose rm transactions were fully
		 * classed still printed classless=9, and the only reading of
		 * that number was a fix that had not worked.  Count them where
		 * they belong, so classless keeps its meaning -- an image
		 * carrying no authority we can name, which must fail closed.
		 */
		case MXFS_AUTH_CLASS_INODE:
			n_inode++;
			break;
		case MXFS_AUTH_CLASS_ICLUS:
			n_iclus++;
			break;
		default:
			n_none++;
			{
				uint16_t bt = xfs_blft_from_flags(blfp);

				if (bt < XFS_BLFT_MAX_BUF)
					n_none_blft[bt]++;
			}
			break;
		}

		if (!publish)
			continue;
		n = atomic_inc_return(&mxfs_tokdet_n);
		if (n > 400)
			continue;
		mxfs_xfs_probe(log->l_mp,
	"MXFS %s replay: P227-TOKEN blkno=%lld len=%u blft=%u v=%u class=%u st=%u res=%llu gepoch=%llu oepoch=%llu slot=%u node=%u lineage=%llu (n=%d)",
			   src, (long long)blfp->blf_blkno,
			   (unsigned int)blfp->blf_len,
			   (unsigned int)xfs_blft_from_flags(blfp),
			   (unsigned int)av.av_version,
			   (unsigned int)av.av_class,
			   (unsigned int)av.av_status,
			   (unsigned long long)av.av_resource,
			   (unsigned long long)av.av_grant_epoch,
			   (unsigned long long)av.av_owner_epoch,
			   (unsigned int)av.av_owner_slot,
			   (unsigned int)av.av_owner_node,
			   (unsigned long long)av.av_lineage, n);
	}

	/*
	 * ICREATE authority.  The chunk was carved from icl_ag under
	 * the AG EX grant the sibling AG-class images record; the record's
	 * SYNCINIT trailer proves every cluster was on the platter before the
	 * record existed, so pass 2 performs NO write for it (verify-and-skip,
	 * refuse on a non-verifying cluster).  Verdict, per the ruling:
	 *   - SYNCINIT proof AND >=1 AG sibling for icl_ag AND every AG
	 *     sibling for icl_ag is APPLY or REDUNDANT:
	 *       any APPLY  -> APPLY     (pass 2 verifies the clusters)
	 *       all REDUND -> REDUNDANT (pass 2 suppresses it entirely: the
	 *                    victim released the AG cleanly after the drain,
	 *                    a successor may have reused the extent — not
	 *                    even the verify read runs)
	 *   - anything else (no proof, no AG sibling, a REFUSED sibling):
	 *       REFUSE, and the transaction is tainted as before.
	 * A refused sibling dominates: one APPLY sibling never admits an
	 * ICREATE whose other required images were refused.
	 */
	if (n_icreate) {
		static atomic_t mxfs_icauth_n = ATOMIC_INIT(0);

		list_for_each_entry(item, item_list, ri_list) {
			struct xfs_icreate_log	*icl;
			struct xlog_recover_item *bi;
			xfs_agnumber_t		icl_ag;
			uint32_t		flags;
			int			na = 0, nr = 0, nx = 0;
			int			n;
			const char		*why;

			if (ITEM_TYPE(item) != XFS_LI_ICREATE)
				continue;
			icl = item->ri_buf[0].iov_base;
			if (item->ri_buf[0].iov_len < sizeof(*icl)) {
				nonbuf_taint = true;
				continue;
			}
			icl_ag = be32_to_cpu(icl->icl_ag);
			flags = mxfs_icreate_record_flags(item->ri_buf[0].iov_base,
							  item->ri_buf[0].iov_len);
			list_for_each_entry(bi, item_list, ri_list) {
				struct mxfs_auth_view bav;

				if (ITEM_TYPE(bi) != XFS_LI_BUF)
					continue;
				if (mxfs_blf_parse_authority(bi, &bav) !=
				    MXFS_AUTH_PARSE_OK)
					continue;
				if (bav.av_class != MXFS_AUTH_CLASS_AG ||
				    bav.av_resource != (uint64_t)icl_ag)
					continue;
				switch (bi->ri_mxfs_verdict) {
				case MXFS_RI_VERDICT_APPLY:
					na++;
					break;
				case MXFS_RI_VERDICT_REDUNDANT:
					nr++;
					break;
				default:
					nx++;
					break;
				}
			}
			if (!(flags & MXFS_ICL_F_SYNCINIT)) {
				why = "no-syncinit-proof";
			} else if (nx) {
				why = "ag-sibling-refused";
			} else if (!na && !nr) {
				why = "no-ag-sibling";
			} else {
				why = NULL;
				item->ri_mxfs_verdict = na ?
					MXFS_RI_VERDICT_APPLY :
					MXFS_RI_VERDICT_REDUNDANT;
				if (se) {
					if (na)
						se->icreate_apply++;
					else
						se->icreate_redundant++;
				}
			}
			if (why) {
				nonbuf_taint = true;
				if (se)
					se->icreate_refused++;
			}
			if (!publish)
				continue;
			n = atomic_inc_return(&mxfs_icauth_n);
			if (n <= 400)
				xfs_notice(log->l_mp,
	"MXFS %s replay: P-ICREATE-AUTH lsn=0x%llx agno=%u agbno=%u syncinit=%d ag_apply=%d ag_redundant=%d ag_refused=%d verdict=%s%s%s (n=%d)",
					   src, (unsigned long long)trans->r_lsn,
					   icl_ag, be32_to_cpu(icl->icl_agbno),
					   (flags & MXFS_ICL_F_SYNCINIT) ? 1 : 0,
					   na, nr, nx,
					   why ? "REFUSE" : (na ? "APPLY" : "REDUNDANT"),
					   why ? " why=" : "", why ? why : "", n);
		}
	}

	/*
	 * Transaction rollup — the ATOMIC-SKIP unit.  all_apply means the
	 * exact gate would have applied this ENTIRE transaction (every buf
	 * image individually authorized, no unauthorizable non-buf images):
	 * the population the blanket skip loses.  buf_ok_taint_blocked
	 * separates "every buf authorized but a non-buf image blocks the
	 * txn" from mixed — the first is unlockable by extending authority
	 * to non-buf classes, the second is not.  mixed would still have to
	 * skip atomically; none is the blanket skip agreeing with the gate.
	 * nonbuf_taint is an overlapping how-many-had-taint count, not a
	 * fifth exclusive category: total = all_apply + taint_blocked +
	 * mixed + none.
	 */
	/*
	 * a REDUNDANT_CLEAN image counts as AUTHORIZED for the
	 * whole-txn rule — its disposition (silent skip) is as decided as an
	 * APPLY's.  A txn whose every buffer image is APPLY or REDUNDANT is
	 * admissible; the pass-2 loop applies the former and skips the latter
	 * per item (the torn hazard of was skipping images NOT on the
	 * platter; these are certified on it).
	 */
	if (se && (n_buf || nonbuf_taint)) {
		se->txn_total++;
		if (nonbuf_taint)
			se->txn_nonbuf_taint++;
		if (n_buf && n_wapply + n_redund == n_buf) {
			if (nonbuf_taint) {
				se->txn_buf_ok_taint_blocked++;
			} else {
				se->txn_all_apply++;
				if (n_redund)
					se->txn_with_redundant++;
				admissible = true;
			}
		} else if (!n_wapply && !n_redund) {
			se->txn_none++;
		} else {
			se->txn_mixed++;
		}
	}

	if (scratch) {
		if (scratch->rman_abort)
			real_se->rman_abort = true;
		kfree(scratch);
		scratch = NULL;
	}

	if (n_buf && publish) {
		int n = atomic_inc_return(&mxfs_toksum_n);
		char stbuf[96];
		char nbbuf[96];
		int len = 0;
		int nlen = 0;
		int n_dino_none = 0, n_dino_agsib = 0;

		/*
		 * (design-consult ruling, fix shape B pre-code census): for
		 * every classless DINODE_BUF image (the iunlink di_next_
		 * unlinked update), is there an AG-class sibling image in
		 * this same transaction naming the AG the cluster lands in?
		 * That sibling (the AGI of the unlinked list) is the
		 * contemporaneous AG authority shape B would classify the
		 * image under; a classless DINODE image WITHOUT one is the
		 * cross-AG / no-authority case the ruling says must not exist.
		 */
		list_for_each_entry(item, item_list, ri_list) {
			struct mxfs_auth_view		dv;
			struct xfs_buf_log_format	*dblfp;
			struct xlog_recover_item	*sib;
			xfs_agnumber_t			dagno;
			bool				found = false;

			if (ITEM_TYPE(item) != XFS_LI_BUF)
				continue;
			if (mxfs_blf_parse_authority(item, &dv) != MXFS_AUTH_PARSE_OK)
				continue;
			dblfp = item->ri_buf[0].iov_base;
			if (dv.av_class != MXFS_AUTH_CLASS_NONE ||
			    xfs_blft_from_flags(dblfp) != XFS_BLFT_DINO_BUF)
				continue;
			n_dino_none++;
			dagno = xfs_daddr_to_agno(log->l_mp, dblfp->blf_blkno);
			list_for_each_entry(sib, item_list, ri_list) {
				struct mxfs_auth_view sv;

				if (ITEM_TYPE(sib) != XFS_LI_BUF)
					continue;
				if (mxfs_blf_parse_authority(sib, &sv) !=
				    MXFS_AUTH_PARSE_OK)
					continue;
				if (sv.av_class == MXFS_AUTH_CLASS_AG &&
				    sv.av_status == MXFS_AUTH_ST_VALID &&
				    sv.av_resource == (uint64_t)dagno) {
					found = true;
					break;
				}
			}
			if (found)
				n_dino_agsib++;
		}

		for (i = 0; i < MXFS_AUTH_ST_MAX; i++) {
			if (!n_st[i] || len >= (int)sizeof(stbuf) - 16)
				continue;
			len += scnprintf(stbuf + len, sizeof(stbuf) - len,
					 " s%d=%d", i, n_st[i]);
		}
		stbuf[len] = '\0';
		for (i = 0; i < XFS_BLFT_MAX_BUF; i++) {
			if (!n_none_blft[i] || nlen >= (int)sizeof(nbbuf) - 16)
				continue;
			nlen += scnprintf(nbbuf + nlen, sizeof(nbbuf) - nlen,
					  " t%d=%d", i, n_none_blft[i]);
		}
		nbbuf[nlen] = '\0';

		if (n <= 2000)
			mxfs_xfs_probe(log->l_mp,
	"MXFS %s replay: P227-TOKENSUM lsn=0x%llx buf_items=%d tokened=%d v1=%d v2=%d v3=%d ag=%d sb=%d ino=%d iclus=%d classless=%d untagged=%d untag_cancel=%d malformed=%d wapply=%d redundant=%d wskip=%d sbclean=%d st:%s classless_blft:%s dino_none=%d dino_agsib=%d",
				   src, (unsigned long long)trans->r_lsn,
				   n_buf, n_tok, n_v1, n_v2, n_v3, n_ag, n_sb,
				   n_inode, n_iclus,
				   n_none, n_untag, n_untag_cancel, n_malf,
				   se ? n_wapply : -1,
				   se ? n_redund : -1,
				   se ? n_buf - n_wapply - n_redund : -1,
				   sbverdict,
				   len ? stbuf : " none",
				   nlen ? nbbuf : " none",
				   n_dino_none, n_dino_agsib);
	}
	return admissible;
}

/*
 * Use-time enforcement predicate for one untrusted log.  enforce_cfg is
 * the attempt-local preflight verdict (see mxfs_fr_enforce_preflight) —
 * FOREIGN only and proto-admission-pinned by construction, since only the
 * preflight sets the mode and only for a foreign shadow log on an admitted
 * mount.  Adopted replay keeps blanket refusal twice over: its mode is
 * never set AND it runs !capable (the predecessor's descriptor is consumed
 * before a pass-2 claim).  The explicit foreign check is a belt in case a
 * future caller sets the mode on a non-foreign log.
 */
/* did the evaluator detect a post-seal authority mutation under
 * enforcement?  Report-only replay never applies tokenized images, so a
 * mutation seen there is telemetry (counted, logged) and not a verdict. */
bool
mxfs_fr_shadow_mutated(
	struct xlog			*log)
{
	return log->l_mxfs_rman_mutated && log->l_mxfs_fr_enforce_mode != 0 &&
	       xlog_is_mxfs_foreign_replay(log);
}

static bool
mxfs_fr_enforcement_active(
	struct xlog			*log)
{
	struct mxfs_shadow_eval		*se = log->l_mxfs_shadow_eval;

	if (!se || !se->enforce_cfg || !se->capable)
		return false;
	/* the bootstrap owner's adopted slot K is an own log whose
	 * replay is ENFORCED by the escrowed certificate (5d ruling: FULL,
	 * authority-evaluated); enforcement-off there refused every
	 * buffer-carrying transaction of a dirty K (chain 28 s442a) */
	if (!xlog_is_mxfs_foreign_replay(log) &&
	    !xlog_is_mxfs_bootstrap_adopted(log))
		return false;
	return true;
}

/*
 * (#1, ruling; reshaped per the design review):
 * enforcement preflight at elected-recovery entry, called by
 * mxfs_xlog_recover_foreign_slice BEFORE xlog_recover so an abort has
 * ZERO replay side effects.  This is the ONLY place the attempt-local
 * l_mxfs_fr_enforce_mode is ever set — the whole attempt then runs under
 * this one verdict and no global-knob flip after this point can change it
 * (design review Q3: no OFF->ARMED transition after the preflight point).
 *
 * With the knob armed, the outcome is one of:
 *   - config invalid (an F2 domain param raced the setter's validation):
 *     ABORT retryably and LOUDLY — an armed knob must never silently
 *     degrade to enforcement-off blanket refusal (design review Q5);
 *   - proto not admitted (mixed-version fleet): explicit logged DEMOTE to
 *     the old blanket-refusal behavior for this attempt — fail closed and
 *     attributable, chosen over an abort that could never terminate on a
 *     genuinely mixed fleet;
 *   - evaluator allocation failed or the victim's FENCED descriptor is
 *     unproven: ABORT retryably — enforcing against an unproven
 *     incarnation could credit a prior tenure's epoch, and blanket
 *     refusal would instead publish the refusal cascade the gate exists
 *     to end;
 *   - otherwise: mode ARMED; the evaluator (one descriptor read, cached
 *     on the log, consumed by every per-txn verdict) carries it.
 *
 * The abort errnos are deliberately NOT -EFSCORRUPTED: the verdict reason
 * stays NONE, so no terminal outcome publishes and the slice stays dirty.
 * Both call paths are VERIFIED to key retry-vs-terminal on the verdict
 * reason, not the errno: the reap loop re-arms MXFS_REAPF_FREPLAY and the
 * mount barrier leaves the slot in the cut for later rounds.
 */
int
mxfs_fr_enforce_preflight(
	struct xlog			*log)
{
	struct mxfs_shadow_eval		*se;
	bool				cfg_ok;

	if (!xlog_is_mxfs_foreign_replay(log) &&
	    !xlog_is_mxfs_bootstrap_adopted(log))
		return 0;
	/* on the adopted slot K enforcement is not a knob — the
	 * ruling's own-log replay is authority-evaluated or it does not run */
	if (!READ_ONCE(mxfs_foreign_replay_token_enforce) &&
	    !xlog_is_mxfs_bootstrap_adopted(log))
		return 0;

	mutex_lock(&mxfs_fr_cfg_lock);
	cfg_ok = !(READ_ONCE(mxfs_fua_disable) &&
		   !READ_ONCE(mxfs_target_cache_protected)) &&
		 mxfs_release_proof_enforce;
	mutex_unlock(&mxfs_fr_cfg_lock);
	if (!cfg_ok) {
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P227-FR-ENFORCE-CFG-ABORT victim_slot=%u — foreign_replay_token_enforce is armed but its F2/proof prerequisites no longer hold; refusing to run enforcement-off under an armed knob, aborting elected recovery (slice stays dirty, retryable)",
			  log->l_mxfs_victim_slot);
		return -EIO;
	}
	if (!log->l_mp->m_mxfs_proto_admitted) {
		xfs_notice(log->l_mp,
	"MXFS foreign replay: P227-FR-ENFORCE-PROTO-DEMOTE victim_slot=%u — token enforcement armed but this mount lacks proto admission (mixed-version fleet); this attempt keeps blanket refusal",
			   log->l_mxfs_victim_slot);
		return 0;
	}

	log->l_mxfs_fr_enforce_mode = 1;
	se = mxfs_shadow_eval_get(log);
	if (!se) {
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P227-FR-ENFORCE-PREFLIGHT-ABORT victim_slot=%u — evaluator allocation failed with token enforcement configured; aborting elected recovery (slice stays dirty, retryable)",
			  log->l_mxfs_victim_slot);
		return -ENOMEM;
	}
	if (!se->capable) {
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P227-FR-ENFORCE-DESC-ABORT victim_slot=%u desc_rc=%d stage=%u — token enforcement configured but the victim's FENCED descriptor is unproven; aborting elected recovery (slice stays dirty, retryable)",
			  log->l_mxfs_victim_slot, se->desc_rc,
			  (unsigned int)se->desc_stage);
		return -EIO;
	}
	/*
	 * under enforcement the verdict source is the sealed
	 * fence-time manifest and nothing else.  A manifest that did not load
	 * (unsealed, corrupt, pointer mismatch, unreadable) leaves no sound
	 * source — never fall back to live authority; abort retryably with the
	 * slice dirty.  P-RMAN-INVALID already named the reason.
	 */
	if (se->manifest_rc == -EPROTO) {
		/* structural: deterministic, nothing can re-snapshot a FENCED
		 * victim — TERMINAL (MANIFEST_INVALID), see foreign_slice */
		log->l_mxfs_rman_invalid = true;
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P-RMAN-INVALID-TERMINAL victim_slot=%u rc=%d — the victim's sealed fence-time manifest fails validation; publishing TERMINAL FSWIDE quarantine (nothing purged, slice stays frozen, operator action)",
			  log->l_mxfs_victim_slot, se->manifest_rc);
		return -EFSCORRUPTED;
	}
	if (se->manifest_rc != 0) {
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P-RMAN-LOAD-ABORT victim_slot=%u rc=%d — token enforcement configured but the victim's sealed fence-time manifest could not be read; aborting elected recovery (slice stays dirty, retryable, nothing purged)",
			  log->l_mxfs_victim_slot, se->manifest_rc);
		return -EIO;
	}
	/*
	 * (D-RMAN-MUTATED-SLICE-REPLAYED-BEFORE-VERIFY-408): verify the
	 * WHOLE sealed manifest against the live table BEFORE a single record
	 * is applied.  The per-record current-safety check only covers the
	 * entries the replayed records happen to reference, and the pre-purge
	 * verify runs after the slice has been applied — so a mutation of an
	 * unreferenced entry let the mutated victim's slice replay to
	 * completion and only then publish MUTATED-TERMINAL (0.26.3 matrix
	 * mutate2, test1: slot 17 complete at 616.13 s, POSTSEAL-MUTATION
	 * site=prepurge at 616.156 s).  "Slice stays frozen" must mean frozen:
	 * a mutation anywhere in the frozen authority set is the broken
	 * invariant, and the verdict is taken here with zero replay side
	 * effects.  Same comparison as the per-record check and the pre-purge
	 * verify; an undecidable live read aborts retryably (reason NONE).
	 */
	if (!se->manifest_no_caw && se->man_n && se->man_ents) {
		uint32_t i, checked = 0, bad = 0, unsupported = 0;
		int err = 0;

		for (i = 0; i < se->man_n; i++) {
			const struct mxfs_rman_entry *e = &se->man_ents[i];
			bool lh = false;
			uint64_t le = 0, ll = 0;
			uint8_t lm = 0;
			uint32_t lidx = UINT32_MAX;
			int lrc;

			lrc = mxfs_v5_dlm_victim_live_read(log->l_mp->m_mxfs_dlm,
					e->type, e->id, log->l_mxfs_victim_slot,
					&lh, &le, &ll, &lm, &lidx);
			if (lrc == -EOPNOTSUPP) {
				unsupported++;
				continue;
			}
			if (lrc == 0 && lh && le == e->grant_epoch &&
			    ll == e->lineage && lm == e->mode &&
			    lidx == e->slot_idx) {
				checked++;
				continue;
			}
			if (lrc == 0 || lrc == -ENOENT) {
				bad++;
				xfs_alert(log->l_mp,
	"MXFS foreign replay: P-RMAN-POSTSEAL-MUTATION site=prereplay victim_slot=%u type=%u id=%llu manifest{mode=0x%x idx=%u lineage=%llu epoch=%llu} live{rc=%d holds=%d mode=0x%x idx=%u lineage=%llu epoch=%llu} — the victim's fence-time authority changed after the seal; broken recovery invariant: TERMINAL before any record is applied (nothing replayed, nothing purged)",
					  log->l_mxfs_victim_slot, e->type,
					  (unsigned long long)e->id, e->mode,
					  e->slot_idx,
					  (unsigned long long)e->lineage,
					  (unsigned long long)e->grant_epoch,
					  lrc, lh ? 1 : 0, lm, lidx,
					  (unsigned long long)ll,
					  (unsigned long long)le);
				continue;
			}
			err = lrc;		/* undecidable: I/O */
			break;
		}
		mxfs_xfs_probe(log->l_mp,
	"MXFS foreign replay: P-RMAN-PREREPLAY-VERIFY victim_slot=%u entries=%u checked=%u mutated=%u unsupported=%u err=%d",
			   log->l_mxfs_victim_slot, se->man_n, checked, bad,
			   unsupported, err);
		if (bad) {
			se->postseal_mutations += bad;
			se->rman_abort = true;
			log->l_mxfs_rman_mutated = true;
			/* the caller's mutated check promotes this to
			 * -EFSCORRUPTED + AUTHORITY_MUTATED (FSWIDE terminal) */
			return -EIO;
		}
		if (err) {
			se->live_check_err++;
			se->rman_abort = true;
			xfs_alert(log->l_mp,
	"MXFS foreign replay: P-RMAN-LIVECHECK-ERR victim_slot=%u site=prereplay rc=%d — the current-safety read of a manifest entry's live slot failed; the manifest cannot be confirmed safe and the attempt ABORTS before any record is applied (retryable)",
				  log->l_mxfs_victim_slot, err);
			return -EIO;
		}
	}
	return 0;
}

/*
 * (ruling, D-513): map a REFUSED log item to the AG it would
 * have modified, accumulating the quarantine domain for the terminal outcome
 * record.  Anything that cannot be mapped confidently — unmappable item
 * type, malformed format, agno beyond the 64-bit mask — widens the domain to
 * the whole filesystem: refusing too much is safe, refusing too little
 * re-creates the suppressed-work hazard the quarantine exists to stop.
 */
STATIC void
mxfs_refused_item_domain(
	struct xlog			*log,
	struct xlog_recover_item	*item)
{
	struct xfs_mount	*mp = log->l_mp;
	unsigned short		t = ITEM_TYPE(item);
	xfs_agnumber_t		agno;

	switch (t) {
	case XFS_LI_BUF: {
		struct xfs_buf_log_format *blf = item->ri_buf[0].iov_base;

		if (item->ri_buf[0].iov_len <
		    offsetof(struct xfs_buf_log_format, blf_map_size)) {
			log->l_mxfs_malformed_skips++;
			log->l_mxfs_refused_fswide = true;
			return;
		}
		agno = xfs_daddr_to_agno(mp, blf->blf_blkno);
		break;
	}
	case XFS_LI_INODE: {
		struct xfs_inode_log_format *ilf = item->ri_buf[0].iov_base;

		if (item->ri_buf[0].iov_len != sizeof(*ilf)) {
			/* legacy 32-bit padding variant or torn format —
			 * unmappable without conversion; go fswide */
			log->l_mxfs_malformed_skips++;
			log->l_mxfs_refused_fswide = true;
			return;
		}
		agno = XFS_INO_TO_AGNO(mp, ilf->ilf_ino);
		break;
	}
	case XFS_LI_ICREATE: {
		struct xfs_icreate_log *icl = item->ri_buf[0].iov_base;

		if (item->ri_buf[0].iov_len < sizeof(*icl)) {
			log->l_mxfs_malformed_skips++;
			log->l_mxfs_refused_fswide = true;
			return;
		}
		agno = be32_to_cpu(icl->icl_ag);
		break;
	}
	default:
		/* dquot/quotaoff/intents: no single-AG home */
		log->l_mxfs_refused_fswide = true;
		return;
	}

	if (agno >= mp->m_sb.sb_agcount || agno >= 64) {
		log->l_mxfs_refused_fswide = true;
		return;
	}
	log->l_mxfs_refused_ag_mask |= 1ULL << agno;
}

/*
 * (D-529): classify the WHOLE untrusted transaction exactly once,
 * over the COMPLETE assembled item queue, at commit entry — before any
 * pass-2 batch is drained.  The former in-batch classification saw only
 * the current 100-item batch (XLOG_RECOVER_COMMIT_QUEUE_MAX), so the
 * "whole-txn" ADMIT / ATOMIC-SKIP unit silently degraded to a per-batch
 * unit for large transactions.  Everything the classifier consumes (the
 * SB counter scan, the per-item token evaluation + TOKENSUM/SHADOW
 * telemetry, per-item ri_mxfs_verdict) walks trans->r_itemq here; the
 * returned MXFS_TXNV_* verdict is cached on the trans and consumed by
 * every batch.  Runs for every untrusted replay (report-only included) —
 * the untagged_apply knob only gates CONSUMPTION, exactly as before.
 */
static uint8_t
mxfs_classify_untrusted_txn(
	struct xlog		*log,
	struct xlog_recover	*trans,
	bool			publish)
{
	struct xlog_recover_item *item;
	int			sbverdict;
	bool			admissible;
	int			n_items = 0;
	bool			tainted = false;

	sbverdict = mxfs_sb_counter_only_txn(log, &trans->r_itemq);
	admissible = mxfs_report_replay_authority(log, trans,
						  &trans->r_itemq, sbverdict,
						  publish);

	list_for_each_entry(item, &trans->r_itemq, ri_list) {
		unsigned short t = ITEM_TYPE(item);

		n_items++;
		if (t == XFS_LI_BUF || t == XFS_LI_DQUOT ||
		    t == XFS_LI_QUOTAOFF || t == XFS_LI_ICREATE)
			tainted = true;
	}

	/*
	 * (D-529 verification): simulate an unauthorized image in a
	 * LATER batch of a large transaction.  Pre-fix, batch 1 of this txn
	 * earned ADMIT and applied while a later batch earned ATOMIC-SKIP —
	 * a partial apply.  With the whole-txn verdict the ENTIRE transaction
	 * must take the refusal arm below and zero images may apply.
	 */
	if (unlikely(mxfs_dbg_fr_taint_items_over > 0) &&
	    n_items > mxfs_dbg_fr_taint_items_over) {
		if (publish)
			xfs_notice(log->l_mp,
"MXFS %s replay: P-DBG-FR-TAINT-INJECT lsn=0x%llx items=%d over=%d — forcing whole-txn ATOMIC-SKIP (D-529 fault injection)",
			   xlog_is_mxfs_foreign_replay(log) ?
			   "foreign" : "adopted",
			   (unsigned long long)trans->r_lsn, n_items,
			   mxfs_dbg_fr_taint_items_over);
		admissible = false;
		sbverdict = MXFS_SBCLEAN_NOTSB;
		tainted = true;
		goto refuse;
	}

	if (!tainted)
		return MXFS_TXNV_UNTAINTED;

	/*
	 * (D-0354 lap 2): a PREVIOUS incarnation's transaction in an
	 * ADOPTED victim's slice.  A transaction is written by exactly one
	 * incarnation, so one PREINC token classifies it; every other buffer
	 * image must then be PREINC or untagged (a tagged current-incarnation
	 * sibling is impossible and fails closed into the refusal arm below).
	 * Published by construction — skip clean: no images, no inode items,
	 * no intents into the census, no quarantine domain.
	 */
	{
		int n_preinc = 0, n_cur = 0;

		list_for_each_entry(item, &trans->r_itemq, ri_list) {
			if (ITEM_TYPE(item) != XFS_LI_BUF)
				continue;
			if (item->ri_mxfs_verdict == MXFS_RI_VERDICT_PREINC)
				n_preinc++;
			else if (item->ri_mxfs_verdict == MXFS_RI_VERDICT_APPLY ||
				 item->ri_mxfs_verdict == MXFS_RI_VERDICT_REDUNDANT)
				n_cur++;
		}
		if (n_preinc && !n_cur && log->l_mxfs_shadow_eval &&
		    log->l_mxfs_shadow_eval->victim_adopted) {
			static atomic_t mxfs_preinc_n = ATOMIC_INIT(0);
			int n = publish ? atomic_inc_return(&mxfs_preinc_n) : 0;

			if (!publish)
				return MXFS_TXNV_PREINC;
			log->l_mxfs_shadow_eval->txn_preinc++;
			if (n <= 2000)
				xfs_notice(log->l_mp,
	"MXFS %s replay: P310-FR-PREINCARNATION-SKIP lsn=0x%llx items=%d preinc_images=%d — a PREVIOUS incarnation's transaction in an ADOPTED victim's slice (victim record carried MXFS_HB_FEAT_ADOPTED: published before the victim could claim); skipped clean, not refused",
					   xlog_is_mxfs_foreign_replay(log) ?
					   "foreign" : "adopted",
					   (unsigned long long)trans->r_lsn,
					   n_items, n_preinc);
			return MXFS_TXNV_PREINC;
		}
	}

	/*
	 * (ruling): the kind-17 + victim-snlocal conjunction
	 * authorizes untagged images on THIS shadow xlog — the victim durably
	 * classified its log single-node-local at write time, so no
	 * cross-node authority question exists and the tear the atomic skip
	 * prevents cannot arise.
	 */
	if (log->l_mxfs_untagged_authorized) {
		static atomic_t mxfs_snaccept_n = ATOMIC_INIT(0);
		int n = publish ? atomic_inc_return(&mxfs_snaccept_n) : 0;

		if (publish && n <= 2000)
			xfs_notice(log->l_mp,
"MXFS %s replay: applying untagged transaction lsn=0x%llx items=%d under kind-17 + victim snlocal marker (P227-SNLOCAL-ACCEPT)",
				   xlog_is_mxfs_foreign_replay(log) ?
				   "foreign" : "adopted",
				   (unsigned long long)trans->r_lsn, n_items);
		return MXFS_TXNV_SNLOCAL;
	}

	/*
	 * (#1, ruling): ENFORCEMENT ADMIT.  Every buffer
	 * image in this transaction individually reached the enforceable
	 * terminal (v3 lineage + FENCED-proven incarnation + held manifest
	 * grant + epoch match) and no unauthorizable non-buf image rides
	 * along — the whole-txn unit the ATOMIC-SKIP protects is authorized,
	 * so apply ALL of it.  The per-item P223 skip honors the ADMIT
	 * verdict; XFS_LI_INODE items keep their node-independent
	 * di_changecount gate in commit_pass2 (authority AND changecount,
	 * per the ruling).  Nothing here counts as a refusal.
	 */
	if (admissible && mxfs_fr_enforcement_active(log)) {
		static atomic_t mxfs_fradmit_n = ATOMIC_INIT(0);
		int n = publish ? atomic_inc_return(&mxfs_fradmit_n) : 0;

		if (!publish)
			return MXFS_TXNV_ADMIT;
		log->l_mxfs_shadow_eval->txn_enforce_admitted++;
		if (n <= 2000)
			mxfs_xfs_probe(log->l_mp,
"MXFS foreign replay: ADMIT fully-tokenized transaction lsn=0x%llx items=%d — every buffer image carries an enforceable authority verdict (APPLY or REDUNDANT_CLEAN) (P227-FR-ENFORCE-ADMIT n=%d)",
				   (unsigned long long)trans->r_lsn,
				   n_items, n);
		return MXFS_TXNV_ADMIT;
	}

	/*
	 * (#94): counter-only SB transaction — skip it CLEAN.  Lazy
	 * SB counters are reconstructible (mxfs mounts recompute them from
	 * AGF/AGI unconditionally): NOT a refusal, no torn-verdict arming,
	 * nothing added to the quarantine domain.
	 */
	if (sbverdict == MXFS_SBCLEAN_OK) {
		static atomic_t mxfs_sbclean_n = ATOMIC_INIT(0);
		int n = publish ? atomic_inc_return(&mxfs_sbclean_n) : 0;

		if (!publish)
			return MXFS_TXNV_SBCLEAN;
		log->l_mxfs_sbclean_skips++;
		if (n <= 2000)
			xfs_notice(log->l_mp,
"MXFS %s replay: CLEAN-SKIP counter-only SB transaction lsn=0x%llx items=%d — lazy counters are recomputed from AGF/AGI at every mxfs mount (P227-FR-SBCOUNTER-CLEANSKIP)",
				   xlog_is_mxfs_foreign_replay(log) ?
				   "foreign" : "adopted",
				   (unsigned long long)trans->r_lsn, n_items);
		return MXFS_TXNV_SBCLEAN;
	}

refuse:
	if (!publish)
		return MXFS_TXNV_SKIP;
	{
		static atomic_t mxfs_fratomic_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&mxfs_fratomic_n);

		log->l_mxfs_untagged_skips++;
		/* every item of the refused transaction is work that
		 * will never be applied — fold each into the quarantine
		 * domain. */
		list_for_each_entry(item, &trans->r_itemq, ri_list)
			mxfs_refused_item_domain(log, item);
		if (n <= 2000)
			xfs_notice(log->l_mp,
"MXFS %s replay: ATOMIC-SKIP whole transaction lsn=0x%llx items=%d — contains unauthorized image(s); partial apply would tear (P227-FR-ATOMIC-SKIP sbreason=%d)",
				   xlog_is_mxfs_foreign_replay(log) ?
				   "foreign" : "adopted",
				   (unsigned long long)trans->r_lsn,
				   n_items, sbverdict);
	}
	return MXFS_TXNV_SKIP;
}

/*
 * (D-FOREIGN-SLICE-INTENTS-ABANDONED, CANCEL authority tokens —
 * Design-consult ruling cancel-item-
 * untagged-fixA-tokenize-binval-pass1-verdict-aware, part 4): the pass-1
 * buffer cancel table is built from ADMITTED transactions only.
 *
 * The hazard: xlog_recover_buf_commit_pass1 adds every XFS_BLF_CANCEL to
 * l_buf_cancel_table before any verdict exists, so a transaction pass 2 then
 * REFUSES (ATOMIC-SKIP, no puts) leaves its entries in place and they suppress
 * an EARLIER, ADMITTED transaction's image of the same block — that admitted
 * transaction is torn before any quarantine publishes, and removing the
 * entries when pass 2 reaches the refused transaction is too late.
 *
 * Why not decide inline in pass 1: the REDUNDANT_CLEAN verdict consults the
 * victim's clean-release markers, and those are inserted by pass 1 AS IT
 * REACHES THEM (xlog_recover_relmark_commit_pass1), so an early transaction
 * classified inline would miss a later marker and refuse what pass 2 admits
 * — common, not rare: a per-AG release lands after almost every AG image.
 * So a CANCEL-bearing transaction is PARKED (mxfs_cdefer_stash: its items
 * are kept, its cancel entries were added as before) and decided once the
 * pass-1 walk is complete (mxfs_cdefer_resolve): the same classifier, with
 * the complete marker table and the sealed manifest, run PURE (no telemetry,
 * counters into a scratch evaluator); a transaction whose verdict means
 * "pass 2 will not run its items" (SKIP / SBCLEAN / PREINC) has one
 * xlog_put_buffer_cancelled per CANCEL item — exactly undoing its adds.
 * The verdict is remembered by (tid, lsn) and pass 2 verifies it reached the
 * same one (mxfs_cdefer_verify; a mismatch aborts the attempt, retryable,
 * nothing published).  Report-only apply-all mode (untagged_apply knob)
 * processes every item in pass 2, so nothing is parked there.
 */
STATIC void xlog_recover_free_trans(struct xlog_recover *trans);

struct mxfs_cdefer_ent {
	struct hlist_node	node;
	xfs_lsn_t		lsn;
	xlog_tid_t		tid;
	uint8_t			verdict;
};
#define MXFS_CDEFER_HT_SIZE	256U

static inline struct hlist_head *
mxfs_cdefer_bucket(struct xlog *log, xlog_tid_t tid, xfs_lsn_t lsn)
{
	uint64_t h = (uint64_t)lsn ^ ((uint64_t)lsn >> 32) ^ (uint64_t)tid;

	return &log->l_mxfs_cdefer_ht[h & (MXFS_CDEFER_HT_SIZE - 1)];
}

static inline bool
mxfs_txnv_skips_items(uint8_t v)
{
	return v == MXFS_TXNV_SKIP || v == MXFS_TXNV_SBCLEAN ||
	       v == MXFS_TXNV_PREINC;
}

static inline bool
mxfs_cdefer_armed(struct xlog *log)
{
	/* initialised by xlog_do_log_recovery; a zeroed head is "not armed" */
	return log->l_mxfs_cdefer.next != NULL &&
	       xlog_is_mxfs_untrusted_replay(log) &&
	       !mxfs_foreign_replay_untagged_apply;
}

/* pass 1, after the item walk: park a CANCEL-bearing untrusted transaction */
static void
mxfs_cdefer_stash(
	struct xlog		*log,
	struct xlog_recover	*trans)
{
	struct xlog_recover_item *item;
	int			n = 0;

	if (!mxfs_cdefer_armed(log))
		return;
	list_for_each_entry(item, &trans->r_itemq, ri_list) {
		struct xfs_buf_log_format *blf;

		if (ITEM_TYPE(item) != XFS_LI_BUF)
			continue;
		if (!xfs_buf_log_check_iovec(&item->ri_buf[0]))
			continue;
		blf = item->ri_buf[0].iov_base;
		if (blf->blf_flags & XFS_BLF_CANCEL)
			n++;
	}
	if (!n)
		return;
	trans->r_mxfs_ncancel = n;
	trans->r_mxfs_deferred = true;
	INIT_LIST_HEAD(&trans->r_mxfs_defer);
	list_add_tail(&trans->r_mxfs_defer, &log->l_mxfs_cdefer);
	log->l_mxfs_p1_txn_deferred++;
}

/* end of pass 1: decide every parked transaction with the complete inputs */
static int
mxfs_cdefer_resolve(
	struct xlog		*log)
{
	struct xlog_recover	*trans, *next;
	uint32_t		txns = 0, refused = 0, kept = 0, supp = 0;

	if (!log->l_mxfs_cdefer.next || list_empty(&log->l_mxfs_cdefer))
		return 0;
	if (!log->l_mxfs_cdefer_ht) {
		log->l_mxfs_cdefer_ht = kcalloc(MXFS_CDEFER_HT_SIZE,
						sizeof(struct hlist_head),
						GFP_KERNEL);
		if (!log->l_mxfs_cdefer_ht)
			return -ENOMEM;		/* no decision = no attempt */
	}
	list_for_each_entry_safe(trans, next, &log->l_mxfs_cdefer,
				 r_mxfs_defer) {
		struct mxfs_cdefer_ent	*e;
		struct xlog_recover_item *item;
		uint8_t			v;

		v = mxfs_classify_untrusted_txn(log, trans, false);
		e = kzalloc(sizeof(*e), GFP_KERNEL);
		if (!e)
			return -ENOMEM;
		e->lsn = trans->r_lsn;
		e->tid = trans->r_log_tid;
		e->verdict = v;
		hlist_add_head(&e->node,
			       mxfs_cdefer_bucket(log, e->tid, e->lsn));
		txns++;
		if (mxfs_txnv_skips_items(v)) {
			refused++;
			list_for_each_entry(item, &trans->r_itemq, ri_list) {
				struct xfs_buf_log_format *blf;

				if (ITEM_TYPE(item) != XFS_LI_BUF)
					continue;
				if (!xfs_buf_log_check_iovec(&item->ri_buf[0]))
					continue;
				blf = item->ri_buf[0].iov_base;
				if (!(blf->blf_flags & XFS_BLF_CANCEL))
					continue;
				if (xlog_put_buffer_cancelled(log, blf->blf_blkno,
							      blf->blf_len))
					supp++;
				else
					log->l_mxfs_cancel_put_miss++;
			}
		} else {
			kept += trans->r_mxfs_ncancel;
		}
		list_del_init(&trans->r_mxfs_defer);
		trans->r_mxfs_deferred = false;
		xlog_recover_free_trans(trans);
	}
	log->l_mxfs_p1_txn_refused += refused;
	log->l_mxfs_p1_cancel_kept += kept;
	log->l_mxfs_p1_cancel_suppressed += supp;
	xfs_notice(log->l_mp,
"MXFS %s replay: P-FR-CANCEL-PASS1 txns=%u refused=%u cancel_kept=%u cancel_suppressed=%u put_miss=%u — pass-1 cancel table rebuilt from admitted transactions only",
		   xlog_is_mxfs_foreign_replay(log) ? "foreign" : "adopted",
		   txns, refused, kept, supp, log->l_mxfs_cancel_put_miss);
	return 0;
}

/* pass 2: the verdict must be the one the pass-1 decision was taken on */
static int
mxfs_cdefer_verify(
	struct xlog		*log,
	struct xlog_recover	*trans)
{
	struct mxfs_cdefer_ent	*e;

	if (!log->l_mxfs_cdefer_ht)
		return 0;
	hlist_for_each_entry(e, mxfs_cdefer_bucket(log, trans->r_log_tid,
						   trans->r_lsn), node) {
		if (e->lsn != trans->r_lsn || e->tid != trans->r_log_tid)
			continue;
		if (e->verdict == trans->r_mxfs_verdict)
			return 0;
		log->l_mxfs_pass_verdict_mismatch++;
		xfs_alert(log->l_mp,
"MXFS %s replay: P-FR-PASS-VERDICT-MISMATCH lsn=0x%llx tid=0x%x pass1=%u pass2=%u — the pass-1 CANCEL decision and the pass-2 verdict disagree; aborting this attempt (slice stays dirty, nothing published)",
			  xlog_is_mxfs_foreign_replay(log) ? "foreign" : "adopted",
			  (unsigned long long)trans->r_lsn,
			  (unsigned)trans->r_log_tid,
			  (unsigned)e->verdict, (unsigned)trans->r_mxfs_verdict);
		return -EIO;
	}
	return 0;
}

static void
mxfs_cdefer_free(
	struct xlog		*log)
{
	struct xlog_recover	*trans, *next;
	unsigned int		i;

	if (log->l_mxfs_cdefer.next) {
		list_for_each_entry_safe(trans, next, &log->l_mxfs_cdefer,
					 r_mxfs_defer) {
			list_del_init(&trans->r_mxfs_defer);
			xlog_recover_free_trans(trans);
		}
	}
	if (log->l_mxfs_cdefer_ht) {
		for (i = 0; i < MXFS_CDEFER_HT_SIZE; i++) {
			struct mxfs_cdefer_ent *e;
			struct hlist_node *tmp;

			hlist_for_each_entry_safe(e, tmp,
						  &log->l_mxfs_cdefer_ht[i], node) {
				hlist_del(&e->node);
				kfree(e);
			}
		}
		kfree(log->l_mxfs_cdefer_ht);
		log->l_mxfs_cdefer_ht = NULL;
	}
}

STATIC int
xlog_recover_items_pass2(
	struct xlog                     *log,
	struct xlog_recover             *trans,
	struct list_head                *buffer_list,
	struct list_head                *item_list)
{
	struct xlog_recover_item	*item;
	int				error = 0;
	bool				mxfs_txn_admitted = false;

	/*
	 * (review-approved containment; PROVEN tear: unlinker_death
	 * reproducer, D-FOREIGN-REPLAY-UNGATED-IMAGES): TRANSACTION-ATOMIC
	 * SKIP for untrusted (foreign/adopted) replay.  The old per-item
	 * policy applied a transaction's INODE items while skipping its
	 * untagged BUFFER siblings — recovery then manufactured a state no
	 * node ever had (dirent present -> nlink=0 inode on NO unlinked
	 * bucket; permanent leak + poisoned dirent).  A committed log
	 * transaction is the minimum redo-consistency unit: if ANY of its
	 * images is unauthoritative here, apply NONE of it.  The un-synced
	 * operation then evaporates atomically (crash semantics) instead of
	 * tearing.  KNOWN LIMITS (ledger stays OPEN): multi-transaction ops
	 * (rolling/deferred) can still tear at op granularity, and home
	 * writes that landed before death are not rolled back — the full
	 * authority protocol remains the real fix.
	 */
	/*
	 * a broken recovery invariant seen by the evaluator
	 * (post-seal mutation of the victim's frozen authority, or a failed
	 * current-safety read) aborts the WHOLE attempt under enforcement —
	 * retryable errno, verdict reason stays NONE so no terminal outcome
	 * publishes and nothing is purged.
	 */
	/*
	 * (design-consult ruling Q5): a replayer that already holds a lease
	 * rechecks the FS-wide terminal state at every transaction boundary
	 * and stops safely — between committed transactions the slice is
	 * restartable exactly like a crash during recovery.  Retryable errno,
	 * reason NONE: nothing publishes, nothing is purged, the reap path's
	 * FSWIDE gate then keeps the slot frozen instead of re-arming.
	 */
	if (xlog_is_mxfs_foreign_replay(log) &&
	    READ_ONCE(log->l_mp->m_mxfs_quar_fswide)) {
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P-RMAN-FSWIDE-HALT victim_slot=%u lsn=0x%llx — aborting elected recovery at a transaction boundary: an FSWIDE terminal quarantine landed on this filesystem (slice stays dirty, nothing purged)",
			  log->l_mxfs_victim_slot,
			  (unsigned long long)trans->r_lsn);
		return -EIO;
	}
	if (mxfs_fr_enforcement_active(log) &&
	    log->l_mxfs_shadow_eval->rman_abort) {
		xfs_alert(log->l_mp,
	"MXFS foreign replay: P-RMAN-ABORT victim_slot=%u lsn=0x%llx — aborting elected recovery on a post-seal authority mutation / failed current-safety check (slice stays dirty, retryable, nothing purged)",
			  log->l_mxfs_victim_slot,
			  (unsigned long long)trans->r_lsn);
		return -EIO;
	}
	/*
	 * (D-529): the whole-transaction verdict was classified
	 * EXACTLY ONCE over the COMPLETE item queue at commit entry
	 * (mxfs_classify_untrusted_txn) and cached on the trans; every batch
	 * of this transaction consumes the same verdict, so a >100-item
	 * transaction can no longer be admitted in one batch and skipped in
	 * another (partial apply = the tear the atomic skip prevents).
	 */
	/*
	 * (D-FOREIGN-SLICE-INTENTS-ABANDONED, proven by instrument): the
	 * intent/done census must see EVERY intent and done in the slice, so
	 * it runs BEFORE the whole-transaction verdict below.  The census
	 * used to be noted inside the item loop, which the SKIP/SBCLEAN/
	 * PREINC verdicts return ahead of — a victim destroyed inside a
	 * held EFD transaction (tests/d_intents_undischarged_verify.sh
	 * burst, dbg_efd_hold_ms) replayed as two ATOMIC-SKIP transactions
	 * and P226-ICENSUS printed intents=0 dones=0 open=0: the durable EFI
	 * was invisible and the INTENTS_UNDISCHARGED refusal could never
	 * fire.  The verdict decides whether IMAGES apply; an intent is an
	 * obligation of the dead slice whether or not its sibling images
	 * are authoritative here (fail closed: a SKIP or SBCLEAN txn's
	 * intents count too — their dones pair the same way, and an
	 * unmatched done is harmless).  The one exception is the
	 * PREINC verdict (docs/ag-metadata-coherency.md fix 2): a published
	 * predecessor incarnation's records are clean by certificate —
	 * "no images, no inode items, no intents into the census" — and a
	 * predecessor EFI whose EFD lies beyond the window tail would be a
	 * false refusal of a slice that was already recovered.
	 */
	if (xlog_is_mxfs_untrusted_replay(log) &&
	    !(!mxfs_foreign_replay_untagged_apply &&
	      trans->r_mxfs_verdict == MXFS_TXNV_PREINC)) {
		list_for_each_entry(item, item_list, ri_list) {
			unsigned short t = ITEM_TYPE(item);

			if (t == XFS_LI_EFI || t == XFS_LI_EFD ||
			    (t >= XFS_LI_RUI && t <= XFS_LI_CUD_RT))
				mxfs_icensus_note(log, item, trans->r_lsn,
						  trans->r_mxfs_verdict);
		}
	}
	if (xlog_is_mxfs_untrusted_replay(log) &&
	    !mxfs_foreign_replay_untagged_apply) {
		switch (trans->r_mxfs_verdict) {
		case MXFS_TXNV_SBCLEAN:
		case MXFS_TXNV_SKIP:
		case MXFS_TXNV_PREINC:	/* published predecessor */
			return 0;	/* every batch of the txn skips */
		case MXFS_TXNV_ADMIT:
			mxfs_txn_admitted = true;
			break;
		default:		/* SNLOCAL / UNTAINTED: proceed */
			break;
		}
	}

	list_for_each_entry(item, item_list, ri_list) {
		trace_xfs_log_recover_item_recover(log, trans, item,
				XLOG_RECOVER_PASS2);

		/*
		 * MXFS foreign-slice replay (live recovery of a dead peer's
		 * log slice): replay only direct metadata images (buf, inode,
		 * dquot, icreate).  Intent/done items are skipped — inserting
		 * a dead peer's intents into this node's live AIL would wedge
		 * the AIL at a foreign LSN, and processing them here could
		 * double-complete against the next mount-time claimer of the
		 * slice (which replays the still-dirty slice with full intent
		 * handling, exactly as before this feature).  Buffer/inode
		 * replay is LSN-gated, so that re-replay is a no-op.
		 */
		if (xlog_is_mxfs_untrusted_replay(log)) {
			unsigned short t = ITEM_TYPE(item);
			const char *src = xlog_is_mxfs_foreign_replay(log) ?
					  "foreign" : "adopted";

			if ((t == XFS_LI_EFI || t == XFS_LI_EFD ||
			     (t >= XFS_LI_RUI && t <= XFS_LI_CUD_RT)) &&
			    !xlog_is_mxfs_bootstrap_adopted(log)) {
				/*
				 * a BOOTSTRAP_ADOPTED log is the real
				 * mount log — its intents ARE processed (the
				 * ruling's reason for shape B); they fall
				 * through to commit_pass2 below.
				 */
				/*
				 * (barrier ruling, stop-ship 1):
				 * NOT applied, but no longer dropped silently —
				 * the census records every intent by id and
				 * retires it on its done.  A foreign replay
				 * whose census is still open at the end FAILS
				 * BEFORE PURGE (INTENTS_UNDISCHARGED, xfs_log.c);
				 * an adopted-slice mount prints the census and
				 * continues (its disposition belongs to the
				 * own-slot reclaim work).  The old comment's
				 * premise — "the next mount-time claimer
				 * performs full replay including intents" — was
				 * false: that claimer is an adopted-slice mount
				 * and took this same branch.
				 */
				/* already noted by the pre-verdict
				 * census pass above. */
				continue;
			}
			/*
			 * D-FOREIGN-REPLAY-UNGATED-IMAGES containment:
			 * buffer/dquot/quotaoff/icreate records carry no
			 * authority token and their only replay gate is a
			 * cross-slice LSN compare, which is meaningless
			 * (per-node slices number LSNs independently — the
			 * sb-LSN check below skips itself for this exact
			 * reason).  Applying them can silently revert a
			 * survivor's newer dir block / AG state; skipping
			 * loses only changes whose covering lock the dead
			 * node still HELD at death (released tenures were
			 * landed by the release drain).  Skip and count
			 * LOUDLY until records carry authority tokens.
			 * Inode records continue: their di_changecount gate
			 * is node-independent and correct.
			 */
			/*
			 * (design-consult ruling): inside an ADMITTED
			 * transaction a buffer image whose token names a
			 * tenure the victim CLEANLY RELEASED (durable
			 * XFS_LI_MXFS_RELMARK collected in pass 1) is
			 * REDUNDANT_CLEAN — already on the platter by the
			 * Invariant-1 drain, possibly overwritten since by a
			 * successor.  Skip it SILENTLY: no untagged_skips, no
			 * quarantine domain, no torn-verdict arming.
			 */
			/* a REDUNDANT ICREATE is suppressed the same way
			 * — the successor may have reused the extent, so not even
			 * its verify read runs (see P-ICREATE-AUTH). */
			/*
			 * a REDUNDANT CANCEL record is NOT skipped
			 * here — it writes nothing anyway, and commit_pass2
			 * must still perform its cancel-table put so the
			 * pass-1 adds stay balanced (the ruling's part 4).
			 */
			if (mxfs_txn_admitted &&
			    (t == XFS_LI_BUF || t == XFS_LI_ICREATE) &&
			    item->ri_mxfs_verdict == MXFS_RI_VERDICT_REDUNDANT &&
			    !(t == XFS_LI_BUF &&
			      (((struct xfs_buf_log_format *)
				item->ri_buf[0].iov_base)->blf_flags &
			       XFS_BLF_CANCEL))) {
				static atomic_t mxfs_frredund_n = ATOMIC_INIT(0);
				int n = atomic_inc_return(&mxfs_frredund_n);

				log->l_mxfs_redundant_skips++;
				if (log->l_mxfs_shadow_eval)
					log->l_mxfs_shadow_eval->redundant_skipped++;
				if (n <= 2000)
					xfs_notice(log->l_mp,
		"MXFS %s replay: REDUNDANT_CLEAN skip %s lsn=0x%llx (n=%d) — tenure cleanly released by the victim (P227-FR-REDUNDANT-SKIP)",
						   src,
						   t == XFS_LI_ICREATE ?
						   "icreate record" : "buffer image",
						   (unsigned long long)trans->r_lsn,
						   n);
				continue;
			}
			if (!mxfs_foreign_replay_untagged_apply &&
			    !log->l_mxfs_untagged_authorized &&
			    !mxfs_txn_admitted &&
			    (t == XFS_LI_BUF || t == XFS_LI_DQUOT ||
			     t == XFS_LI_QUOTAOFF || t == XFS_LI_ICREATE)) {
				static atomic_t mxfs_frskip_n = ATOMIC_INIT(0);
				int n = atomic_inc_return(&mxfs_frskip_n);

				log->l_mxfs_untagged_skips++;
				/* refused item → quarantine domain */
				mxfs_refused_item_domain(log, item);
				if (n <= 2000)
					xfs_notice(log->l_mp,
		"MXFS %s replay: skipping untagged image item type 0x%x (n=%d) — no cross-slice authority gate (P223-FR-UNTAGGED-SKIP)",
						   src, t, n);
				continue;
			}
		}

		/*
		 * (ruling Q2b): genuine mid-replay TORN fault
		 * injection.  Fails BEFORE applying this item, so the applied
		 * prefix is deterministic and the caller's xlog_recover_cancel
		 * runs the real unwind mid-replay — nothing after the failure
		 * point may reach the platter.  Foreign-replay shadow logs
		 * only (the arm site guarantees it; the opstate check makes it
		 * structurally impossible on an owned log).
		 */
		if (unlikely(log->l_mxfs_force_torn_countdown) &&
		    xlog_is_mxfs_foreign_replay(log) &&
		    --log->l_mxfs_force_torn_countdown == 0) {
			xfs_alert(log->l_mp,
	"MXFS foreign replay: P227-FR-FORCED-TORN mid-replay fault injection at lsn=0x%llx item type 0x%x — failing pass 2 with a real applied prefix",
				  (unsigned long long)trans->r_lsn,
				  ITEM_TYPE(item));
			return -EFSCORRUPTED;
		}

		if (item->ri_ops->commit_pass2)
			error = item->ri_ops->commit_pass2(log, buffer_list,
					item, trans->r_lsn);
		if (error)
			return error;
	}

	return error;
}

/*
 * Perform the transaction.
 *
 * If the transaction modifies a buffer or inode, do it now.  Otherwise,
 * EFIs and EFDs get queued up by adding entries into the AIL for them.
 */
STATIC int mxfs_xlog_validate_trans_assembly(struct xlog *log,
					     struct xlog_recover *trans,
					     int pass);

STATIC int
xlog_recover_commit_trans(
	struct xlog		*log,
	struct xlog_recover	*trans,
	int			pass,
	struct list_head	*buffer_list)
{
	int				error = 0;
	int				items_queued = 0;
	struct xlog_recover_item	*item;
	struct xlog_recover_item	*next;
	LIST_HEAD			(ra_list);
	LIST_HEAD			(done_list);

	#define XLOG_RECOVER_COMMIT_QUEUE_MAX 100

	hlist_del_init(&trans->r_list);

	error = mxfs_xlog_validate_trans_assembly(log, trans, pass);
	if (error)
		return error;

	/*
	 * (D-529): whole-transaction untrusted-replay verdict,
	 * classified once here over the COMPLETE item queue and cached on
	 * the trans; the pass-2 batches consume it.  Pass 2 only (pass 1
	 * never applies images), before reorder (the classifier's own walks
	 * are order-independent; classifying pre-reorder keeps the item
	 * stream in log order for the telemetry).
	 */
	if (pass == XLOG_RECOVER_PASS2 && xlog_is_mxfs_untrusted_replay(log)) {
		trans->r_mxfs_verdict = mxfs_classify_untrusted_txn(log, trans,
								    true);
		/* must equal the end-of-pass-1 CANCEL decision */
		error = mxfs_cdefer_verify(log, trans);
		if (error)
			return error;
	}

	error = xlog_recover_reorder_trans(log, trans, pass);
	if (error)
		return error;

	list_for_each_entry_safe(item, next, &trans->r_itemq, ri_list) {
		trace_xfs_log_recover_item_recover(log, trans, item, pass);

		switch (pass) {
		case XLOG_RECOVER_PASS1:
			if (item->ri_ops->commit_pass1)
				error = item->ri_ops->commit_pass1(log, item);
			break;
		case XLOG_RECOVER_PASS2:
			if (item->ri_ops->ra_pass2)
				item->ri_ops->ra_pass2(log, item);
			list_move_tail(&item->ri_list, &ra_list);
			items_queued++;
			if (items_queued >= XLOG_RECOVER_COMMIT_QUEUE_MAX) {
				error = xlog_recover_items_pass2(log, trans,
						buffer_list, &ra_list);
				list_splice_tail_init(&ra_list, &done_list);
				items_queued = 0;
			}

			break;
		default:
			ASSERT(0);
		}

		if (error)
			goto out;
	}

out:
	if (!list_empty(&ra_list)) {
		if (!error)
			error = xlog_recover_items_pass2(log, trans,
					buffer_list, &ra_list);
		list_splice_tail_init(&ra_list, &done_list);
	}

	if (!list_empty(&done_list))
		list_splice_init(&done_list, &trans->r_itemq);

	/*
	 * a pass-1 CANCEL-bearing untrusted transaction is parked
	 * (its items kept) until the walk completes — see mxfs_cdefer_resolve.
	 * The caller sees r_mxfs_deferred and does not free it.
	 */
	if (!error && pass == XLOG_RECOVER_PASS1)
		mxfs_cdefer_stash(log, trans);

	return error;
}

STATIC void
xlog_recover_add_item(
	struct list_head	*head)
{
	struct xlog_recover_item *item;

	item = kzalloc(sizeof(struct xlog_recover_item),
			GFP_KERNEL | __GFP_NOFAIL);
	INIT_LIST_HEAD(&item->ri_list);
	list_add_tail(&item->ri_list, head);
}

STATIC int
xlog_recover_add_to_cont_trans(
	struct xlog		*log,
	struct xlog_recover	*trans,
	char			*dp,
	int			len)
{
	struct xlog_recover_item *item;
	char			*ptr, *old_ptr;
	int			old_len;

	/*
	 * If the transaction is empty, the header was split across this and the
	 * previous record. Copy the rest of the header.
	 */
	if (list_empty(&trans->r_itemq)) {
		ASSERT(len <= sizeof(struct xfs_trans_header));
		if (len > sizeof(struct xfs_trans_header)) {
			xfs_warn(log->l_mp, "%s: bad header length", __func__);
			return -EFSCORRUPTED;
		}

		xlog_recover_add_item(&trans->r_itemq);
		ptr = (char *)&trans->r_theader +
				sizeof(struct xfs_trans_header) - len;
		memcpy(ptr, dp, len);
		return 0;
	}

	/* take the tail entry */
	item = list_entry(trans->r_itemq.prev, struct xlog_recover_item,
			  ri_list);

	old_ptr = item->ri_buf[item->ri_cnt-1].iov_base;
	old_len = item->ri_buf[item->ri_cnt-1].iov_len;

	ptr = mxfs_kvrealloc(old_ptr, old_len, len + old_len, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	memcpy(&ptr[old_len], dp, len);
	item->ri_buf[item->ri_cnt-1].iov_len += len;
	item->ri_buf[item->ri_cnt-1].iov_base = ptr;
	trace_xfs_log_recover_item_add_cont(log, trans, item, 0);
	return 0;
}

/*
 * The next region to add is the start of a new region.  It could be
 * a whole region or it could be the first part of a new region.  Because
 * of this, the assumption here is that the type and size fields of all
 * format structures fit into the first 32 bits of the structure.
 *
 * This works because all regions must be 32 bit aligned.  Therefore, we
 * either have both fields or we have neither field.  In the case we have
 * neither field, the data part of the region is zero length.  We only have
 * a log_op_header and can throw away the header since a new one will appear
 * later.  If we have at least 4 bytes, then we can determine how many regions
 * will appear in the current log item.
 */
STATIC int
xlog_recover_add_to_trans(
	struct xlog		*log,
	struct xlog_recover	*trans,
	char			*dp,
	int			len)
{
	struct xfs_inode_log_format	*in_f;			/* any will do */
	struct xlog_recover_item *item;
	char			*ptr;

	if (!len)
		return 0;
	if (list_empty(&trans->r_itemq)) {
		/* we need to catch log corruptions here */
		if (*(uint *)dp != MXFS_TRANS_HEADER_MAGIC) {
			xfs_warn(log->l_mp, "%s: bad header magic number",
				__func__);
			ASSERT(0);
			return -EFSCORRUPTED;
		}

		if (len > sizeof(struct xfs_trans_header)) {
			xfs_warn(log->l_mp, "%s: bad header length", __func__);
			ASSERT(0);
			return -EFSCORRUPTED;
		}

		/*
		 * The transaction header can be arbitrarily split across op
		 * records. If we don't have the whole thing here, copy what we
		 * do have and handle the rest in the next record.
		 */
		if (len == sizeof(struct xfs_trans_header))
			xlog_recover_add_item(&trans->r_itemq);
		memcpy(&trans->r_theader, dp, len);
		return 0;
	}

	ptr = xlog_kvmalloc(len);
	memcpy(ptr, dp, len);
	in_f = (struct xfs_inode_log_format *)ptr;

	/* take the tail entry */
	item = list_entry(trans->r_itemq.prev, struct xlog_recover_item,
			  ri_list);
	if (item->ri_total != 0 &&
	     item->ri_total == item->ri_cnt) {
		/* tail item is in use, get a new one */
		xlog_recover_add_item(&trans->r_itemq);
		item = list_entry(trans->r_itemq.prev,
					struct xlog_recover_item, ri_list);
	}

	if (item->ri_total == 0) {		/* first region to be added */
		if (in_f->ilf_size == 0 ||
		    in_f->ilf_size > XLOG_MAX_REGIONS_IN_ITEM) {
			xfs_warn(log->l_mp,
		"bad number of regions (%d) in inode log format",
				  in_f->ilf_size);
			ASSERT(0);
			kvfree(ptr);
			return -EFSCORRUPTED;
		}

		item->ri_total = in_f->ilf_size;
		item->ri_buf = kcalloc(item->ri_total, sizeof(*item->ri_buf),
				GFP_KERNEL | __GFP_NOFAIL);
	}

	if (item->ri_total <= item->ri_cnt) {
		xfs_warn(log->l_mp,
	"log item region count (%d) overflowed size (%d)",
				item->ri_cnt, item->ri_total);
		ASSERT(0);
		kvfree(ptr);
		return -EFSCORRUPTED;
	}

	/* Description region is ri_buf[0] */
	item->ri_buf[item->ri_cnt].iov_base = ptr;
	item->ri_buf[item->ri_cnt].iov_len  = len;
	item->ri_cnt++;
	trace_xfs_log_recover_item_add(log, trans, item, 0);
	return 0;
}

/*
 * Free up any resources allocated by the transaction
 *
 * Remember that EFIs, EFDs, and IUNLINKs are handled later.
 */
STATIC void
xlog_recover_free_trans(
	struct xlog_recover	*trans)
{
	struct xlog_recover_item *item, *n;
	int			i;

	hlist_del_init(&trans->r_list);

	list_for_each_entry_safe(item, n, &trans->r_itemq, ri_list) {
		/* Free the regions in the item. */
		list_del(&item->ri_list);
		for (i = 0; i < item->ri_cnt; i++)
			kvfree(item->ri_buf[i].iov_base);
		/* Free the item itself */
		kfree(item->ri_buf);
		kfree(item);
	}
	/* Free the transaction recover structure */
	kfree(trans);
}

/*
 * (D-527 design-consult ruling, part (b)): the hard assembly invariant.  A
 * COMMITTED transaction must arrive whole: every item fully claimed
 * (ri_total set from its format header), every declared region present,
 * and the first region carrying a recognized item type.  A healthy log
 * always commits complete items, so this never fires on legal
 * interleaving or slack — it fires exactly when expected ophdr regions
 * were DELETED from the stream (stale prior-life records inside the
 * [tail,head] span skipped as unknown-tid slack), which is the measured
 * cause of type-0 items and misassembled dinode images reaching pass 2.
 * Refuse with -EILSEQ (EUCLEAN would collide with EFSCORRUPTED — same
 * errno), a class the foreign-replay unwind publishes as
 * ASSEMBLY-DISCONTINUITY (terminal, diagnosable, NOT a media tear).
 * Runs in both passes, so pass 1 refuses before pass 2 writes anything.
 */
STATIC int
mxfs_xlog_validate_trans_assembly(
	struct xlog		*log,
	struct xlog_recover	*trans,
	int			pass)
{
	struct xlog_recover_item *item;
	unsigned int		nitems = 0, nregions = 0;
	int			ord = 0;

	list_for_each_entry(item, &trans->r_itemq, ri_list) {
		const char	*why = NULL;
		uint32_t	head4 = 0;

		if (item->ri_total == 0 || item->ri_cnt == 0)
			why = "item never claimed by a format region";
		else if (item->ri_cnt != item->ri_total)
			why = "declared regions missing";
		else if (!item->ri_buf || !item->ri_buf[0].iov_base ||
			 item->ri_buf[0].iov_len < 4)
			why = "first region absent or short";
		else if (!xlog_find_item_ops(item))
			why = "unrecognized item type in first region";

		if (!why) {
			nitems++;
			nregions += item->ri_cnt;
			ord++;
			continue;
		}
		if (item->ri_buf && item->ri_cnt > 0 &&
		    item->ri_buf[0].iov_base &&
		    item->ri_buf[0].iov_len >= 4)
			head4 = *(uint32_t *)item->ri_buf[0].iov_base;
		xfs_alert(log->l_mp,
"MXFS: P-FRASM-DISCONT tid=0x%x lsn=0x%llx pass=%d item=%d cnt=%d total=%d head4=0x%08x unktid_skips=%u snap=%d — %s; transaction assembly crossed an ophdr discontinuity, refusing before any replay side effect",
			  trans->r_log_tid,
			  (unsigned long long)trans->r_lsn, pass, ord,
			  item->ri_cnt, item->ri_total, head4,
			  log->l_mxfs_unktid_skips,
			  log->l_mxfs_slice_snap != NULL, why);
		return -EILSEQ;
	}

	/*
	 * measurement 2: the writer records the checkpoint's TOTAL
	 * region (iovec) count in the trans header (xlog_cil_build_trans_hdr:
	 * th_num_items = num_iovecs), and upstream recovery never checks it.
	 * Verified against the platter (slot 26, txn 0x100007410): 131 items,
	 * 128 inode x3 + 3 buf x2 regions = th_num_items 390 exactly.  Both
	 * measured di_magic -117s (slot 29, slot 26) failed
	 * on an item ~17 positions past what the kernel assembled, i.e. the
	 * assembled stream was SHORTER than the writer's count with ZERO
	 * unknown-tid skips — so enforce the writer's own total.  A mismatch
	 * is a mis-assembly caught BEFORE any garbage item reaches pass 2;
	 * the per-item dump bounds where the shift started.
	 */
	if (trans->r_theader.th_magic == MXFS_TRANS_HEADER_MAGIC &&
	    trans->r_theader.th_num_items > 0 &&
	    nregions != (unsigned int)trans->r_theader.th_num_items) {
		int dumped = 0;

		xfs_alert(log->l_mp,
"MXFS: P-FRASM-COUNT tid=0x%x lsn=0x%llx pass=%d items=%u regions=%u th_num_items=%u unktid_skips=%u snap=%d — assembled region total differs from the writer's checkpoint count; refusing before any replay side effect",
			  trans->r_log_tid,
			  (unsigned long long)trans->r_lsn, pass,
			  nitems, nregions,
			  (unsigned int)trans->r_theader.th_num_items,
			  log->l_mxfs_unktid_skips,
			  log->l_mxfs_slice_snap != NULL);
		list_for_each_entry(item, &trans->r_itemq, ri_list) {
			if (dumped >= 8)
				break;
			xfs_notice(log->l_mp,
	"MXFS: P-FRASM-ITEM ord=%d type=0x%x cnt=%d total=%d len0=%zu",
				   dumped, ITEM_TYPE(item), item->ri_cnt,
				   item->ri_total,
				   item->ri_buf[0].iov_len);
			dumped++;
		}
		return -EILSEQ;
	}
	return 0;
}

/*
 * On error or completion, trans is freed.
 */
STATIC int
xlog_recovery_process_trans(
	struct xlog		*log,
	struct xlog_recover	*trans,
	char			*dp,
	unsigned int		len,
	unsigned int		flags,
	int			pass,
	struct list_head	*buffer_list)
{
	int			error = 0;
	bool			freeit = false;

	/* mask off ophdr transaction container flags */
	flags &= ~XLOG_END_TRANS;
	if (flags & XLOG_WAS_CONT_TRANS)
		flags &= ~XLOG_CONTINUE_TRANS;

	/*
	 * Callees must not free the trans structure. We'll decide if we need to
	 * free it or not based on the operation being done and it's result.
	 */
	switch (flags) {
	/* expected flag values */
	case 0:
	case XLOG_CONTINUE_TRANS:
		error = xlog_recover_add_to_trans(log, trans, dp, len);
		break;
	case XLOG_WAS_CONT_TRANS:
		error = xlog_recover_add_to_cont_trans(log, trans, dp, len);
		break;
	case XLOG_COMMIT_TRANS:
		error = xlog_recover_commit_trans(log, trans, pass,
						  buffer_list);
		/* success or fail, we are now done with this transaction. */
		freeit = true;
		break;

	/* unexpected flag values */
	case XLOG_UNMOUNT_TRANS:
		/* just skip trans */
		xfs_warn(log->l_mp, "%s: Unmount LR", __func__);
		freeit = true;
		break;
	case XLOG_START_TRANS:
	default:
		xfs_warn(log->l_mp, "%s: bad flag 0x%x", __func__, flags);
		ASSERT(0);
		error = -EFSCORRUPTED;
		break;
	}
	/* a parked CANCEL-bearing transaction is owned by the
	 * pass-1 defer list (mxfs_cdefer_stash) until mxfs_cdefer_resolve */
	if (error || (freeit && !trans->r_mxfs_deferred))
		xlog_recover_free_trans(trans);
	return error;
}

/*
 * Lookup the transaction recovery structure associated with the ID in the
 * current ophdr. If the transaction doesn't exist and the start flag is set in
 * the ophdr, then allocate a new transaction for future ID matches to find.
 * Either way, return what we found during the lookup - an existing transaction
 * or nothing.
 */
STATIC struct xlog_recover *
xlog_recover_ophdr_to_trans(
	struct hlist_head	rhash[],
	struct xlog_rec_header	*rhead,
	struct xlog_op_header	*ohead)
{
	struct xlog_recover	*trans;
	xlog_tid_t		tid;
	struct hlist_head	*rhp;

	tid = be32_to_cpu(ohead->oh_tid);
	rhp = &rhash[XLOG_RHASH(tid)];
	hlist_for_each_entry(trans, rhp, r_list) {
		if (trans->r_log_tid == tid)
			return trans;
	}

	/*
	 * skip over non-start transaction headers - we could be
	 * processing slack space before the next transaction starts
	 */
	if (!(ohead->oh_flags & XLOG_START_TRANS))
		return NULL;

	ASSERT(be32_to_cpu(ohead->oh_len) == 0);

	/*
	 * This is a new transaction so allocate a new recovery container to
	 * hold the recovery ops that will follow.
	 */
	trans = kzalloc(sizeof(struct xlog_recover), GFP_KERNEL | __GFP_NOFAIL);
	trans->r_log_tid = tid;
	trans->r_lsn = be64_to_cpu(rhead->h_lsn);
	INIT_LIST_HEAD(&trans->r_itemq);
	INIT_HLIST_NODE(&trans->r_list);
	hlist_add_head(&trans->r_list, rhp);

	/*
	 * Nothing more to do for this ophdr. Items to be added to this new
	 * transaction will be in subsequent ophdr containers.
	 */
	return NULL;
}

STATIC int
xlog_recover_process_ophdr(
	struct xlog		*log,
	struct hlist_head	rhash[],
	struct xlog_rec_header	*rhead,
	struct xlog_op_header	*ohead,
	char			*dp,
	char			*end,
	int			pass,
	struct list_head	*buffer_list)
{
	struct xlog_recover	*trans;
	unsigned int		len;
	int			error;

	/* Do we understand who wrote this op? */
	if (ohead->oh_clientid != XFS_TRANSACTION &&
	    ohead->oh_clientid != XFS_LOG) {
		xfs_warn(log->l_mp, "%s: bad clientid 0x%x",
			__func__, ohead->oh_clientid);
		ASSERT(0);
		return -EFSCORRUPTED;
	}

	/*
	 * Check the ophdr contains all the data it is supposed to contain.
	 */
	len = be32_to_cpu(ohead->oh_len);
	if (dp + len > end) {
		xfs_warn(log->l_mp, "%s: bad length 0x%x", __func__, len);
		WARN_ON(1);
		return -EFSCORRUPTED;
	}

	trans = xlog_recover_ophdr_to_trans(rhash, rhead, ohead);
	if (!trans) {
		/*
		 * (D-527 ruling): an unknown-tid non-START ophdr is
		 * tolerated as slack (a txn wholly applied before the tail can
		 * leave regions inside [tail,head]) — but it is also exactly
		 * what a stale prior-life record inside the span looks like,
		 * and there it DELETES regions the real stream held at this
		 * position.  Count every skip and log the first few with full
		 * provenance; the commit-time assembly validator refuses any
		 * transaction the deletion actually broke.
		 */
		if (!(ohead->oh_flags & XLOG_START_TRANS)) {
			log->l_mxfs_unktid_skips++;
			if (log->l_mxfs_unktid_probes < 8) {
				log->l_mxfs_unktid_probes++;
				xfs_notice(log->l_mp,
	"MXFS: P-FRASM-UNKTID rec_lsn=0x%llx rec_cycle=%u tid=0x%x flags=0x%x client=0x%x len=%u skips=%u — unknown-tid ophdr skipped as slack inside the recovery span",
					   (unsigned long long)be64_to_cpu(rhead->h_lsn),
					   be32_to_cpu(rhead->h_cycle),
					   be32_to_cpu(ohead->oh_tid),
					   ohead->oh_flags,
					   ohead->oh_clientid, len,
					   log->l_mxfs_unktid_skips);
			}
		}
		/* nothing to do, so skip over this ophdr */
		return 0;
	}

	/*
	 * The recovered buffer queue is drained only once we know that all
	 * recovery items for the current LSN have been processed. This is
	 * required because:
	 *
	 * - Buffer write submission updates the metadata LSN of the buffer.
	 * - Log recovery skips items with a metadata LSN >= the current LSN of
	 *   the recovery item.
	 * - Separate recovery items against the same metadata buffer can share
	 *   a current LSN. I.e., consider that the LSN of a recovery item is
	 *   defined as the starting LSN of the first record in which its
	 *   transaction appears, that a record can hold multiple transactions,
	 *   and/or that a transaction can span multiple records.
	 *
	 * In other words, we are allowed to submit a buffer from log recovery
	 * once per current LSN. Otherwise, we may incorrectly skip recovery
	 * items and cause corruption.
	 *
	 * We don't know up front whether buffers are updated multiple times per
	 * LSN. Therefore, track the current LSN of each commit log record as it
	 * is processed and drain the queue when it changes. Use commit records
	 * because they are ordered correctly by the logging code.
	 */
	if (log->l_recovery_lsn != trans->r_lsn &&
	    ohead->oh_flags & XLOG_COMMIT_TRANS) {
		/*
		 * 0.74.1 (D-FOREIGN-REPLAY-OVERRIDE-APPLY-OLDER-PARTIAL-IMAGE-
		 * DRAINED-PER-LSN-INVALID-INTERMEDIATE-REFUSES-SLICE-0904): the
		 * per-LSN drain above is safe upstream only because the
		 * on-disk-LSN veto in xlog_recover_buf_commit_pass2 never lets
		 * an image OLDER than the platter reach the queue.  An untrusted
		 * replay overrides that veto for token-admitted AG/INODE images
		 * (the stamp may be another slice's number), so the queue can
		 * hold a partial image of an older state — the tail
		 * transaction's dir-block chunks over a block the victim last
		 * flushed at the head transaction.  Written here, before the
		 * head transaction overlays it, that intermediate fails the
		 * write verifier and the slice is refused.  Keep the queue and
		 * submit once at the end of the pass instead: every image of
		 * the slice lands in core in LSN order first.  Nothing is
		 * vetoed that upstream would not veto — the stamp an image is
		 * compared against is the one the platter copy already carried,
		 * since no mid-pass write ever restamps it.
		 */
		if (xlog_is_mxfs_untrusted_replay(log)) {
			log->l_mxfs_drain_deferred++;
		} else {
			error = xfs_buf_delwri_submit(buffer_list);
			if (error)
				return error;
		}
		log->l_recovery_lsn = trans->r_lsn;
	}

	return xlog_recovery_process_trans(log, trans, dp, len,
					   ohead->oh_flags, pass, buffer_list);
}

/*
 * There are two valid states of the r_state field.  0 indicates that the
 * transaction structure is in a normal state.  We have either seen the
 * start of the transaction or the last operation we added was not a partial
 * operation.  If the last operation we added to the transaction was a
 * partial operation, we need to mark r_state with XLOG_WAS_CONT_TRANS.
 *
 * NOTE: skip LRs with 0 data length.
 */
STATIC int
xlog_recover_process_data(
	struct xlog		*log,
	struct hlist_head	rhash[],
	struct xlog_rec_header	*rhead,
	char			*dp,
	int			pass,
	struct list_head	*buffer_list)
{
	struct xlog_op_header	*ohead;
	char			*end;
	int			num_logops;
	int			error;

	end = dp + be32_to_cpu(rhead->h_len);
	num_logops = be32_to_cpu(rhead->h_num_logops);

	/* check the log format matches our own - else we can't recover */
	if (xlog_header_check_recover(log->l_mp, rhead))
		return -EIO;

	trace_xfs_log_recover_record(log, rhead, pass);
	while ((dp < end) && num_logops) {

		ohead = (struct xlog_op_header *)dp;
		dp += sizeof(*ohead);
		if (dp > end) {
			xfs_warn(log->l_mp, "%s: op header overrun", __func__);
			return -EFSCORRUPTED;
		}

		/* errors will abort recovery */
		error = xlog_recover_process_ophdr(log, rhash, rhead, ohead,
						   dp, end, pass, buffer_list);
		if (error)
			return error;

		dp += be32_to_cpu(ohead->oh_len);
		num_logops--;
	}
	return 0;
}

/* Take all the collected deferred ops and finish them in order. */
static int
xlog_finish_defer_ops(
	struct xfs_mount	*mp,
	struct list_head	*capture_list)
{
	struct xfs_defer_capture *dfc, *next;
	struct xfs_trans	*tp;
	int			error = 0;

	list_for_each_entry_safe(dfc, next, capture_list, dfc_list) {
		struct xfs_trans_res	resv;
		struct xfs_defer_resources dres;

		/*
		 * Create a new transaction reservation from the captured
		 * information.  Set logcount to 1 to force the new transaction
		 * to regrant every roll so that we can make forward progress
		 * in recovery no matter how full the log might be.
		 */
		resv.tr_logres = dfc->dfc_logres;
		resv.tr_logcount = 1;
		resv.tr_logflags = XFS_TRANS_PERM_LOG_RES;

		error = xfs_trans_alloc(mp, &resv, dfc->dfc_blkres,
				dfc->dfc_rtxres, XFS_TRANS_RESERVE, &tp);
		if (error) {
			xlog_force_shutdown(mp->m_log, SHUTDOWN_LOG_IO_ERROR);
			return error;
		}

		/*
		 * Transfer to this new transaction all the dfops we captured
		 * from recovering a single intent item.
		 */
		list_del_init(&dfc->dfc_list);
		xfs_defer_ops_continue(dfc, tp, &dres);
		error = xfs_trans_commit(tp);
		xfs_defer_resources_rele(&dres);
		if (error)
			return error;
	}

	ASSERT(list_empty(capture_list));
	return 0;
}

/* Release all the captured defer ops and capture structures in this list. */
static void
xlog_abort_defer_ops(
	struct xfs_mount		*mp,
	struct list_head		*capture_list)
{
	struct xfs_defer_capture	*dfc;
	struct xfs_defer_capture	*next;

	list_for_each_entry_safe(dfc, next, capture_list, dfc_list) {
		list_del_init(&dfc->dfc_list);
		xfs_defer_ops_capture_abort(mp, dfc);
	}
}

/*
 * When this is called, all of the log intent items which did not have
 * corresponding log done items should be in the AIL.  What we do now is update
 * the data structures associated with each one.
 *
 * Since we process the log intent items in normal transactions, they will be
 * removed at some point after the commit.  This prevents us from just walking
 * down the list processing each one.  We'll use a flag in the intent item to
 * skip those that we've already processed and use the AIL iteration mechanism's
 * generation count to try to speed this up at least a bit.
 *
 * When we start, we know that the intents are the only things in the AIL. As we
 * process them, however, other items are added to the AIL. Hence we know we
 * have started recovery on all the pending intents when we find an non-intent
 * item in the AIL.
 */
STATIC int
xlog_recover_process_intents(
	struct xlog			*log)
{
	LIST_HEAD(capture_list);
	struct xfs_defer_pending	*dfp, *n;
	int				error = 0;
#if defined(DEBUG) || defined(XFS_WARN)
	xfs_lsn_t			last_lsn;

	last_lsn = xlog_assign_lsn(log->l_curr_cycle, log->l_curr_block);
#endif

	list_for_each_entry_safe(dfp, n, &log->r_dfops, dfp_list) {
		ASSERT(xlog_item_is_intent(dfp->dfp_intent));

		/*
		 * We should never see a redo item with a LSN higher than
		 * the last transaction we found in the log at the start
		 * of recovery.
		 */
		ASSERT(XFS_LSN_CMP(last_lsn, dfp->dfp_intent->li_lsn) >= 0);

		/*
		 * NOTE: If your intent processing routine can create more
		 * deferred ops, you /must/ attach them to the capture list in
		 * the recover routine or else those subsequent intents will be
		 * replayed in the wrong order!
		 *
		 * The recovery function can free the log item, so we must not
		 * access dfp->dfp_intent after it returns.  It must dispose of
		 * @dfp if it returns 0.
		 */
		error = xfs_defer_finish_recovery(log->l_mp, dfp,
				&capture_list);
		if (error)
			break;
	}
	if (error)
		goto err;

	error = xlog_finish_defer_ops(log->l_mp, &capture_list);
	if (error)
		goto err;

	return 0;
err:
	xlog_abort_defer_ops(log->l_mp, &capture_list);
	return error;
}

/*
 * A cancel occurs when the mount has failed and we're bailing out.  Release all
 * pending log intent items that we haven't started recovery on so they don't
 * pin the AIL.
 */
STATIC void
xlog_recover_cancel_intents(
	struct xlog			*log)
{
	struct xfs_defer_pending	*dfp, *n;

	list_for_each_entry_safe(dfp, n, &log->r_dfops, dfp_list) {
		ASSERT(xlog_item_is_intent(dfp->dfp_intent));

		xfs_defer_cancel_recovery(log->l_mp, dfp);
	}
}

/*
 * Transfer ownership of the recovered pending work to the recovery transaction
 * and try to finish the work.  If there is more work to be done, the dfp will
 * remain attached to the transaction.  If not, the dfp is freed.
 */
int
xlog_recover_finish_intent(
	struct xfs_trans		*tp,
	struct xfs_defer_pending	*dfp)
{
	int				error;

	list_move(&dfp->dfp_list, &tp->t_dfops);
	error = xfs_defer_finish_one(tp, dfp);
	if (error == -EAGAIN)
		return 0;
	return error;
}

/*
 * This routine performs a transaction to null out a bad inode pointer
 * in an agi unlinked inode hash bucket.
 */
STATIC void
xlog_recover_clear_agi_bucket(
	struct xfs_perag	*pag,
	int			bucket)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_trans	*tp;
	struct xfs_agi		*agi;
	struct xfs_buf		*agibp;
	int			offset;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_clearagi, 0, 0, 0, &tp);
	if (error)
		goto out_error;

	error = xfs_read_agi(pag, tp, 0, &agibp);
	if (error)
		goto out_abort;

	agi = agibp->b_addr;
	agi->agi_unlinked[bucket] = cpu_to_be32(NULLAGINO);
	offset = offsetof(xfs_agi_t, agi_unlinked) +
		 (sizeof(xfs_agino_t) * bucket);
	xfs_trans_log_buf(tp, agibp, offset,
			  (offset + sizeof(xfs_agino_t) - 1));

	error = xfs_trans_commit(tp);
	if (error)
		goto out_error;
	return;

out_abort:
	xfs_trans_cancel(tp);
out_error:
	xfs_warn(mp, "%s: failed to clear agi %d. Continuing.", __func__,
			pag_agno(pag));
	return;
}

static int
xlog_recover_iunlink_bucket(
	struct xfs_perag	*pag,
	struct xfs_agi		*agi,
	int			bucket)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_inode	*prev_ip = NULL;
	struct xfs_inode	*ip;
	xfs_agino_t		prev_agino, agino;
	int			error = 0;

	agino = be32_to_cpu(agi->agi_unlinked[bucket]);
	while (agino != NULLAGINO) {
		error = xfs_iget(mp, NULL, xfs_agino_to_ino(pag, agino), 0, 0,
				&ip);
		if (error)
			break;

		ASSERT(VFS_I(ip)->i_nlink == 0);
		ASSERT(VFS_I(ip)->i_mode != 0);
		xfs_iflags_clear(ip, XFS_IRECOVERY);
		/* (F1): membership established by this walk — the
		 * later remove must target THIS bucket, not a recomputation. */
		ip->i_unlinked_bucket = (short)bucket;
		agino = ip->i_next_unlinked;

		if (prev_ip) {
			ip->i_prev_unlinked = prev_agino;
			xfs_irele(prev_ip);

			/*
			 * Ensure the inode is removed from the unlinked list
			 * before we continue so that it won't race with
			 * building the in-memory list here. This could be
			 * serialised with the agibp lock, but that just
			 * serialises via lockstepping and it's much simpler
			 * just to flush the inodegc queue and wait for it to
			 * complete.
			 */
			error = xfs_inodegc_flush(mp);
			if (error)
				break;
		}

		prev_agino = agino;
		prev_ip = ip;
	}

	if (prev_ip) {
		int	error2;

		ip->i_prev_unlinked = prev_agino;
		xfs_irele(prev_ip);

		error2 = xfs_inodegc_flush(mp);
		if (error2 && !error)
			return error2;
	}
	return error;
}

/*
 * Recover AGI unlinked lists
 *
 * This is called during recovery to process any inodes which we unlinked but
 * not freed when the system crashed.  These inodes will be on the lists in the
 * AGI blocks. What we do here is scan all the AGIs and fully truncate and free
 * any inodes found on the lists. Each inode is removed from the lists when it
 * has been fully truncated and is freed. The freeing of the inode and its
 * removal from the list must be atomic.
 *
 * If everything we touch in the agi processing loop is already in memory, this
 * loop can hold the cpu for a long time. It runs without lock contention,
 * memory allocation contention, the need wait for IO, etc, and so will run
 * until we either run out of inodes to process, run low on memory or we run out
 * of log space.
 *
 * This behaviour is bad for latency on single CPU and non-preemptible kernels,
 * and can prevent other filesystem work (such as CIL pushes) from running. This
 * can lead to deadlocks if the recovery process runs out of log reservation
 * space. Hence we need to yield the CPU when there is other kernel work
 * scheduled on this CPU to ensure other scheduled work can run without undue
 * latency.
 */
static void
xlog_recover_iunlink_ag(
	struct xfs_perag	*pag)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct xfs_agi		*agi;
	struct xfs_buf		*agibp;
	int			bucket;
	int			error;

	error = xfs_read_agi(pag, NULL, 0, &agibp);
	if (error) {
		/*
		 * AGI is b0rked. Don't process it.
		 *
		 * We should probably mark the filesystem as corrupt after we've
		 * recovered all the ag's we can....
		 */
		return;
	}

	/*
	 * Unlock the buffer so that it can be acquired in the normal course of
	 * the transaction to truncate and free each inode.  Because we are not
	 * racing with anyone else here for the AGI buffer, we don't even need
	 * to hold it locked to read the initial unlinked bucket entries out of
	 * the buffer. We keep buffer reference though, so that it stays pinned
	 * in memory while we need the buffer.
	 */
	agi = agibp->b_addr;
	xfs_buf_unlock(agibp);

	for (bucket = 0; bucket < XFS_AGI_UNLINKED_BUCKETS; bucket++) {
		/*
		 * (D-AGI-UNLINKED F1, recovery scoping): on a
		 * multi-node mount this recovery owns ONLY its own slot's
		 * bucket — every other bucket belongs to a live peer (its
		 * members are the peer's in-flight open-unlinked inodes;
		 * "recovering" them frees a live inode) or to a dead node
		 * whose slice the elected survivor replays and whose bucket
		 * that survivor sweeps.  Walking them here was the mount-time
		 * arm of the cross-node zombie-recovery defect.  A genuinely
		 * single-node cluster (first mounter forming a new cluster,
		 * or degraded to one) still sweeps all 64, which also drains
		 * legacy agino-hashed leftovers.
		 */
		if (mp->m_mxfs_dlm &&
		    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
		    bucket != (int)(mp->m_mxfs_node_slot %
				    XFS_AGI_UNLINKED_BUCKETS)) {
			if (be32_to_cpu(agi->agi_unlinked[bucket]) !=
			    NULLAGINO)
				pr_warn_ratelimited(
	"mxfs: P86-UNL-RECOVERY-SCOPE-SKIP agno=%u bucket=%d head=0x%x — peer-owned bucket left to its owner\n",
					pag_agno(pag), bucket,
					be32_to_cpu(
						agi->agi_unlinked[bucket]));
			continue;
		}
		error = xlog_recover_iunlink_bucket(pag, agi, bucket);
		if (error) {
			/*
			 * Bucket is unrecoverable, so only a repair scan can
			 * free the remaining unlinked inodes. Just empty the
			 * bucket and remaining inodes on it unreferenced and
			 * unfreeable.
			 */
			xlog_recover_clear_agi_bucket(pag, bucket);
		}
	}

	xfs_buf_rele(agibp);
}

static void
xlog_recover_process_iunlinks(
	struct xlog	*log)
{
	struct xfs_perag	*pag = NULL;

	while ((pag = xfs_perag_next(log->l_mp, pag)))
		xlog_recover_iunlink_ag(pag);
}

STATIC void
xlog_unpack_data(
	struct xlog_rec_header	*rhead,
	char			*dp,
	struct xlog		*log)
{
	int			i;

	for (i = 0; i < BTOBB(be32_to_cpu(rhead->h_len)); i++) {
		*(__be32 *)dp = *xlog_cycle_data(rhead, i);
		dp += BBSIZE;
	}
}

/*
 * CRC check, unpack and process a log record.
 */
STATIC int
xlog_recover_process(
	struct xlog		*log,
	struct hlist_head	rhash[],
	struct xlog_rec_header	*rhead,
	char			*dp,
	int			pass,
	struct list_head	*buffer_list)
{
	__le32			expected_crc = rhead->h_crc, crc, other_crc;

	crc = xlog_cksum(log, rhead, dp, XLOG_REC_SIZE,
			be32_to_cpu(rhead->h_len));

	/*
	 * Look at the end of the struct xlog_rec_header definition in
	 * xfs_log_format.h for the glory details.
	 */
	if (expected_crc && crc != expected_crc) {
		other_crc = xlog_cksum(log, rhead, dp, XLOG_REC_SIZE_OTHER,
				be32_to_cpu(rhead->h_len));
		if (other_crc == expected_crc) {
			xfs_notice_once(log->l_mp,
	"Fixing up incorrect CRC due to padding.");
			crc = other_crc;
		}
	}

	/*
	 * Nothing else to do if this is a CRC verification pass. Just return
	 * if this a record with a non-zero crc. Unfortunately, mkfs always
	 * sets expected_crc to 0 so we must consider this valid even on v5
	 * supers.  Otherwise, return EFSBADCRC on failure so the callers up the
	 * stack know precisely what failed.
	 */
	if (pass == XLOG_RECOVER_CRCPASS) {
		if (expected_crc && crc != expected_crc)
			return -EFSBADCRC;
		return 0;
	}

	/*
	 * We're in the normal recovery path. Issue a warning if and only if the
	 * CRC in the header is non-zero. This is an advisory warning and the
	 * zero CRC check prevents warnings from being emitted when upgrading
	 * the kernel from one that does not add CRCs by default.
	 */
	if (crc != expected_crc) {
		if (expected_crc || xfs_has_crc(log->l_mp)) {
			xfs_alert(log->l_mp,
		"log record CRC mismatch: found 0x%x, expected 0x%x.",
					le32_to_cpu(expected_crc),
					le32_to_cpu(crc));
			xfs_hex_dump(dp, 32);
		}

		/*
		 * If the filesystem is CRC enabled, this mismatch becomes a
		 * fatal log corruption failure.
		 */
		if (xfs_has_crc(log->l_mp)) {
			XFS_ERROR_REPORT(__func__, XFS_ERRLEVEL_LOW, log->l_mp);
			return -EFSCORRUPTED;
		}
	}

	xlog_unpack_data(rhead, dp, log);

	return xlog_recover_process_data(log, rhash, rhead, dp, pass,
					 buffer_list);
}

STATIC int
xlog_valid_rec_header(
	struct xlog		*log,
	struct xlog_rec_header	*rhead,
	xfs_daddr_t		blkno,
	int			bufsize)
{
	struct xfs_mount	*mp = log->l_mp;
	u32			h_version = be32_to_cpu(rhead->h_version);
	int			hlen;

	if (XFS_IS_CORRUPT(mp,
			   rhead->h_magicno != cpu_to_be32(MXFS_LOG_HEADER_MAGIC_NUM)))
		return -EFSCORRUPTED;

	/*
	 * The log version must match the superblock
	 */
	if (xfs_has_logv2(mp)) {
		if (XFS_IS_CORRUPT(mp, h_version != XLOG_VERSION_2))
			return -EFSCORRUPTED;
	} else {
		if (XFS_IS_CORRUPT(mp, h_version != XLOG_VERSION_1))
			return -EFSCORRUPTED;
	}

	/*
	 * LR body must have data (or it wouldn't have been written)
	 * and h_len must not be greater than LR buffer size.
	 */
	hlen = be32_to_cpu(rhead->h_len);
	if (XFS_IS_CORRUPT(mp, hlen <= 0 || hlen > bufsize))
		return -EFSCORRUPTED;

	if (XFS_IS_CORRUPT(mp, blkno > log->l_logBBsize || blkno > INT_MAX))
		return -EFSCORRUPTED;

	return 0;
}

/*
 * THE PARTIAL-REPLAY CUT.  Make a nonempty PREFIX of this pass's replayed
 * buffers durable, leave a nonempty required SUFFIX unissued, advance no
 * completion marker, and park so the node can be destroyed there.  The
 * knobs, and why this is the only place the state is reachable, are
 * documented with them in xfs_mxfs_dlm.c; the lap's shape and the assertions
 * it owes are in
 * docs/rulings/fence-matrix-remaining-gates-and-partial-replay.md.
 *
 * Two things here are deliberate and are the difference between a cut and a
 * coincidence.
 *
 * IT REFUSES A VACUOUS CUT.  A prefix that would take the whole list leaves
 * no suffix, and "everything was applied" is not a partial replay — it is the
 * ordinary success this lap is supposed to differ from.  The same goes for a
 * prefix of zero.  Either way the cut is declined LOUDLY and the pass
 * proceeds normally, so the harness sees that nothing was measured instead of
 * grading a lap that quietly became its own control.
 *
 * IT WAITS, AND THEN FLUSHES.  xfs_buf_delwri_submit() returns when the
 * writes have completed, which is not the same as their being durable, and
 * the whole point of the prefix is that a successor must find it ALREADY
 * APPLIED.  A cut that parked on completion alone would leave the platter
 * state dependent on a cache nobody in this experiment controls.
 */
STATIC int
mxfs_replay_cut_partial(
	struct xlog		*log,
	struct list_head	*buffer_list)
{
	LIST_HEAD		(prefix);
	struct xfs_buf		*bp, *nbp;
	unsigned int		want = (unsigned int)mxfs_dbg_replay_cut_prefix;
	unsigned int		moved = 0, left = 0;
	int			hold = mxfs_dbg_replay_cut_hold_ms > 0 ?
					mxfs_dbg_replay_cut_hold_ms : 0;
	int			err, frc;

	mxfs_dbg_replay_cut_prefix = 0;			/* one-shot */

	list_for_each_entry_safe(bp, nbp, buffer_list, b_list) {
		if (moved >= want)
			break;
		list_move_tail(&bp->b_list, &prefix);
		moved++;
	}
	list_for_each_entry(bp, buffer_list, b_list)
		left++;

	if (!moved || !left) {
		pr_warn("mxfs: P-DBG-REPLAY-CUT-VACUOUS slot=%u victim_inc=%llu want=%u queued=%u — a prefix of %u over %u queued buffer(s) leaves no nonempty suffix (or no nonempty prefix), so this is not a partial replay.  NOTHING is cut, the pass submits normally, and this lap measured nothing\n",
			log->l_mxfs_victim_slot,
			(unsigned long long)log->l_mxfs_victim_epoch,
			want, moved + left, want, moved + left);
		list_splice_init(&prefix, buffer_list);
		return xfs_buf_delwri_submit(buffer_list);
	}

	err = xfs_buf_delwri_submit(&prefix);
	frc = blkdev_issue_flush(log->l_mp->m_ddev_targp->bt_bdev);
	pr_warn("mxfs: P-DBG-REPLAY-CUT slot=%u victim_inc=%llu prefix=%u suffix=%u submit_rc=%d flush_rc=%d — %u replayed buffer(s) are DURABLE on home storage and %u required one(s) were never issued.  No completion marker has advanced, no slice is retired or zeroed and the source journal is intact.  Parking %d ms: destroy the VM now\n",
		log->l_mxfs_victim_slot,
		(unsigned long long)log->l_mxfs_victim_epoch,
		moved, left, err, frc, moved, left, hold);
	if (hold > 0)
		msleep(hold);
	pr_warn("mxfs: P-DBG-REPLAY-CUT-EXPIRED slot=%u victim_inc=%llu suffix=%u — the hold expired without a crash.  The remaining buffers are being submitted so the filesystem is left consistent, and THIS LAP IS CONTAMINATED: it no longer holds the state it was arming for and its outcome must not be read as a recovery result\n",
		log->l_mxfs_victim_slot,
		(unsigned long long)log->l_mxfs_victim_epoch, left);
	err = xfs_buf_delwri_submit(buffer_list);
	return err;
}

/*
 * Is the partial-replay cut armed for THIS replay?  Slot and incarnation both
 * have to match, and an unset filter matches anything — but only the
 * incarnation is allowed to be unset by default, because a slot number is
 * reused and an unfiltered slot is how a one-shot fires on the wrong victim.
 */
STATIC bool
mxfs_replay_cut_armed(
	struct xlog		*log)
{
	if (mxfs_dbg_replay_cut_prefix <= 0)
		return false;
	if (!xlog_is_mxfs_foreign_replay(log))
		return false;
	if (mxfs_dbg_replay_cut_slot >= 0 &&
	    (uint32_t)mxfs_dbg_replay_cut_slot != log->l_mxfs_victim_slot)
		return false;
	if (mxfs_dbg_replay_cut_epoch &&
	    mxfs_dbg_replay_cut_epoch != log->l_mxfs_victim_epoch)
		return false;
	return true;
}

/*
 * Read the log from tail to head and process the log records found.
 * Handle the two cases where the tail and head are in the same cycle
 * and where the active portion of the log wraps around the end of
 * the physical log separately.  The pass parameter is passed through
 * to the routines called to process the data and is not looked at
 * here.
 */
STATIC int
xlog_do_recovery_pass(
	struct xlog		*log,
	xfs_daddr_t		head_blk,
	xfs_daddr_t		tail_blk,
	int			pass,
	xfs_daddr_t		*first_bad)	/* out: first bad log rec */
{
	struct xlog_rec_header	*rhead;
	xfs_daddr_t		blk_no, rblk_no;
	xfs_daddr_t		rhead_blk;
	char			*offset;
	char			*hbp, *dbp;
	int			error = 0, h_size, h_len;
	int			error2 = 0;
	int			bblks, split_bblks;
	int			hblks = 1, split_hblks, wrapped_hblks;
	int			i;
	struct hlist_head	rhash[XLOG_RHASH_SIZE];
	LIST_HEAD		(buffer_list);

	ASSERT(head_blk != tail_blk);
	blk_no = rhead_blk = tail_blk;

	for (i = 0; i < XLOG_RHASH_SIZE; i++)
		INIT_HLIST_HEAD(&rhash[i]);

	hbp = xlog_alloc_buffer(log, hblks);
	if (!hbp)
		return -ENOMEM;

	/*
	 * Read the header of the tail block and get the iclog buffer size from
	 * h_size.  Use this to tell how many sectors make up the log header.
	 */
	if (xfs_has_logv2(log->l_mp)) {
		/*
		 * When using variable length iclogs, read first sector of
		 * iclog header and extract the header size from it.  Get a
		 * new hbp that is the correct size.
		 */
		error = xlog_bread(log, tail_blk, 1, hbp, &offset);
		if (error)
			goto bread_err1;

		rhead = (struct xlog_rec_header *)offset;

		/*
		 * xfsprogs has a bug where record length is based on lsunit but
		 * h_size (iclog size) is hardcoded to 32k. Now that we
		 * unconditionally CRC verify the unmount record, this means the
		 * log buffer can be too small for the record and cause an
		 * overrun.
		 *
		 * Detect this condition here. Use lsunit for the buffer size as
		 * long as this looks like the mkfs case. Otherwise, return an
		 * error to avoid a buffer overrun.
		 */
		h_size = be32_to_cpu(rhead->h_size);
		h_len = be32_to_cpu(rhead->h_len);
		if (h_len > h_size && h_len <= log->l_mp->m_logbsize &&
		    rhead->h_num_logops == cpu_to_be32(1)) {
			xfs_warn(log->l_mp,
		"invalid iclog size (%d bytes), using lsunit (%d bytes)",
				 h_size, log->l_mp->m_logbsize);
			h_size = log->l_mp->m_logbsize;
		}

		error = xlog_valid_rec_header(log, rhead, tail_blk, h_size);
		if (error)
			goto bread_err1;

		/*
		 * This open codes xlog_logrec_hblks so that we can reuse the
		 * fixed up h_size value calculated above.  Without that we'd
		 * still allocate the buffer based on the incorrect on-disk
		 * size.
		 */
		if (h_size > XLOG_HEADER_CYCLE_SIZE &&
		    (rhead->h_version & cpu_to_be32(XLOG_VERSION_2))) {
			hblks = DIV_ROUND_UP(h_size, XLOG_HEADER_CYCLE_SIZE);
			if (hblks > 1) {
				kvfree(hbp);
				hbp = xlog_alloc_buffer(log, hblks);
				if (!hbp)
					return -ENOMEM;
			}
		}
	} else {
		ASSERT(log->l_sectBBsize == 1);
		h_size = XLOG_BIG_RECORD_BSIZE;
	}

	dbp = xlog_alloc_buffer(log, BTOBB(h_size));
	if (!dbp) {
		kvfree(hbp);
		return -ENOMEM;
	}

	memset(rhash, 0, sizeof(rhash));
	if (tail_blk > head_blk) {
		/*
		 * Perform recovery around the end of the physical log.
		 * When the head is not on the same cycle number as the tail,
		 * we can't do a sequential recovery.
		 */
		while (blk_no < log->l_logBBsize) {
			/*
			 * Check for header wrapping around physical end-of-log
			 */
			offset = hbp;
			split_hblks = 0;
			wrapped_hblks = 0;
			if (blk_no + hblks <= log->l_logBBsize) {
				/* Read header in one read */
				error = xlog_bread(log, blk_no, hblks, hbp,
						   &offset);
				if (error)
					goto bread_err2;
			} else {
				/* This LR is split across physical log end */
				if (blk_no != log->l_logBBsize) {
					/* some data before physical log end */
					ASSERT(blk_no <= INT_MAX);
					split_hblks = log->l_logBBsize - (int)blk_no;
					ASSERT(split_hblks > 0);
					error = xlog_bread(log, blk_no,
							   split_hblks, hbp,
							   &offset);
					if (error)
						goto bread_err2;
				}

				/*
				 * Note: this black magic still works with
				 * large sector sizes (non-512) only because:
				 * - we increased the buffer size originally
				 *   by 1 sector giving us enough extra space
				 *   for the second read;
				 * - the log start is guaranteed to be sector
				 *   aligned;
				 * - we read the log end (LR header start)
				 *   _first_, then the log start (LR header end)
				 *   - order is important.
				 */
				wrapped_hblks = hblks - split_hblks;
				error = xlog_bread_noalign(log, 0,
						wrapped_hblks,
						offset + BBTOB(split_hblks));
				if (error)
					goto bread_err2;
			}
			rhead = (struct xlog_rec_header *)offset;
			error = xlog_valid_rec_header(log, rhead,
					split_hblks ? blk_no : 0, h_size);
			if (error)
				goto bread_err2;

			bblks = (int)BTOBB(be32_to_cpu(rhead->h_len));
			blk_no += hblks;

			/*
			 * Read the log record data in multiple reads if it
			 * wraps around the end of the log. Note that if the
			 * header already wrapped, blk_no could point past the
			 * end of the log. The record data is contiguous in
			 * that case.
			 */
			if (blk_no + bblks <= log->l_logBBsize ||
			    blk_no >= log->l_logBBsize) {
				rblk_no = xlog_wrap_logbno(log, blk_no);
				error = xlog_bread(log, rblk_no, bblks, dbp,
						   &offset);
				if (error)
					goto bread_err2;
			} else {
				/* This log record is split across the
				 * physical end of log */
				offset = dbp;
				split_bblks = 0;
				if (blk_no != log->l_logBBsize) {
					/* some data is before the physical
					 * end of log */
					ASSERT(!wrapped_hblks);
					ASSERT(blk_no <= INT_MAX);
					split_bblks =
						log->l_logBBsize - (int)blk_no;
					ASSERT(split_bblks > 0);
					error = xlog_bread(log, blk_no,
							split_bblks, dbp,
							&offset);
					if (error)
						goto bread_err2;
				}

				/*
				 * Note: this black magic still works with
				 * large sector sizes (non-512) only because:
				 * - we increased the buffer size originally
				 *   by 1 sector giving us enough extra space
				 *   for the second read;
				 * - the log start is guaranteed to be sector
				 *   aligned;
				 * - we read the log end (LR header start)
				 *   _first_, then the log start (LR header end)
				 *   - order is important.
				 */
				error = xlog_bread_noalign(log, 0,
						bblks - split_bblks,
						offset + BBTOB(split_bblks));
				if (error)
					goto bread_err2;
			}

			error = xlog_recover_process(log, rhash, rhead, offset,
						     pass, &buffer_list);
			if (error)
				goto bread_err2;

			blk_no += bblks;
			rhead_blk = blk_no;
		}

		ASSERT(blk_no >= log->l_logBBsize);
		blk_no -= log->l_logBBsize;
		rhead_blk = blk_no;
	}

	/* read first part of physical log */
	while (blk_no < head_blk) {
		error = xlog_bread(log, blk_no, hblks, hbp, &offset);
		if (error)
			goto bread_err2;

		rhead = (struct xlog_rec_header *)offset;
		error = xlog_valid_rec_header(log, rhead, blk_no, h_size);
		if (error)
			goto bread_err2;

		/* blocks in data section */
		bblks = (int)BTOBB(be32_to_cpu(rhead->h_len));
		error = xlog_bread(log, blk_no+hblks, bblks, dbp,
				   &offset);
		if (error)
			goto bread_err2;

		error = xlog_recover_process(log, rhash, rhead, offset, pass,
					     &buffer_list);
		if (error)
			goto bread_err2;

		blk_no += bblks + hblks;
		rhead_blk = blk_no;
	}

 bread_err2:
	kvfree(dbp);
 bread_err1:
	kvfree(hbp);

	/*
	 * The untrusted-replay drain deferral above keeps every buffer the pass
	 * dirtied queued until this point, so at this moment the list IS the
	 * recovery's peak pinned metadata.  Nothing bounds it but the number of
	 * distinct buffers the slice's records name, and the recovering node
	 * must hold all of it while still allocating for the remainder of the
	 * pass — one small logged region retains a whole buffer.  Measure the
	 * peak rather than assume it is small: an unbounded pin during recovery
	 * is a stability defect in its own right, and it cannot be inferred
	 * from the deferral count, which counts skipped submits and not bytes.
	 */
	if (log->l_mxfs_drain_deferred) {
		struct xfs_buf	*qbp;
		uint32_t	nbuf = 0;
		uint64_t	bytes = 0;

		list_for_each_entry(qbp, &buffer_list, b_list) {
			nbuf++;
			bytes += BBTOB(qbp->b_length);
		}
		mxfs_xfs_probe(log->l_mp,
	"MXFS: P-DRAIN-PEAK deferred=%u queued_buffers=%u queued_bytes=%llu — metadata pinned to end-of-pass by the untrusted-replay drain deferral; unbounded except by the slice's distinct-buffer count",
			   log->l_mxfs_drain_deferred, nbuf,
			   (unsigned long long)bytes);
	}

	/*
	 * Submit buffers that have been dirtied by the last record recovered.
	 */
	if (!list_empty(&buffer_list)) {
		if (error) {
			/*
			 * If there has been an item recovery error then we
			 * cannot allow partial checkpoint writeback to
			 * occur.  We might have multiple checkpoints with the
			 * same start LSN in this buffer list, and partial
			 * writeback of a checkpoint in this situation can
			 * prevent future recovery of all the changes in the
			 * checkpoints at this start LSN.
			 *
			 * 513B (design-consult ruling): the upstream
			 * unwind below achieves that by shutting down
			 * log->l_mp so the delwri submission stales the
			 * batch without I/O — but on a FOREIGN-slice replay
			 * this xlog is a shadow whose l_mp is the SURVIVOR's
			 * live mount, so that unwind kills the replayer (the
			 * exact D-513 suicide class).  For the foreign shadow
			 * fail the batch directly instead: no I/O, no
			 * shutdown-state consultation, error propagated so
			 * the slice recovery is refused (TORN verdict) and
			 * quarantined by the caller.  Adopted-slice
			 * mount-time recovery deliberately KEEPS the upstream
			 * shutdown: that log is the mounting fs's own log,
			 * and skipping its shutdown would let the
			 * mount-failure teardown write an unmount record over
			 * a dirty slice whose replay just failed.
			 *
			 * Note: Shutting down the filesystem will result in the
			 * delwri submission marking all the buffers stale,
			 * completing them and cleaning up _XBF_LOGRECOVERY
			 * state without doing any IO.
			 */
			if (xlog_is_mxfs_foreign_replay(log)) {
				mxfs_probe("mxfs: P227-FR-UNWIND err=%d — foreign-slice pass-2 error with queued buffers; failing batch without I/O, survivor mount untouched\n",
					error);
				error2 = xfs_buf_delwri_fail(&buffer_list,
							     error);
			} else {
				xlog_force_shutdown(log,
						    SHUTDOWN_LOG_IO_ERROR);
				error2 = xfs_buf_delwri_submit(&buffer_list);
			}
		} else if (mxfs_replay_cut_armed(log)) {
			error2 = mxfs_replay_cut_partial(log, &buffer_list);
		} else {
			error2 = xfs_buf_delwri_submit(&buffer_list);
		}
	}

	if (error && first_bad)
		*first_bad = rhead_blk;

	/*
	 * Transactions are freed at commit time but transactions without commit
	 * records on disk are never committed. Free any that may be left in the
	 * hash table.
	 */
	for (i = 0; i < XLOG_RHASH_SIZE; i++) {
		struct hlist_node	*tmp;
		struct xlog_recover	*trans;

		hlist_for_each_entry_safe(trans, tmp, &rhash[i], r_list)
			xlog_recover_free_trans(trans);
	}

	return error ? error : error2;
}

/*
 * Do the recovery of the log.  We actually do this in two phases.
 * The two passes are necessary in order to implement the function
 * of cancelling a record written into the log.  The first pass
 * determines those things which have been cancelled, and the
 * second pass replays log items normally except for those which
 * have been cancelled.  The handling of the replay and cancellations
 * takes place in the log item type specific routines.
 *
 * The table of items which have cancel records in the log is allocated
 * and freed at this level, since only here do we know when all of
 * the log recovery has been completed.
 */
STATIC int
xlog_do_log_recovery(
	struct xlog	*log,
	xfs_daddr_t	head_blk,
	xfs_daddr_t	tail_blk)
{
	int		error;

	ASSERT(head_blk != tail_blk);

	/*
	 * First do a pass to find all of the cancelled buf log items.
	 * Store them in the buf_cancel_table for use in the second pass.
	 */
	error = xlog_alloc_buf_cancel_table(log);
	if (error)
		return error;
	/* parked CANCEL-bearing untrusted txns (mxfs_cdefer_stash) */
	INIT_LIST_HEAD(&log->l_mxfs_cdefer);

	error = xlog_do_recovery_pass(log, head_blk, tail_blk,
				      XLOG_RECOVER_PASS1, NULL);
	if (error != 0)
		goto out_cancel;

	/*
	 * the pass-1 walk is complete (every clean-release marker
	 * collected) — decide the parked transactions and put a refused one's
	 * cancel entries back out BEFORE pass 2 applies anything.
	 */
	error = mxfs_cdefer_resolve(log);
	if (error)
		goto out_cancel;

	/*
	 * Then do a second pass to actually recover the items in the log.
	 * When it is complete free the table of buf cancel items.
	 */
	error = xlog_do_recovery_pass(log, head_blk, tail_blk,
				      XLOG_RECOVER_PASS2, NULL);
	if (!error)
		xlog_check_buf_cancel_table(log);
out_cancel:
	mxfs_cdefer_free(log);
	xlog_free_buf_cancel_table(log);
	return error;
}

/*
 * Do the actual recovery
 */
STATIC int
xlog_do_recover(
	struct xlog		*log,
	xfs_daddr_t		head_blk,
	xfs_daddr_t		tail_blk)
{
	struct xfs_mount	*mp = log->l_mp;
	struct xfs_buf		*bp = mp->m_sb_bp;
	struct xfs_sb		*sbp = &mp->m_sb;
	int			error;

	trace_xfs_log_recover(log, head_blk, tail_blk);

	/*
	 * First replay the images in the log.
	 */
	error = xlog_do_log_recovery(log, head_blk, tail_blk);
	if (error)
		return error;

	if (xlog_is_shutdown(log))
		return -EIO;

	/*
	 * an ADOPTED own-slice mount replay skipped the previous
	 * incarnation's intents through the same census as a foreign replay.
	 * Print it here (the foreign shadow prints from its terminal
	 * predicate in xfs_log.c); an open set on this path is the
	 * D-OWN-CRASH-RECLAIM / settle_own_slot problem, reported LOUDLY and
	 * not yet a mount refusal.
	 */
	if (!xlog_is_mxfs_foreign_replay(log) &&
	    !xlog_is_mxfs_bootstrap_adopted(log) &&	/* intents applied */
	    xlog_is_mxfs_untrusted_replay(log)) {
		uint64_t	imask = 0;
		bool		ifsw = false;
		uint32_t	nopen;

		nopen = mxfs_icensus_undischarged(log, "adopted", &imask,
						  &ifsw, NULL);
		if (nopen)
			xfs_alert(log->l_mp,
	"MXFS adopted replay: P226-ICENSUS-ADOPTED-OPEN %u intent obligation(s) of the previous incarnation are UNDISCHARGED (fswide=%d ag_mask=0x%llx) — the own-slot reclaim path has no owner for them",
				  nopen, (int)ifsw, (unsigned long long)imask);
	}

	/*
	 * MXFS foreign-slice replay: the metadata images are now on disk and
	 * that is ALL this path needs.  The remaining steps below are
	 * mount-time-only side effects — tail-lsn assignment belongs to the
	 * slice owner's AIL, and re-initialising the in-core superblock /
	 * percpu counters would clobber this node's live state.
	 */
	if (xlog_is_mxfs_foreign_replay(log)) {
		clear_bit(XLOG_ACTIVE_RECOVERY, &log->l_opstate);
		return 0;
	}

	/*
	 * We now update the tail_lsn since much of the recovery has completed
	 * and there may be space available to use.  If there were no extent or
	 * iunlinks, we can free up the entire log.  This was set in
	 * xlog_find_tail to be the lsn of the last known good LR on disk.  If
	 * there are extent frees or iunlinks they will have some entries in the
	 * AIL; so we look at the AIL to determine how to set the tail_lsn.
	 */
	xfs_ail_assign_tail_lsn(log->l_ailp);

	/*
	 * Now that we've finished replaying all buffer and inode updates,
	 * re-read the superblock and reverify it.
	 */
	xfs_buf_lock(bp);
	xfs_buf_hold(bp);
	error = _xfs_buf_read(bp);
	if (error) {
		if (!xlog_is_shutdown(log)) {
			xfs_buf_ioerror_alert(bp, __this_address);
			ASSERT(0);
		}
		xfs_buf_relse(bp);
		return error;
	}

	/* Convert superblock from on-disk format */
	xfs_sb_from_disk(sbp, bp->b_addr);
	xfs_buf_relse(bp);

	/* re-initialise in-core superblock and geometry structures */
	mp->m_features |= xfs_sb_version_to_features(sbp);
	xfs_reinit_percpu_counters(mp);

	/* Normal transactions can now occur */
	clear_bit(XLOG_ACTIVE_RECOVERY, &log->l_opstate);
	return 0;
}

/*
 * Perform recovery and re-initialize some log variables in xlog_find_tail.
 *
 * Return error or zero.
 */
int
xlog_recover(
	struct xlog	*log)
{
	xfs_daddr_t	head_blk, tail_blk;
	int		error;

	/* find the tail of the log */
	error = xlog_find_tail(log, &head_blk, &tail_blk);
	if (error)
		return error;

	/*
	 * The superblock was read before the log was available and thus the LSN
	 * could not be verified. Check the superblock LSN against the current
	 * LSN now that it's known.
	 */
	/*
	 * MXFS foreign-slice replay: sb_lsn was stamped by whichever node
	 * last wrote the superblock from ITS OWN log slice; LSN cycle
	 * numbers are not comparable across per-node slices, so this check
	 * would spuriously fail.  Skip it — the slice's own records are
	 * still CRC-verified during the recovery passes.
	 */
	if (!xlog_is_mxfs_foreign_replay(log) &&
	    xfs_has_crc(log->l_mp) &&
	    !xfs_log_check_lsn(log->l_mp, log->l_mp->m_sb.sb_lsn))
		return -EINVAL;

	if (tail_blk != head_blk) {
		/* There used to be a comment here:
		 *
		 * disallow recovery on read-only mounts.  note -- mount
		 * checks for ENOSPC and turns it into an intelligent
		 * error message.
		 * ...but this is no longer true.  Now, unless you specify
		 * NORECOVERY (in which case this function would never be
		 * called), we just go ahead and recover.  We do this all
		 * under the vfs layer, so we can get away with it unless
		 * the device itself is read-only, in which case we fail.
		 */
		if ((error = xfs_dev_is_read_only(log->l_mp, "recovery"))) {
			return error;
		}

		/*
		 * Version 5 superblock log feature mask validation. We know the
		 * log is dirty so check if there are any unknown log features
		 * in what we need to recover. If there are unknown features
		 * (e.g. unsupported transactions, then simply reject the
		 * attempt at recovery before touching anything.
		 */
		if (xfs_sb_is_v5(&log->l_mp->m_sb) &&
		    xfs_sb_has_incompat_log_feature(&log->l_mp->m_sb,
					XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN)) {
			xfs_warn(log->l_mp,
"Superblock has unknown incompatible log features (0x%x) enabled.",
				(log->l_mp->m_sb.sb_features_log_incompat &
					XFS_SB_FEAT_INCOMPAT_LOG_UNKNOWN));
			xfs_warn(log->l_mp,
"The log can not be fully and/or safely recovered by this kernel.");
			xfs_warn(log->l_mp,
"Please recover the log on a kernel that supports the unknown features.");
			return -EINVAL;
		}

		/*
		 * Delay log recovery if the debug hook is set. This is debug
		 * instrumentation to coordinate simulation of I/O failures with
		 * log recovery.
		 */
		if (xfs_globals.log_recovery_delay) {
			xfs_notice(log->l_mp,
				"Delaying log recovery for %d seconds.",
				xfs_globals.log_recovery_delay);
			msleep(xfs_globals.log_recovery_delay * 1000);
		}

		xfs_notice(log->l_mp, "Starting recovery (logdev: %s)",
				log->l_mp->m_logname ? log->l_mp->m_logname
						     : "internal");

		error = xlog_do_recover(log, head_blk, tail_blk);
		set_bit(XLOG_RECOVERY_NEEDED, &log->l_opstate);
	}
	return error;
}

/*
 * In the first part of recovery we replay inodes and buffers and build up the
 * list of intents which need to be processed. Here we process the intents and
 * clean up the on disk unlinked inode lists. This is separated from the first
 * part of recovery so that the root and real-time bitmap inodes can be read in
 * from disk in between the two stages.  This is necessary so that we can free
 * space in the real-time portion of the file system.
 *
 * We run this whole process under GFP_NOFS allocation context. We do a
 * combination of non-transactional and transactional work, yet we really don't
 * want to recurse into the filesystem from direct reclaim during any of this
 * processing. This allows all the recovery code run here not to care about the
 * memory allocation context it is running in.
 */
int
xlog_recover_finish(
	struct xlog	*log)
{
	unsigned int	nofs_flags = memalloc_nofs_save();
	int		error;

	error = xlog_recover_process_intents(log);
	if (error) {
		/*
		 * Cancel all the unprocessed intent items now so that we don't
		 * leave them pinned in the AIL.  This can cause the AIL to
		 * livelock on the pinned item if anyone tries to push the AIL
		 * (inode reclaim does this) before we get around to
		 * xfs_log_mount_cancel.
		 */
		xlog_recover_cancel_intents(log);
		xfs_alert(log->l_mp, "Failed to recover intents");
		xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR);
		goto out_error;
	}

	/*
	 * Sync the log to get all the intents out of the AIL.  This isn't
	 * absolutely necessary, but it helps in case the unlink transactions
	 * would have problems pushing the intents out of the way.
	 */
	xfs_log_force(log->l_mp, XFS_LOG_SYNC);

	xlog_recover_process_iunlinks(log);

	/*
	 * Recover any CoW staging blocks that are still referenced by the
	 * ondisk refcount metadata.  During mount there cannot be any live
	 * staging extents as we have not permitted any user modifications.
	 * Therefore, it is safe to free them all right now, even on a
	 * read-only mount.
	 */
	error = xfs_reflink_recover_cow(log->l_mp);
	if (error) {
		xfs_alert(log->l_mp,
	"Failed to recover leftover CoW staging extents, err %d.",
				error);
		/*
		 * If we get an error here, make sure the log is shut down
		 * but return zero so that any log items committed since the
		 * end of intents processing can be pushed through the CIL
		 * and AIL.
		 */
		xlog_force_shutdown(log, SHUTDOWN_LOG_IO_ERROR);
		error = 0;
		goto out_error;
	}

out_error:
	memalloc_nofs_restore(nofs_flags);
	return error;
}

void
xlog_recover_cancel(
	struct xlog	*log)
{
	if (xlog_recovery_needed(log))
		xlog_recover_cancel_intents(log);
}

