// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS — real EFI completion for a dead peer's OPEN obligation case
 * (D-FOREIGN-SLICE-INTENTS-ABANDONED, 0.85.0; the TCP custody model in
 * docs/dlm-protocol.md "Item 5").
 *
 * The custodian is the survivor holding the recovery execution lease for a
 * victim whose descriptor is durably at IMAGES_REPLAYED with an OPEN
 * obligation record: the victim's base images are replayed and home (nobody
 * re-replays past that milestone), the dead node's grants are retired, and
 * the AGs in the record's mask are frozen on every live node against every
 * ordinary acquire (xfs_mxfs_dlm.c, the obligation freeze).  What is owed is
 * the free of every extent an open EFI named: the victim logged the intent,
 * unmapped the extent from its file, and died before the done transaction
 * that would have inserted it into the bnobt.
 *
 * Per extent, in the list's canonical (agno, agbno) order, ONE bounded live
 * transaction on this node: read the AGF, query the bnobt over the extent:
 *   EMPTY  — still allocated: free it directly (xfs_free_ag_extent, owner
 *            unknown, no reservation, busy-extent bookkeeping kept), commit.
 *            No replacement EFI, no deferred work, no roll.
 *   FULL   — already free: skip.  Safe ONLY because the freeze never
 *            lapsed: the only writer that could have freed it is a prior
 *            custodian whose committed free was replayed home before this
 *            case resumed (the worker's takeover dependency), and nobody
 *            could have re-allocated it since.
 *   SPARSE — partially free: neither answer is safe; the case goes TERMINAL
 *            (OBLIGATION_UNRECONCILABLE over the record's AG mask) and the
 *            quarantine takes over from the freeze.
 * After the last extent the log is forced, the allocation metadata is
 * destaged home and the device flushed, then the completion proof is made
 * durable and OBLIGATIONS_DONE advanced in one compare-and-write.  Only then
 * does the ladder release anything.
 *
 * A custodian that dies anywhere in here leaves a case a successor re-runs
 * from the start over the same durable list: every free it committed is
 * replayed home first and reads FULL; every free it did not commit reads
 * EMPTY.  No per-extent durable outcome is needed for that, which is why the
 * proof is written once, at the end.
 */
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_mount.h"
#include "xfs_btree.h"
#include "xfs_alloc.h"
#include "xfs_alloc_btree.h"
#include "xfs_rmap.h"
#include "xfs_extent_busy.h"
#include "xfs_trans.h"
#include "xfs_log.h"
#include "xfs_error.h"
#include "xfs_ag.h"
#include "xfs_mxfs_dlm.h"
#include "../dlm/v5_mount.h"
#include "../dlm/disklock.h"	/* MXFS_OBL_* observer states */
#include "../dlm/recov_obl.h"
#include "../dlm/recov_obl_done.h"

/* the custodian's wait for a quiet AG: one transaction time, budgeted like
 * a dead holder's frozen grant */
#define MXFS_OBL_QUIESCE_MS	120000u

/*
 * TEST ONLY (kill-the-custodian lap): a one-shot hold, in ms, taken after
 * the FIRST extent's transaction has committed and before the second is
 * begun.  The harness destroys the custodian inside the hold, so the
 * successor finds one extent already freed (FULL) and the rest still
 * allocated (EMPTY) over the same durable list.  Consumed on use.
 */
static int mxfs_dbg_obl_engine_hold_ms;
module_param_named(dbg_obl_engine_hold_ms, mxfs_dbg_obl_engine_hold_ms, int, 0644);
MODULE_PARM_DESC(dbg_obl_engine_hold_ms,
	"TEST: one-shot hold (ms) inside the obligation engine after the first extent commits");
/* per-extent notices are bounded per case; the counters are not */
#define MXFS_OBL_NOTICES	64u

/*
 * One extent, one transaction.  Returns 0 with *outcome set, or -errno.  A
 * FULL/SPARSE outcome commits the (possibly AGFL-dirtied) transaction rather
 * than cancelling it: xfs_alloc_fix_freelist may legitimately have moved
 * blocks into the freelist, and a dirty cancel is a shutdown.
 */
static int
mxfs_recov_obl_one(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	xfs_agblock_t		agbno,
	xfs_extlen_t		len,
	enum xbtree_recpacking	*outcome)
{
	struct xfs_trans	*tp;
	struct xfs_buf		*agbp = NULL;
	struct xfs_btree_cur	*cur;
	int			error;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_itruncate, 0, 0, 0, &tp);
	if (error)
		return error;
	/* blocking: the custodian task is exempt from the freeze it holds;
	 * the dead node's grant on this AG is already retired */
	error = mxfs_ag_dlm_lock(mp, pag);
	if (error)
		goto cancel;
	error = xfs_free_extent_fix_freelist(tp, pag, &agbp);
	if (error)
		goto unlock_cancel;
	cur = xfs_bnobt_init_cursor(mp, tp, agbp, pag);
	error = xfs_alloc_has_records(cur, agbno, len, outcome);
	xfs_btree_del_cursor(cur, error);
	if (error)
		goto unlock_cancel;
	if (*outcome == XBTREE_RECPACKING_EMPTY) {
		error = xfs_free_ag_extent(tp, agbp, agbno, len,
					   &XFS_RMAP_OINFO_ANY_OWNER,
					   XFS_AG_RESV_NONE);
		if (error)
			goto unlock_cancel;
		xfs_extent_busy_insert(tp, pag_group(pag), agbno, len, 0);
	}
	/* the AG grant is released when the transaction is freed, like
	 * every other extent free on this node */
	mxfs_ag_dlm_unlock_deferred(tp, pag);
	return xfs_trans_commit(tp);

unlock_cancel:
	mxfs_ag_dlm_unlock(mp, pag);
cancel:
	xfs_trans_cancel(tp);
	return error;
}

int
mxfs_recov_obl_complete(
	struct xfs_mount		*mp,
	unsigned int			slot)
{
	struct mxfs_v5_dlm		*dlm = mp->m_mxfs_dlm;
	struct mxfs_recov_obl		rec;
	struct mxfs_recov_obl_ext	*ext = NULL;
	struct mxfs_rman_obl_done	*proof = NULL;
	struct xfs_perag		*pag = NULL;
	uint32_t			count = 0, i, notices = 0;
	uint32_t			n_empty = 0, n_full = 0;
	xfs_agnumber_t			cur_agno = NULLAGNUMBER;
	unsigned long			t0 = jiffies;
	int				rc;

	if (!dlm || slot >= 64)
		return -EINVAL;
	ext = kvcalloc(MXFS_RECOV_OBL_MAX_EXTENTS, sizeof(*ext), GFP_KERNEL);
	proof = kzalloc(sizeof(*proof), GFP_KERNEL);
	if (!ext || !proof) {
		rc = -ENOMEM;
		goto out;
	}
	rc = mxfs_v5_dlm_recovery_read_obl(dlm, (int)slot, &rec, ext, &count);
	if (rc) {
		xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-READ slot=%u rc=%d — the obligation record/list did not read back valid; nothing completed (the ladder holds the case)",
			  slot, rc);
		rc = rc < 0 ? rc : -EPROTO;
		goto out;
	}
	if (!mxfs_recov_obl_is_open(&rec) || count != rec.count ||
	    (rec.flags & MXFS_RECOV_OBL_F_FSWIDE)) {
		xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-NOTOPEN slot=%u flags=0x%x count=%u/%u — not a completable OPEN case; nothing completed",
			  slot, rec.flags, count, rec.count);
		rc = -EPROTO;
		goto out;
	}
	/*
	 * Feature gate: an EFI on a filesystem with reverse mapping or
	 * reference counting names owner and refcount work this completion
	 * does not perform; mkfs_mxfs never sets those bits, and a volume
	 * that carries them is refused terminally rather than half-completed.
	 */
	if (xfs_has_rmapbt(mp) || xfs_has_reflink(mp)) {
		xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-FEATURE slot=%u rmapbt=%d reflink=%d — this completion is defined for FINOBT-only geometry; publishing a TERMINAL outcome over ag_mask=0x%llx",
			  slot, xfs_has_rmapbt(mp) ? 1 : 0,
			  xfs_has_reflink(mp) ? 1 : 0,
			  (unsigned long long)rec.obl_ag_mask);
		goto terminal;
	}
	/* the list validated against the header's geometry; re-check it
	 * against the MOUNTED geometry, which is the one the frees use */
	for (i = 0; i < count; i++) {
		if (ext[i].agno >= mp->m_sb.sb_agcount || ext[i].len == 0 ||
		    (uint64_t)XFS_FSB_TO_AGBNO(mp, ext[i].fsbno) + ext[i].len >
			    mp->m_sb.sb_agblocks ||
		    XFS_FSB_TO_AGNO(mp, ext[i].fsbno) != ext[i].agno ||
		    (i && (ext[i].agno < ext[i - 1].agno ||
			   (ext[i].agno == ext[i - 1].agno &&
			    XFS_FSB_TO_AGBNO(mp, ext[i].fsbno) <
			    XFS_FSB_TO_AGBNO(mp, ext[i - 1].fsbno) +
			    ext[i - 1].len)))) {
			xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-GEOM slot=%u entry %u fsbno=%llu agno=%u len=%u — outside the mounted geometry or non-canonical; publishing a TERMINAL outcome",
				  slot, i, (unsigned long long)ext[i].fsbno,
				  ext[i].agno, ext[i].len);
			goto terminal;
		}
	}

	xfs_notice(mp,
	"MXFS: P-OBL-ENGINE-START slot=%u count=%u ag_mask=0x%llx seq=%u — completing the dead peer's open EFI extents in live transactions",
		   slot, count, (unsigned long long)rec.obl_ag_mask, rec.pub_seq);
	WRITE_ONCE(mp->m_mxfs_oblf_task, current);

	for (i = 0; i < count; i++) {
		enum xbtree_recpacking	outcome = XBTREE_RECPACKING_SPARSE;
		xfs_agblock_t		agbno = XFS_FSB_TO_AGBNO(mp, ext[i].fsbno);

		if (xfs_is_shutdown(mp)) {
			rc = -EIO;
			goto out_task;
		}
		if (ext[i].agno != cur_agno) {
			if (pag)
				xfs_perag_put(pag);
			pag = xfs_perag_get(mp, ext[i].agno);
			if (!pag) {
				rc = -EFSCORRUPTED;
				goto out_task;
			}
			cur_agno = ext[i].agno;
			/* no ordinary holder may be inside the AG when the
			 * first completion transaction commits (the freeze
			 * keeps new ones out; existing ones drain) */
			rc = mxfs_ag_dlm_quiesce_wait(mp, pag,
						      MXFS_OBL_QUIESCE_MS);
			if (rc) {
				xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-QUIESCE slot=%u agno=%u rc=%d — the AG did not go quiet inside the budget; the case stays OPEN and retries",
					  slot, cur_agno, rc);
				goto out_task;
			}
		}
		rc = mxfs_recov_obl_one(mp, pag, agbno, ext[i].len, &outcome);
		if (rc) {
			xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-EXTENT-FAIL slot=%u entry %u agno=%u agbno=%u len=%u rc=%d",
				  slot, i, cur_agno, agbno, ext[i].len, rc);
			if (rc == -EFSCORRUPTED || rc == -EFSBADCRC)
				goto terminal_task;
			goto out_task;
		}
		if (outcome == XBTREE_RECPACKING_SPARSE) {
			xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-SPARSE slot=%u entry %u agno=%u agbno=%u len=%u — the extent is PARTIALLY free; neither freeing nor skipping is safe; publishing a TERMINAL outcome",
				  slot, i, cur_agno, agbno, ext[i].len);
			goto terminal_task;
		}
		if (outcome == XBTREE_RECPACKING_EMPTY) {
			mxfs_rman_obl_done_set(proof, i);
			n_empty++;
		} else {
			n_full++;
		}
		if (notices++ < MXFS_OBL_NOTICES)
			xfs_notice(mp,
	"MXFS: P-OBL-ENGINE-EXTENT slot=%u entry %u agno=%u agbno=%u len=%u %s",
				   slot, i, cur_agno, agbno, ext[i].len,
				   outcome == XBTREE_RECPACKING_EMPTY ?
					"EMPTY->freed" : "FULL->already-free");
		if (i == 0) {
			int	hold = READ_ONCE(mxfs_dbg_obl_engine_hold_ms);

			if (hold > 0 &&
			    cmpxchg(&mxfs_dbg_obl_engine_hold_ms, hold, 0) == hold) {
				/*
				 * The hold exists so the successor meets a DURABLE
				 * committed free (the FULL branch).  A commit alone
				 * parks in the CIL: measured s614c (tests/evidence/
				 * 20260913T043857Z_intents2tcp_s614c) the custodian
				 * destroyed inside the hold left nothing of entry 0
				 * in its slice and the successor read it EMPTY.  The
				 * engine's own durability point is the log force
				 * below, after every extent; the knob forces here so
				 * the death lands between a durable entry 0 and the
				 * rest, which is the case the takeover must handle.
				 */
				xfs_log_force(mp, XFS_LOG_SYNC);
				xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-HOLD slot=%u entry 0 committed and forced to the log; holding %d ms before entry 1 (TEST: the harness kills this custodian inside the hold)",
					  slot, hold);
				msleep(hold);
			}
		}
	}
	if (pag) {
		xfs_perag_put(pag);
		pag = NULL;
	}

	/*
	 * Home-write before the proof: log force, destage every dirty AG
	 * buffer this node holds (the same primitive the replay path uses
	 * before it publishes), then a durable device flush.  After this the
	 * frees exist on the platter independently of this node's log.
	 */
	xfs_log_force(mp, XFS_LOG_SYNC);
	rc = mxfs_recov_obl_home_flush(mp);
	if (rc) {
		xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-HOMEFLUSH-FAIL slot=%u rc=%d — the completion metadata is not proven home; no proof written, the case stays OPEN and retries",
			  slot, rc);
		goto out_task;
	}

	proof->count = count;
	proof->n_empty = n_empty;
	proof->n_full = n_full;
	proof->n_sparse = 0;
	memcpy(proof->fs_uuid, &mp->m_sb.sb_uuid, sizeof(proof->fs_uuid));
	rc = mxfs_v5_dlm_recovery_obl_done_write(dlm, (int)slot, proof);
	if (rc) {
		xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-PROOF-FAIL slot=%u rc=%d — the completion proof is not durable; the case stays OPEN and retries",
			  slot, rc);
		goto out_task;
	}
	rc = mxfs_v5_dlm_recovery_advance_obl_done(dlm, (int)slot);
	if (rc) {
		xfs_alert(mp,
	"MXFS: P-OBL-ENGINE-DONE-FAIL slot=%u rc=%d — OBLIGATIONS_DONE did not land; the case stays OPEN and retries",
			  slot, rc);
		goto out_task;
	}
	WRITE_ONCE(mp->m_mxfs_oblf_task, NULL);
	mxfs_oblf_note(mp, (int)slot, MXFS_OBL_NONE, 0, 0, 0, 0, false);
	xfs_notice(mp,
	"MXFS: P-OBL-COMPLETE slot=%u count=%u n_empty=%u n_full=%u ag_mask=0x%llx wall_ms=%u — every open EFI obligation of the dead peer is completed, home and proven; OBLIGATIONS_DONE durable, freeze lifted",
		   slot, count, n_empty, n_full,
		   (unsigned long long)rec.obl_ag_mask,
		   jiffies_to_msecs(jiffies - t0));
	rc = 0;
	goto out;

terminal_task:
	WRITE_ONCE(mp->m_mxfs_oblf_task, NULL);
terminal:
	if (pag) {
		xfs_perag_put(pag);
		pag = NULL;
	}
	rc = mxfs_recov_obl_publish_terminal(mp, slot, rec.obl_ag_mask);
	if (rc == 0)
		rc = 1;		/* terminal published: the caller latches it */
	goto out;

out_task:
	WRITE_ONCE(mp->m_mxfs_oblf_task, NULL);
out:
	if (pag)
		xfs_perag_put(pag);
	kfree(proof);
	kvfree(ext);
	return rc;
}
