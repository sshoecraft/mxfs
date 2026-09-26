// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- superblock summary counters under the cluster summary lock
 */
#define MXFS_TU_ID 9	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * (D-0133 design-consult instrumentation): the DURABLE superblock summary
 * counters, sampled at the cluster's coherence point (mxfs_dbg_coherent_read),
 * for the P-SB-SYNC-PRE/-POST lines around a node's quiesce recompute+cover.
 * One 512-byte sector read of the primary SB (the counters sit in its first
 * 0xa0 bytes); never the cached m_sb_bp.
 */
int
mxfs_sb_read_counters_coherent(struct xfs_mount *mp, uint64_t *icount,
			       uint64_t *ifree, uint64_t *fdblocks)
{
	struct xfs_dsb	*dsb;
	int		error;

	if (!mp->m_ddev_targp)
		return -ENODEV;
	dsb = kzalloc(512, GFP_KERNEL);
	if (!dsb)
		return -ENOMEM;
	error = mxfs_dbg_coherent_read(mp,
			(uint64_t)mp->m_ddev_targp->bt_sector_offset + XFS_SB_DADDR,
			dsb, 512);
	if (!error) {
		*icount = be64_to_cpu(dsb->sb_icount);
		*ifree = be64_to_cpu(dsb->sb_ifree);
		*fdblocks = be64_to_cpu(dsb->sb_fdblocks);
	}
	kfree(dsb);
	return error;
}

/*
 * (D-0133 counter arm, design-consult design A+).  The durable SB summary
 * counters after a FULL clean unmount must equal the AG totals (chk).  Each
 * node's quiesce recomputed them from its OWN buffer cache — stale for every
 * AG it never acquired (chain 116 s474c: the 30 idle nodes summed the
 * mount-time AGI images to 64/61 and three of them wrote that over the
 * workers' durable 128/125; the per-AG summary and the cached buffer agreed,
 * so nothing was refreshed) — and the 32 parallel unmounts raced their
 * whole-sector SB writes.  Now the quiesce path:
 *   (1) has already emptied its own AIL (local AG headers durable);
 *   (2) takes a dedicated cluster EX lock on a geometry-reserved
 *       unallocatable key (slot 65 — beyond every per-node pw-selftest key
 *       and the shared samenode key at 64) so recompute + cover + SB home
 *       write + flush form ONE critical section cluster-wide;
 *   (3) reads every AGF/AGI UNCACHED at the coherence point (a plain bio to
 *       the target's coherent cache, never the stale xfs_buf; the verifiers'
 *       checks re-done by hand because uncached buffers carry no b_pag);
 *   (4) sums into m_sb; the caller covers, flushes, re-reads the durable
 *       sector (P-SB-SYNC-POST) and only then unlocks.
 * The last serialized writer is the last node out and its sums are terminal.
 * Lock order: nothing (no inode/AG grant is held by the quiesce task).
 */
uint64_t
mxfs_sb_summary_key(struct xfs_mount *mp)
{
	return ((uint64_t)(mp->m_sb.sb_agcount + 1 + 65)
		<< (mp->m_sb.sb_agblklog + mp->m_sb.sb_inopblog)) | 1;
}

/*
 * (D-0487): "is this INODE-class resource id EXACTLY the SB summary
 * key?"  The closure classifier needs the exact identity, never a generic
 * "decodes above the AG space" rule: every other out-of-range key stays
 * frozen.
 */
bool
mxfs_sb_summary_key_is(struct xfs_mount *mp, uint64_t ino)
{
	return ino == mxfs_sb_summary_key(mp);
}

/*
 * 0.89.69 (D-A-STALLED-PAGE-TRANSITION-IS-AN-UNBOUNDED-WAIT-FOR-A-NON-
 * FALLIBLE-CALLER): the summary lock is a FALLIBLE boundary and registers
 * as one.  Every caller — put_super's final sync, the freeze cover, the
 * runtime cover — already fails closed on a nonzero return (no cover, no
 * unlocked SB write; put_super's departure is DIRTY and peers recover the
 * slice), and nothing is dirty at the acquire: no transaction is open and
 * the caller's own AIL is already empty.  Unregistered, the acquire was
 * permanently non-fallible, so a page transition the engine had already
 * detected as stalled (P960-AUTH-TRANSITION-STALLED fallible=0) reset its
 * clock and waited again without end — a survivor whose summary page was
 * authored by a dead incarnation under an open judgement could not unmount
 * (the 0.89.43 measurement: SIGKILLed at 70 s, twice).  Now the same stall
 * ends the acquire with -EREMCHG and the caller takes the path it already
 * had for a lock it could not get.
 */
int
mxfs_sb_summary_lock(struct xfs_mount *mp, uint64_t *epoch)
{
	struct mxfs_grant_result gres;
	int rc;

	if (epoch)
		*epoch = 0;
	if (!mp->m_mxfs_dlm)
		return -ENODEV;
	rc = mxfs_sb_summary_lock_fallible(mp, mxfs_sb_summary_key(mp), &gres);
	if (!rc && epoch)
		*epoch = gres.grant_epoch;
	return rc;
}

/*
 * 0.89.66: does THIS node master the summary key's ledger page?  1 yes, 0 no,
 * -1 no TCP DLM.  Printed beside every P-SB-SUMMARY-LOCK line.  Mastership is
 * page-aligned over the sorted active view, so which node masters the summary
 * page is decided by the node ids drawn at mount and cannot be arranged from
 * outside; and a dead member keeps its pages until its recovery completes.  A
 * lap that needs the page's master ALIVE while its durable authority is a dead
 * incarnation under judgement (tests/nonfallible_transition_stall.sh) chooses
 * its victim by reading this rather than guessing — s130c/s133d guessed, and
 * measured a transport refusal and a refused remount instead of the wait.
 */
int
mxfs_sb_summary_master_self(struct xfs_mount *mp)
{
	if (!mp->m_mxfs_dlm)
		return -1;
	return mxfs_v5_dlm_inode_master_self(mp->m_mxfs_dlm,
					     mxfs_sb_summary_key(mp));
}

/*
 * debug knobs for the D-0133 verification arms (all default-off,
 * one-shot where they inject; never enable in production):
 *   dbg_sb_pause_point=N (one-shot) + dbg_sb_pause_ms (sticky, default
 *     5000): the summary critical section parks for the hold at point N
 *     (1 after the lock before the recount, 2 after the recount before the
 *     cover, 3 after the cover before the flush/POST, 4 after POST before
 *     the unlock) printing P-SB-SUMMARY-PAUSE, so a peer's concurrent unmount
 *     can be shown to WAIT (its LOCK epoch must be ours + 1 and it must not
 *     print PRE/WRITE/POST until our UNLOCK), and so the VM can be destroyed
 *     inside the section for the holder-failure arm.  The hold is sliced so
 *     the task is never parked in D state for more than 100 ms at a time.
 *   dbg_sb_late_dirty=1 (one-shot): put_super logs the root inode core AFTER
 *     the SB summary seal — the invariant-violation arm.  The later quiesce
 *     must refuse the clean departure (P-SB-LATE-DIRTY-COVER, no unmount
 *     record, slot retained), never write the SB unlocked.
 */
static int mxfs_dbg_sb_pause_point;
module_param_named(dbg_sb_pause_point, mxfs_dbg_sb_pause_point, int, 0644);
MODULE_PARM_DESC(dbg_sb_pause_point,
	"DEBUG one-shot: park the SB summary critical section at point 1-4 for dbg_sb_pause_ms (D-0133 adversarial/holder-failure arms)");
static int mxfs_dbg_sb_pause_ms = 5000;
module_param_named(dbg_sb_pause_ms, mxfs_dbg_sb_pause_ms, int, 0644);
MODULE_PARM_DESC(dbg_sb_pause_ms, "DEBUG: hold length for dbg_sb_pause_point (ms)");

void
mxfs_sb_summary_pause(struct xfs_mount *mp, int point)
{
	int ms, left;

	if (likely(READ_ONCE(mxfs_dbg_sb_pause_point) != point))
		return;
	if (xchg(&mxfs_dbg_sb_pause_point, 0) != point)
		return;
	ms = READ_ONCE(mxfs_dbg_sb_pause_ms);
	mxfs_probe("mxfs: P-SB-SUMMARY-PAUSE slot=%u point=%d ms=%d epoch=%llu — INJECTED: parking inside the SB summary critical section\n",
		mp->m_mxfs_node_slot, point, ms,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch);
	for (left = ms; left > 0; left -= 100)
		msleep(left > 100 ? 100 : left);
	mxfs_probe("mxfs: P-SB-SUMMARY-PAUSE-END slot=%u point=%d epoch=%llu\n",
		mp->m_mxfs_node_slot, point,
		(unsigned long long)mp->m_mxfs_sb_grant_epoch);
}

void
mxfs_sb_summary_unlock(struct xfs_mount *mp)
{
	if (mp->m_mxfs_dlm)
		mxfs_v5_dlm_inode_unlock(mp->m_mxfs_dlm, mxfs_sb_summary_key(mp));
}

static int
mxfs_sb_summary_read_hdr(struct xfs_mount *mp, xfs_agnumber_t agno,
			 xfs_daddr_t agdaddr, __be32 want_magic, u32 crc_off,
			 struct xfs_buf **bpp, const char *what)
{
	struct xfs_buf	*bp = NULL;
	__be32		*magicp;
	int		error;

	error = xfs_buf_read_uncached(mp->m_ddev_targp,
				      XFS_AG_DADDR(mp, agno, agdaddr),
				      XFS_FSS_TO_BB(mp, 1), &bp, NULL);
	if (error)
		return error;
	magicp = bp->b_addr;
	if (*magicp != want_magic ||
	    (xfs_has_crc(mp) &&
	     !xfs_verify_cksum(bp->b_addr, BBTOB(bp->b_length), crc_off))) {
		pr_err("mxfs: P-SB-RECOUNT-HDR-BAD agno=%u %s magic=0x%x — uncached AG header failed magic/crc; keeping the old counters\n",
			agno, what, be32_to_cpu(*magicp));
		xfs_buf_relse(bp);
		return -EFSCORRUPTED;
	}
	*bpp = bp;
	return 0;
}

int
mxfs_sb_summary_recount_uncached(struct xfs_mount *mp, unsigned int *ags_read)
{
	xfs_agnumber_t	agno;
	uint64_t	ifree = 0, ialloc = 0, bfree = 0, bfreelst = 0, btree = 0;
	uint64_t	fdblocks;
	int		error;

	*ags_read = 0;
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_buf	*agfbp, *agibp;
		struct xfs_agf	*agf;
		struct xfs_agi	*agi;

		error = mxfs_sb_summary_read_hdr(mp, agno, XFS_AGF_DADDR(mp),
				cpu_to_be32(MXFS_AGF_MAGIC), XFS_AGF_CRC_OFF,
				&agfbp, "AGF");
		if (error)
			return error;
		error = mxfs_sb_summary_read_hdr(mp, agno, XFS_AGI_DADDR(mp),
				cpu_to_be32(MXFS_AGI_MAGIC), XFS_AGI_CRC_OFF,
				&agibp, "AGI");
		if (error) {
			xfs_buf_relse(agfbp);
			return error;
		}
		agf = agfbp->b_addr;
		agi = agibp->b_addr;
		if (be32_to_cpu(agf->agf_seqno) != agno ||
		    be32_to_cpu(agi->agi_seqno) != agno) {
			pr_err("mxfs: P-SB-RECOUNT-HDR-BAD agno=%u seqno agf=%u agi=%u\n",
				agno, be32_to_cpu(agf->agf_seqno),
				be32_to_cpu(agi->agi_seqno));
			xfs_buf_relse(agibp);
			xfs_buf_relse(agfbp);
			return -EFSCORRUPTED;
		}
		ifree += be32_to_cpu(agi->agi_freecount);
		ialloc += be32_to_cpu(agi->agi_count);
		bfree += be32_to_cpu(agf->agf_freeblks);
		bfreelst += be32_to_cpu(agf->agf_flcount);
		btree += be32_to_cpu(agf->agf_btreeblks);
		xfs_buf_relse(agibp);
		xfs_buf_relse(agfbp);
		(*ags_read)++;
	}
	fdblocks = bfree + bfreelst + btree;
	if (fdblocks > mp->m_sb.sb_dblocks || ifree > ialloc) {
		pr_err("mxfs: P-SB-RECOUNT-BAD icount=%llu ifree=%llu fdblocks=%llu dblocks=%llu — uncached AG totals inconsistent; keeping the old counters\n",
			(unsigned long long)ialloc, (unsigned long long)ifree,
			(unsigned long long)fdblocks,
			(unsigned long long)mp->m_sb.sb_dblocks);
		return -EFSCORRUPTED;
	}
	spin_lock(&mp->m_sb_lock);
	mp->m_sb.sb_ifree = ifree;
	mp->m_sb.sb_icount = ialloc;
	mp->m_sb.sb_fdblocks = fdblocks;
	spin_unlock(&mp->m_sb_lock);
	xfs_reinit_percpu_counters(mp);
	return 0;
}
