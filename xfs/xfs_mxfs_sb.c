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
	mxfs_probe("mxfs: P-SB-SUMMARY-PAUSE slot=%u point=%d ms=%d epoch=%llu -- INJECTED: parking inside the SB summary critical section\n",
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
		pr_err("mxfs: P-SB-RECOUNT-HDR-BAD agno=%u %s magic=0x%x -- uncached AG header failed magic/crc; keeping the old counters\n",
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
	uint64_t	(*hdr)[3];	/* per AG: fd total, icount, ifree */
	int		error;

	*ags_read = 0;
	hdr = kcalloc(mp->m_sb.sb_agcount, sizeof(*hdr), GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_buf	*agfbp, *agibp;
		struct xfs_agf	*agf;
		struct xfs_agi	*agi;

		error = mxfs_sb_summary_read_hdr(mp, agno, XFS_AGF_DADDR(mp),
				cpu_to_be32(MXFS_AGF_MAGIC), XFS_AGF_CRC_OFF,
				&agfbp, "AGF");
		if (error)
			goto out_free;
		error = mxfs_sb_summary_read_hdr(mp, agno, XFS_AGI_DADDR(mp),
				cpu_to_be32(MXFS_AGI_MAGIC), XFS_AGI_CRC_OFF,
				&agibp, "AGI");
		if (error) {
			xfs_buf_relse(agfbp);
			goto out_free;
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
			error = -EFSCORRUPTED;
			goto out_free;
		}
		hdr[agno][0] = (uint64_t)be32_to_cpu(agf->agf_freeblks) +
			       be32_to_cpu(agf->agf_flcount) +
			       be32_to_cpu(agf->agf_btreeblks);
		hdr[agno][1] = be32_to_cpu(agi->agi_count);
		hdr[agno][2] = be32_to_cpu(agi->agi_freecount);
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
		pr_err("mxfs: P-SB-RECOUNT-BAD icount=%llu ifree=%llu fdblocks=%llu dblocks=%llu -- uncached AG totals inconsistent; keeping the old counters\n",
			(unsigned long long)ialloc, (unsigned long long)ifree,
			(unsigned long long)fdblocks,
			(unsigned long long)mp->m_sb.sb_dblocks);
		error = -EFSCORRUPTED;
		goto out_free;
	}
	/* the counters are set from these headers: so is what each AG has
	 * folded in */
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag *pag = xfs_perag_get(mp, agno);

		mxfs_pag_cnt_rebase(pag, hdr[agno][0], hdr[agno][1],
				    hdr[agno][2]);
		xfs_perag_put(pag);
	}
	spin_lock(&mp->m_sb_lock);
	mp->m_sb.sb_ifree = ifree;
	mp->m_sb.sb_icount = ialloc;
	mp->m_sb.sb_fdblocks = fdblocks;
	spin_unlock(&mp->m_sb_lock);
	xfs_reinit_percpu_counters(mp);
	error = 0;
out_free:
	kfree(hdr);
	return error;
}

/*
 * A peer's allocations and frees in this node's admission counters.
 *
 * m_free[XC_FREE_BLOCKS], m_icount and m_ifree are set from the AG headers
 * at mount and then moved by this node's own transactions only, so without
 * this a block a peer frees is never free here and a block a peer allocates
 * is still free here.  Measured on a DRBD pair (tests/pve_freespace_drift.sh):
 * one host fallocated 6 GiB, the other removed the file, and the first host
 * was refused ENOSPC on a filesystem that was empty, its df still 6 GB used.
 *
 * Per AG, what this node's counters hold for the AG is its in-core header
 * summary (pagf/pagi, which this node's transactions move together with the
 * counters) plus the pag_mxfs_ext_ terms.  When anything brings that AG's
 * header totals in, the difference is the peer's net change and goes into
 * the counters as a delta:
 *
 *  - a summary rebuilt from the header at a fresh tenure (the peer has held
 *    the AG; mxfs_pag_agf_reinit / mxfs_pag_agi_reinit, which also reset the
 *    ext_ terms the rebuilt summary now contains);
 *  - a header read from the medium while the AG is not this node's
 *    (mxfs_freecount_refresh_statfs), into the ext_ terms.  This node holds
 *    nothing of the AG then: its lineage is closed, which happens only after
 *    the release drain wrote its changes home, and no tenure opened while
 *    the header was read (ag_dlm_tenure_id, checked with the lineage under
 *    pag_dlm_lock, the lock the fresh acquire bumps and opens them under).
 *    A peer's change still in its log is not on the medium yet; the next
 *    read brings it;
 *  - on ENOSPC, the AG taken through its lock (mxfs_freecount_refresh_enospc):
 *    the peer's release writes its changes home first, the summary is rebuilt
 *    at the fresh tenure.  A peer's free that is only in its log is how a
 *    retry that reads the medium alone would still be refused.
 *
 * Two hosts' counters can still both admit the same last free blocks; that
 * is reservation across the cluster, not this.
 */
static void
mxfs_cnt_apply(struct xfs_mount *mp, int64_t d_fd, int64_t d_ic,
	       int64_t d_if)
{
	if (d_fd > 0)
		xfs_add_freecounter(mp, XC_FREE_BLOCKS, d_fd);
	else if (d_fd < 0)
		percpu_counter_add(&mp->m_free[XC_FREE_BLOCKS].count, d_fd);
	if (d_ic)
		percpu_counter_add(&mp->m_icount, d_ic);
	if (d_if)
		percpu_counter_add(&mp->m_ifree, d_if);
	if (d_fd || d_ic || d_if)
		mxfs_probe_ratelimited("mxfs: P-FREECNT-PEER d_fdblocks=%lld d_icount=%lld d_ifree=%lld fdblocks=%lld\n",
			(long long)d_fd, (long long)d_ic, (long long)d_if,
			(long long)percpu_counter_sum(&mp->m_free[XC_FREE_BLOCKS].count));
}

static int32_t
mxfs_agf_rmap_adj(struct xfs_mount *mp, struct xfs_agf *agf)
{
	return xfs_has_rmapbt(mp) ? (int32_t)be32_to_cpu(agf->agf_rmap_blocks) - 1 : 0;
}

/*
 * xfs_alloc_read_agf is about to rebuild the AGF summary from @agf.  The
 * first build of a mount is counted by the mount's own recount; a later one
 * folds the change since the last into the counters, and the AG's share of
 * m_allocbt_blks with it (upstream adds the whole share at every build,
 * which a rebuild per tenure would add again and again).  Returns true when
 * the allocbt share has been accounted here.
 */
bool
mxfs_pag_agf_reinit(struct xfs_perag *pag, struct xfs_agf *agf)
{
	struct xfs_mount	*mp = pag_mount(pag);
	int64_t			newt, oldt, oldbt, newbt;
	int32_t			adj = mxfs_agf_rmap_adj(mp, agf);

	if (!mp->m_mxfs_dlm)
		return false;
	spin_lock(&pag->pag_mxfs_cnt_lock);
	if (!pag->pag_mxfs_agf_based) {
		pag->pag_mxfs_agf_based = true;
		pag->pag_mxfs_ext_fdblocks = 0;
		pag->pag_mxfs_rmap_adj = adj;
		spin_unlock(&pag->pag_mxfs_cnt_lock);
		return false;
	}
	newt = (int64_t)be32_to_cpu(agf->agf_freeblks) +
	       be32_to_cpu(agf->agf_flcount) + be32_to_cpu(agf->agf_btreeblks);
	oldt = (int64_t)pag->pagf_freeblks + pag->pagf_flcount +
	       pag->pagf_btreeblks + pag->pag_mxfs_ext_fdblocks;
	oldbt = max_t(int64_t, 0,
		      (int64_t)pag->pagf_btreeblks - pag->pag_mxfs_rmap_adj);
	newbt = max_t(int64_t, 0,
		      (int64_t)be32_to_cpu(agf->agf_btreeblks) - adj);
	pag->pag_mxfs_ext_fdblocks = 0;
	pag->pag_mxfs_rmap_adj = adj;
	spin_unlock(&pag->pag_mxfs_cnt_lock);

	if (newbt != oldbt)
		atomic64_add(newbt - oldbt, &mp->m_allocbt_blks);
	mxfs_cnt_apply(mp, newt - oldt, 0, 0);
	return true;
}

/* The AGI half of mxfs_pag_agf_reinit. */
void
mxfs_pag_agi_reinit(struct xfs_perag *pag, struct xfs_agi *agi)
{
	struct xfs_mount	*mp = pag_mount(pag);
	int64_t			d_ic, d_if;

	if (!mp->m_mxfs_dlm)
		return;
	spin_lock(&pag->pag_mxfs_cnt_lock);
	if (!pag->pag_mxfs_agi_based) {
		pag->pag_mxfs_agi_based = true;
		pag->pag_mxfs_ext_icount = 0;
		pag->pag_mxfs_ext_ifree = 0;
		spin_unlock(&pag->pag_mxfs_cnt_lock);
		return;
	}
	d_ic = (int64_t)be32_to_cpu(agi->agi_count) -
	       ((int64_t)pag->pagi_count + pag->pag_mxfs_ext_icount);
	d_if = (int64_t)be32_to_cpu(agi->agi_freecount) -
	       ((int64_t)pag->pagi_freecount + pag->pag_mxfs_ext_ifree);
	pag->pag_mxfs_ext_icount = 0;
	pag->pag_mxfs_ext_ifree = 0;
	spin_unlock(&pag->pag_mxfs_cnt_lock);

	mxfs_cnt_apply(mp, 0, d_ic, d_if);
}

/*
 * The counters were just set from these header totals outright: make what
 * the AG has folded in equal them, whatever its in-core summary says.
 */
void
mxfs_pag_cnt_rebase(struct xfs_perag *pag, uint64_t fd_total,
		    uint64_t icount, uint64_t ifree)
{
	spin_lock(&pag->pag_mxfs_cnt_lock);
	pag->pag_mxfs_ext_fdblocks = (int64_t)fd_total -
		((int64_t)pag->pagf_freeblks + pag->pagf_flcount +
		 pag->pagf_btreeblks);
	pag->pag_mxfs_ext_icount = (int64_t)icount - pag->pagi_count;
	pag->pag_mxfs_ext_ifree = (int64_t)ifree - pag->pagi_freecount;
	pag->pag_mxfs_agf_based = true;
	pag->pag_mxfs_agi_based = true;
	spin_unlock(&pag->pag_mxfs_cnt_lock);
}

/*
 * One AG this node does not hold: read its headers from the medium and fold
 * the change since the last fold in.  Returns true when it was folded.
 */
static bool
mxfs_freecount_fold_medium(struct xfs_mount *mp, struct xfs_perag *pag)
{
	struct xfs_buf	*agfbp, *agibp;
	struct xfs_agf	*agf;
	struct xfs_agi	*agi;
	u64		tenure = READ_ONCE(pag->ag_dlm_tenure_id);
	int64_t		d_fd = 0, d_ic = 0, d_if = 0;
	bool		folded = false;

	if (READ_ONCE(pag->pag_dlm_lineage_open) ||
	    !READ_ONCE(pag->pag_mxfs_agf_based) ||
	    !READ_ONCE(pag->pag_mxfs_agi_based))
		return false;
	if (mxfs_sb_summary_read_hdr(mp, pag_agno(pag), XFS_AGF_DADDR(mp),
			cpu_to_be32(MXFS_AGF_MAGIC), XFS_AGF_CRC_OFF,
			&agfbp, "AGF"))
		return false;
	if (mxfs_sb_summary_read_hdr(mp, pag_agno(pag), XFS_AGI_DADDR(mp),
			cpu_to_be32(MXFS_AGI_MAGIC), XFS_AGI_CRC_OFF,
			&agibp, "AGI")) {
		xfs_buf_relse(agfbp);
		return false;
	}
	agf = agfbp->b_addr;
	agi = agibp->b_addr;
	if (be32_to_cpu(agf->agf_seqno) != pag_agno(pag) ||
	    be32_to_cpu(agi->agi_seqno) != pag_agno(pag))
		goto out;

	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	if (!pag->pag_dlm_lineage_open && pag->pag_dlm_holders == 0 &&
	    pag->ag_dlm_tenure_id == tenure) {
		spin_lock(&pag->pag_mxfs_cnt_lock);
		d_fd = ((int64_t)be32_to_cpu(agf->agf_freeblks) +
			be32_to_cpu(agf->agf_flcount) +
			be32_to_cpu(agf->agf_btreeblks)) -
		       ((int64_t)pag->pagf_freeblks + pag->pagf_flcount +
			pag->pagf_btreeblks + pag->pag_mxfs_ext_fdblocks);
		d_ic = (int64_t)be32_to_cpu(agi->agi_count) -
		       ((int64_t)pag->pagi_count + pag->pag_mxfs_ext_icount);
		d_if = (int64_t)be32_to_cpu(agi->agi_freecount) -
		       ((int64_t)pag->pagi_freecount + pag->pag_mxfs_ext_ifree);
		pag->pag_mxfs_ext_fdblocks += d_fd;
		pag->pag_mxfs_ext_icount += d_ic;
		pag->pag_mxfs_ext_ifree += d_if;
		spin_unlock(&pag->pag_mxfs_cnt_lock);
		folded = true;
	}
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);
	if (folded)
		mxfs_cnt_apply(mp, d_fd, d_ic, d_if);
out:
	xfs_buf_relse(agibp);
	xfs_buf_relse(agfbp);
	return folded;
}

static bool
mxfs_freecount_cluster(struct xfs_mount *mp)
{
	return mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm);
}

/*
 * statfs: the AGs this node does not hold, from the medium, at most once a
 * second, in a work item.  statfs itself answers from the counters at once:
 * under load the header reads queue behind the guests' writes (measured on
 * the physical pair: pvestatd sampled in D in the read), and upstream's
 * statfs waits on no I/O.  What the read folds in shows at the next statfs.
 */
void
mxfs_freecount_refresh_statfs(struct xfs_mount *mp)
{
	u64			now = ktime_get_ns();
	u64			last = READ_ONCE(mp->m_mxfs_cnt_statfs_ns);

	if (!mxfs_freecount_cluster(mp))
		return;
	if (last && now - last < NSEC_PER_SEC)
		return;
	if (cmpxchg(&mp->m_mxfs_cnt_statfs_ns, last, now) != last)
		return;		/* another statfs is queueing it */
	queue_work(system_unbound_wq, &mp->m_mxfs_cnt_statfs_work);
}

void
mxfs_freecount_statfs_work_fn(struct work_struct *work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_cnt_statfs_work);
	struct xfs_perag	*pag = NULL;

	if (xfs_is_shutdown(mp) || !mxfs_freecount_cluster(mp))
		return;
	while ((pag = xfs_perag_next(mp, pag)))
		mxfs_freecount_fold_medium(mp, pag);
}

/*
 * ENOSPC retry: every AG this node does not hold, through its lock, so a
 * peer's free still in its log is written home and counted.  The bounded
 * acquire demands the peer's release and gives up on an AG after ~4 s
 * rather than wait on it with whatever the caller holds; such an AG is read
 * from the medium instead.  One sweep at a time, and none within a second
 * of the last: the counters it leaves are that fresh.  Never inside a
 * transaction, never re-entered from the sweep itself.
 */
void
mxfs_freecount_refresh_enospc(struct xfs_mount *mp)
{
	struct xfs_perag	*pag = NULL;
	unsigned int		taken = 0, medium = 0, busy = 0;
	u64			t0 = ktime_get_ns();

	if (!mxfs_freecount_cluster(mp) || current->journal_info ||
	    READ_ONCE(mp->m_mxfs_cnt_sweep_owner) == current)
		return;
	if (!mutex_trylock(&mp->m_mxfs_cnt_sweep_mutex)) {
		/* someone is sweeping: wait for it, its result is ours */
		if (mutex_lock_killable(&mp->m_mxfs_cnt_sweep_mutex))
			return;
		mutex_unlock(&mp->m_mxfs_cnt_sweep_mutex);
		return;
	}
	if (mp->m_mxfs_cnt_sweep_ns &&
	    t0 - mp->m_mxfs_cnt_sweep_ns < NSEC_PER_SEC)
		goto out;
	WRITE_ONCE(mp->m_mxfs_cnt_sweep_owner, current);
	while ((pag = xfs_perag_next(mp, pag))) {
		struct xfs_buf	*bp;

		if (READ_ONCE(pag->pag_dlm_lineage_open))
			continue;	/* this node's: its summary is current */
		if (mxfs_ag_dlm_lock_bounded(mp, pag)) {
			busy++;
			if (mxfs_freecount_fold_medium(mp, pag))
				medium++;
			continue;
		}
		if (!xfs_alloc_read_agf(pag, NULL, 0, &bp))
			xfs_buf_relse(bp);
		if (!xfs_ialloc_read_agi(pag, NULL, 0, &bp))
			xfs_buf_relse(bp);
		mxfs_ag_dlm_unlock(mp, pag);
		taken++;
	}
	WRITE_ONCE(mp->m_mxfs_cnt_sweep_owner, NULL);
	mp->m_mxfs_cnt_sweep_ns = ktime_get_ns();
	mxfs_probe("mxfs: P-FREECNT-ENOSPC-SWEEP taken=%u busy=%u medium=%u ms=%llu fdblocks=%lld comm=%s\n",
		taken, busy, medium,
		(unsigned long long)((mp->m_mxfs_cnt_sweep_ns - t0) / NSEC_PER_MSEC),
		(long long)percpu_counter_sum(&mp->m_free[XC_FREE_BLOCKS].count),
		current->comm);
out:
	mutex_unlock(&mp->m_mxfs_cnt_sweep_mutex);
}
