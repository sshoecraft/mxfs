// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- AG metadata handoff, publication writes and stale-buffer invalidation
 */
#define MXFS_TU_ID 25	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
/*
 * (design-consult ruling ag-handoff-latch-
 * closing-restartable): the armed handoff latch — see pag_dlm_latched in
 * xfs_ag.h and mxfs_ag_handoff_commit below.  Replaces the
 * admission-window knob (ag_readopt_window_ms): arm 3 of that (blocking
 * acquirers waited at the gate) wedged two nodes, arm 4 (nonblock refused,
 * blocking re-adopted PINNED) livelocked at 1.5-2.2 M refusals per lap; both
 * measured at 25 AGs.  Both gated ADMISSION while the worker still had to win
 * a race to COMMIT; the latch makes the COMMIT itself the admission decision.
 *
 *   ag_handoff_latch      1 = on.  0 = legacy (worker-only COMMIT), for A/B.
 *   ag_handoff_grace_ms   local re-adoptions are admitted for this long after
 *                         the peer's BAST before the latch arms (ruling: 0 to
 *                         validate immediate closing, then 20-25 ms).
 *   ag_handoff_admit_cap  or after this many post-BAST re-adoptions
 *                         (whichever first; 0 = no count cap; ruling: 8).
 */
int mxfs_ag_handoff_latch = 1;
module_param_named(ag_handoff_latch, mxfs_ag_handoff_latch, int, 0644);
MODULE_PARM_DESC(ag_handoff_latch,
	"commit a pending AG handoff at the first holders==0 after the worker prepass + grace (1=on, 0=legacy worker-only COMMIT)");
int mxfs_ag_handoff_grace_ms = 0;
module_param_named(ag_handoff_grace_ms, mxfs_ag_handoff_grace_ms, int, 0644);
MODULE_PARM_DESC(ag_handoff_grace_ms,
	"local re-adoptions admitted for this many ms after a peer's AG BAST before the handoff latch arms (default 0 = immediate)");
int mxfs_ag_handoff_admit_cap = 0;
module_param_named(ag_handoff_admit_cap, mxfs_ag_handoff_admit_cap, int, 0644);
MODULE_PARM_DESC(ag_handoff_admit_cap,
	"the handoff latch also arms after this many post-BAST local re-adoptions (0 = no count cap)");

/* ─── AG allocation locks ─── */

/*
 * Wait while the AG is in the brief drain+unlock demote window.
 * Caller holds pag_dlm_lock; this drops it across schedule() and
 * retakes it before returning.  Returns with pag_dlm_lock held and
 * pag_dlm_demoting cleared.  After waking, the caller MUST re-check
 * cached/release_pending/holders state — the demote may have raced
 * with another thread that re-acquired between unlock and wake.
 */
void
mxfs_ag_dlm_wait_demote(
	struct xfs_perag	*pag)
{
	u64			t0 = 0;
	bool			waited = false;
	bool			had_trans = false, had_dirty = false;

	while (pag->pag_dlm_demoting) {
		DEFINE_WAIT(wait);

		if (!waited) {
			struct xfs_trans *wtp = current->journal_info;

			waited = true;
			t0 = ktime_get_ns();
			atomic64_inc(&mxfs_dlm_stat_demote_wait_n);
			if (wtp) {
				had_trans = true;
				atomic64_inc(&mxfs_dlm_stat_demote_wait_trans);
				if (wtp->t_flags & XFS_TRANS_DIRTY) {
					had_dirty = true;
					atomic64_inc(&mxfs_dlm_stat_demote_wait_dirty);
				}
			}
			/*
			 * publish the sleep as an in-flight AG wait so
			 * the convoy-aware no-inode release fence attributes a
			 * frozen AIL item owned by this sleeper to the handoff
			 * instead of charging it as a wedge — the same class as
			 * the blocking CAW wait in __mxfs_ag_dlm_lock (the
			 * sleeper may hold an ILOCK on a dirty inode in this AG).
			 */
			if (atomic_inc_return(&pag->pag_mxfs_agwait_inflight) == 1)
				WRITE_ONCE(pag->pag_mxfs_agwait_since_ns, t0);
		}
		prepare_to_wait(&pag->pag_dlm_demote_wq, &wait,
				TASK_UNINTERRUPTIBLE);
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		schedule();
		finish_wait(&pag->pag_dlm_demote_wq, &wait);
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
	}
	if (waited) {
		s64 ms = (s64)((ktime_get_ns() - t0) / NSEC_PER_MSEC);

		if (atomic_dec_return(&pag->pag_mxfs_agwait_inflight) == 0)
			WRITE_ONCE(pag->pag_mxfs_agwait_since_ns, 0);
		atomic64_add(ms, &mxfs_dlm_stat_demote_wait_ms);
		mxfs_stat_max64(&mxfs_dlm_stat_demote_wait_max, ms);
		if (ms >= 2000)
			mxfs_probe_ratelimited("mxfs: P12-DEMOTE-WAIT-LONG ag=%u comm=%s pid=%d ms=%lld trans=%d dirty=%d — blocking acquirer slept through a local AG handoff\n",
				pag_agno(pag), current->comm, current->pid,
				(long long)ms, had_trans ? 1 : 0,
				had_dirty ? 1 : 0);
	}
}

/*
 * handoff latch (design-consult ruling
 * ag-handoff-latch-closing-restartable).  Both helpers run under pag_dlm_lock.
 *
 * mxfs_ag_handoff_closing: is local admission closed for this BAST
 * generation?  True once the worker's prepass has run (the publish pass does
 * writeback that must acquire THIS AG — it can only run while admission is
 * open) and either the grace since the BAST is spent or the post-BAST
 * re-adoption count hit the cap.
 *
 * mxfs_ag_handoff_commit: THE release COMMIT — the single point that detaches
 * the cached grant and invalidates in-core authority (step 5.1:
 * epoch/lineage zeroed in the same critical section that publishes the
 * decision).  Formerly reachable only from the worker's Phase 2; now also
 * taken at the last-holder unlock and by a would-be re-adopter, which closes
 * the worker/re-adopter race at the root (the worker lost it ~2 M times per
 * lap at 25 AGs).  Preconditions: holders==0, cached, !demoting.  The caller
 * queues the worker (idempotent) unless it IS the worker; the worker's
 * pag_dlm_latched check then jumps straight to the post-COMMIT drains.
 */
bool
mxfs_ag_handoff_closing(
	struct xfs_perag	*pag)
{
	if (!mxfs_ag_handoff_latch || !pag->pag_dlm_bast_pending ||
	    !pag->pag_dlm_prepass_done)
		return false;
	if (mxfs_ag_handoff_admit_cap > 0 &&
	    pag->pag_dlm_readopt_n >= (u32)mxfs_ag_handoff_admit_cap)
		return true;
	return jiffies_to_msecs(jiffies - pag->pag_dlm_bast_pending_since) >=
	       (unsigned int)max(mxfs_ag_handoff_grace_ms, 0);
}

/*
 * 0.75.55 AG release stage split (instrument): how many of this AG's cached
 * buffers are still pinned (their commit not yet checkpointed and inserted
 * into the AIL) and how many carry a log item in the AIL.  Read at two
 * points of the post-COMMIT drain to say whether the empirical sleeps
 * between the log forces are waiting for anything.  Walk only; no locks
 * taken on the buffers.
 */
void
mxfs_ag_bcache_pin_census(
	struct xfs_perag	*pag,
	unsigned int		*pinned,
	unsigned int		*inail)
{
	struct rhashtable_iter	it;
	struct xfs_buf		*bp;

	*pinned = 0;
	*inail = 0;
	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &it);
	do {
		rhashtable_walk_start(&it);
		while ((bp = rhashtable_walk_next(&it))) {
			struct xfs_buf_log_item *bip;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (xfs_buf_ispinned(bp))
				(*pinned)++;
			bip = bp->b_log_item;
			if (bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))
				(*inail)++;
		}
		rhashtable_walk_stop(&it);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&it);
}

/*
 * (D-0351): the publication-write gate around pag_mxfs_grant_epoch.
 * A FREE-obligation copy-in (xfs_iflush P55C) may write the free dinode
 * image only inside the SAME uninterrupted AG EX tenure the ifree committed
 * under, and only if it is guaranteed to be visible to that tenure's release
 * drain.  begin() takes a count and re-checks the epoch under it; the release
 * commit zeroes the epoch and then waits for the count to reach zero before
 * its drain.  Bounded: the copy-in holds the count only across the dinode
 * copy (microseconds, buffer locked).
 */
bool mxfs_ag_pubwrite_begin(struct xfs_perag *pag, uint64_t epoch)
{
	if (!epoch || READ_ONCE(pag->pag_mxfs_grant_epoch) != epoch)
		return false;
	atomic_inc(&pag->pag_mxfs_pubwrite);
	smp_mb__after_atomic();
	if (READ_ONCE(pag->pag_mxfs_grant_epoch) != epoch) {
		atomic_dec(&pag->pag_mxfs_pubwrite);
		return false;
	}
	return true;
}

void mxfs_ag_pubwrite_end(struct xfs_perag *pag)
{
	smp_mb__before_atomic();
	atomic_dec(&pag->pag_mxfs_pubwrite);
}

/*
 * (D-0351, design-consult ruling "mint an explicit per-slot FREE-publication
 * claim; never infer authority from in-core state").  The P55C copy-in
 * stamps the claim; the cluster merge and the partial-write mask consult it
 * through here.  Every field must still hold: a rolled-back flush_seq, a
 * different buffer instance, a re-used inode object, an overlaid image or a
 * moved AG tenure all invalidate it.  The AG check accepts the live grant
 * epoch, or the retiring token (pag_mxfs_rel_epoch) while the release audit's
 * drain is running — the two sanctions P55C itself accepts.
 */
bool mxfs_freepub_claim_valid(struct xfs_inode *ip, struct xfs_buf *bp,
			      struct xfs_perag *pag,
			      const struct xfs_dinode *img, const char **why)
{
	uint64_t ce = READ_ONCE(ip->i_mxfs_freepub_epoch);
	const char *w;

	if (!ce) {
		w = "none";
		goto fail;
	}
	if (READ_ONCE(ip->i_mxfs_freepub_bp) != (void *)bp) {
		w = "buffer";
		goto fail;
	}
	if (READ_ONCE(ip->i_mxfs_pub_flush_seq) !=
	    READ_ONCE(ip->i_mxfs_freepub_seq)) {
		w = "flush_seq";
		goto fail;
	}
	if (READ_ONCE(ip->i_mxfs_freeob) != 2 ||
	    !xfs_iflags_test(ip, MXFS_IF_PUBOB)) {
		w = "obligation";
		goto fail;
	}
	if (!img || be16_to_cpu(img->di_magic) != XFS_DINODE_MAGIC ||
	    img->di_mode != 0 ||
	    be32_to_cpu(img->di_gen) != READ_ONCE(ip->i_mxfs_freepub_gen)) {
		w = "image";
		goto fail;
	}
	if (pag) {
		uint64_t cur = READ_ONCE(pag->pag_mxfs_grant_epoch);
		uint64_t rel = READ_ONCE(pag->pag_mxfs_rel_epoch);

		if (ce != cur &&
		    !(READ_ONCE(pag->pag_dlm_demoting) && ce == rel)) {
			w = "ag_epoch";
			goto fail;
		}
	}
	if (why)
		*why = "ok";
	return true;
fail:
	if (why)
		*why = w;
	return false;
}
EXPORT_SYMBOL(mxfs_freepub_claim_valid);

void mxfs_freepub_claim_clear(struct xfs_inode *ip, const char *why)
{
	static atomic_t n = ATOMIC_INIT(0);

	if (!READ_ONCE(ip->i_mxfs_freepub_epoch))
		return;
	if (atomic_inc_return(&n) <= 2000)
		mxfs_probe("mxfs: P-FREEPUB-CLAIM-CLEAR ino=%llu gen=%u epoch=%llu seq=%llu why=%s\n",
			(unsigned long long)ip->i_ino, ip->i_mxfs_freepub_gen,
			(unsigned long long)ip->i_mxfs_freepub_epoch,
			(unsigned long long)ip->i_mxfs_freepub_seq, why);
	WRITE_ONCE(ip->i_mxfs_freepub_epoch, 0);
	WRITE_ONCE(ip->i_mxfs_freepub_bp, NULL);
	WRITE_ONCE(ip->i_mxfs_freepub_seq, 0);
	WRITE_ONCE(ip->i_mxfs_freepub_gen, 0);
}
EXPORT_SYMBOL(mxfs_freepub_claim_clear);

static void
mxfs_ag_pubwrite_quiesce(struct xfs_perag *pag)
{
	int spins = 0;

	smp_mb();
	while (atomic_read(&pag->pag_mxfs_pubwrite) > 0) {
		if (++spins > 20000) {	/* ~2 s: a copy-in cannot take this long */
			pr_warn("mxfs: P-FREEOB-GATE-STUCK ag=%u writers=%d — publication-write gate did not drain before the release drain\n",
				pag_agno(pag),
				atomic_read(&pag->pag_mxfs_pubwrite));
			break;
		}
		usleep_range(50, 100);
	}
}

void
mxfs_ag_handoff_commit(
	struct xfs_perag	*pag,
	const char		*who,
	atomic64_t		*stat)
{
	WARN_ON_ONCE(pag->pag_dlm_holders != 0 || pag->pag_dlm_demoting);
	pag->pag_dlm_cached = false;
	pag->pag_dlm_bast_pending = false;
	/* Latched so a lost worker is re-queued by the rx watchdog
	 * (P275-AG-STUCK-LATCH); cleared with demoting at completion. */
	pag->pag_dlm_bast_scheduled = true;
	/* a strand marker cannot outlive a release COMMIT. */
	pag->pag_dlm_readopt_pending = false;
	pag->pag_dlm_prepass_done = false;
	pag->pag_dlm_demoting = true;
	pag->pag_dlm_latched = true;
	pag->pag_dlm_latch_ns = ktime_get_ns();
	/* remember the detached tenure's identity for the
	 * clean-release marker the worker publishes after its drain —
	 * same critical section as the invalidation, so the saved pair is
	 * exactly the one the tokens of this tenure carry. */
	pag->pag_mxfs_rel_epoch = READ_ONCE(pag->pag_mxfs_grant_epoch);
	pag->pag_mxfs_rel_lineage = READ_ONCE(pag->pag_mxfs_grant_lineage);
	WRITE_ONCE(pag->pag_mxfs_grant_epoch, 0);
	WRITE_ONCE(pag->pag_mxfs_grant_lineage, 0);
	pag->pag_mxfs_grant_single = false;	/* (D-0353) */
	/* (D-0351): no FREE-obligation copy-in that validated against
	 * the epoch just zeroed may still be between its check and its
	 * attach — the worker's drain must see every sanctioned image. */
	mxfs_ag_pubwrite_quiesce(pag);
	if (stat)
		atomic64_inc(stat);
	if (who)
		mxfs_probe_ratelimited("mxfs: P12-LATCH ag=%u by=%s readopt=%u page_ms=%u comm=%s\n",
			pag_agno(pag), who, pag->pag_dlm_readopt_n,
			jiffies_to_msecs(jiffies -
				pag->pag_dlm_bast_pending_since),
			current->comm);
}

/*
 * Acquire per-AG DLM EX lock with node-local holder counting.
 * Multiple threads on the same node share one DLM lock grant;
 * XFS's existing AGF/AGI buffer locks serialize local threads.
 *
 * Holder counting handles nesting: inode allocation acquires
 * the AG lock, then calls block allocation within the same AG
 * which also tries to acquire — the nested call increments
 * the counter without DLM I/O.
 */

/*
 * ROOT FIX (confirmed P90-FUA-OVER-LOGGED, FIRED 7× on the
 * shutdown node): does this buffer carry a LOGGED-but-not-yet-checkpointed
 * modification that lives ONLY in core?  If so, clearing XBF_DONE +
 * FUA/bio-re-reading the on-disk image would DMA-clobber that uncheckpointed
 * change with stale disk content = the lost-update family (inode-cluster
 * di_size→0, bnobt lost-removal → block double-alloc → double-free shutdown).
 *
 * A buffer is authoritative-in-core when ANY of:
 *   - it is pinned (a CIL commit referencing it is in flight), or
 *   - it has log items attached (b_log_item or a non-empty b_li_list — a BLI
 *     whose transaction modified it), or
 *   - that BLI is DIRTY or IN_AIL (committed, not yet written back), or
 *   - it is delwri-queued (about to be written back from core).
 * In every one of these states the in-core image is ahead of (or equal to)
 * disk and MUST NOT be overwritten by a re-read.  Mirrors the protection the
 * AG-meta invalidation path has carried since /; this helper just
 * makes it reusable for the inode-cluster invalidation paths (xfs_icache.c),
 * which previously staled unconditionally and were the proven clobber site.
 */
bool
mxfs_buf_has_uncheckpointed_mods(struct xfs_buf *bp)
{
	struct xfs_buf_log_item	*bip;

	if (!bp)
		return false;
	if (xfs_buf_ispinned(bp))
		return true;
	if (!list_empty(&bp->b_li_list))
		return true;
	bip = bp->b_log_item;
	if (bip) {
		if (test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags) ||
		    test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))
			return true;
		/* BLI attached at all → a transaction touched this buffer */
		return true;
	}
	if (bp->b_flags & _XBF_DELWRI_Q)
		return true;
	return false;
}

/*
 * (design review design-consult design — VERIFIED against kernel
 * source xfs_btree.c:454 xfs_btree_agblock_calc_crc):  Does this AG-meta
 * buffer carry modifications that have NOT yet been written to disk (i.e. the
 * in-core image is strictly AHEAD of the on-disk image)?
 *
 * This resolves the (P110)/(P117) CONTRADICTION.  Both fired on
 * the SAME in-AIL bnobt/cntbt buffer with OPPOSITE verdicts because the
 * in-core BLI flags (b_log_item attached, XFS_LI_IN_AIL, dirty=0, pin=0)
 * cannot distinguish two cases that share identical flags:
 *   (A) drained pre-yield, content ON disk, BLI merely lingers in the AIL
 *       until the next log-tail-advancing checkpoint  -> safe to discard.
 *   (B) un-destaged, content NOT on disk (disk pristine)  -> MUST keep;
 *       discarding reverts this node's own allocations -> AG-meta corruption
 *       (cntbt CRC err74 + AGF verify fail + shutdown — PROVEN).
 *
 * The reliable discriminator is the LSN the write verifier stamps into the
 * metadata payload.  xfs_btree_agblock_calc_crc / the AGF/AGI calc_crc paths
 * copy bip->bli_item.li_lsn into the on-disk header (bb_lsn / agf_lsn / ...)
 * at WRITE-SUBMIT time only.  The log item's li_lsn advances earlier, at
 * CIL->AIL insertion.  So:
 *   - pinned (in CIL, not yet in AIL)               -> un-destaged (true)
 *   - in AIL and li_lsn  >  payload_lsn             -> modified since last
 *                                                      write submit -> true
 *   - in AIL and li_lsn <= payload_lsn             -> last mods were written
 *                                                      (at least to the shared
 *                                                      SCST cache) -> false
 * No blocking I/O: payload_lsn is read straight out of the already-resident
 * b_addr.  Scoped to the AG-meta buffers the invalidation path walks.
 */
static xfs_lsn_t
mxfs_ag_meta_payload_lsn(struct xfs_buf *bp)
{
	__be32	magic;

	if (!bp->b_addr)
		return 0;
	magic = *(__be32 *)bp->b_addr;
	switch (be32_to_cpu(magic)) {
	case XFS_AGF_MAGIC:
		return be64_to_cpu(((struct xfs_agf *)bp->b_addr)->agf_lsn);
	case XFS_AGI_MAGIC:
		return be64_to_cpu(((struct xfs_agi *)bp->b_addr)->agi_lsn);
	case XFS_AGFL_MAGIC:
		return be64_to_cpu(((struct xfs_agfl *)bp->b_addr)->agfl_lsn);
	default:
		/* short-pointer (AG) btree blocks: bnobt/cntbt/inobt/finobt/rmap */
		return be64_to_cpu(
			((struct xfs_btree_block *)bp->b_addr)->bb_u.s.bb_lsn);
	}
}

bool
mxfs_buf_is_undestaged(struct xfs_buf *bp)
{
	struct xfs_buf_log_item	*bip;
	xfs_lsn_t		bli_lsn, payload_lsn;

	if (!bp)
		return false;
	/* In the CIL: pinned, not yet even in the AIL — definitely un-destaged. */
	if (xfs_buf_ispinned(bp))
		return true;
	bip = bp->b_log_item;
	if (!bip)
		return false;		/* no log item ever, or freed at write
					 * completion — content is on disk */
	if (!test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))
		/*
		 * (b62r4 ROOT, PROVEN by
		 * P110@18:11:38.727064): a BLI exists from first modification
		 * until xfs_buf_item_done at WRITE COMPLETION — so a live BLI
		 * that is neither pinned nor in the AIL is in the async
		 * CIL→AIL transition window (unpinned by the commit-record
		 * callback, AIL insertion not yet visible).  The old
		 * `return false` called that DESTAGED; the P117 release-path
		 * stale-clean then cleared XBF_DONE on a bnobt mid free-chain
		 * (deferred AG unlock between two back-to-back frees), the
		 * next free cold-read the LAGGING platter image over the
		 * committed-unwritten insert, and computed a right-merge on
		 * the reverted base → bnobt/cntbt permanently disagree about
		 * the first free → peer's `i != 1` shutdown.  A live BLI not
		 * yet in the AIL is committed-unwritten by construction:
		 * report undestaged.
		 */
		return true;
	bli_lsn = bip->bli_item.li_lsn;
	payload_lsn = mxfs_ag_meta_payload_lsn(bp);
	/* li_lsn strictly newer than the LSN last stamped at write-submit => the
	 * current content has not been written since it was last modified. */
	return XFS_LSN_CMP(bli_lsn, payload_lsn) > 0;
}

/*
 * destaged-vs-undestaged discriminator for DIRECTORY metadata
 * buffers (dir3 data/block/leaf/free, da3 node) and dir data-fork BMBT
 * blocks.  Needed because the dpn=100 storm's true silent dirent loss
 * (node3_dir63/64 vanished cluster-wide after successful creates) was
 * produced by the in-AIL skip in xfs_da_read_buf: a dir block whose
 * content was drained-durable at release but whose BLI lingers in the AIL
 * was treated as "this node's committed unwritten work" and NOT refreshed
 * on the next tenure — the subsequent RMW added our new entry to a base
 * image missing the peer's entries and clobbered them on destage.
 * (The original payload-LSN implementation was replaced in run14d —
 * see the comment inside.)
 */
bool
mxfs_dir_buf_is_undestaged(struct xfs_buf *bp)
{
	if (!bp)
		return false;
	if (xfs_buf_ispinned(bp))
		return true;
	/*
	 * run14d (instrumented, PROVEN via P35A): the former payload-LSN
	 * compare here was cross-node-UNSAFE.  The LSN in a dir block's
	 * header is stamped by whichever node last write-submitted the
	 * block, from ITS OWN journal sequence; comparing it to our local
	 * li_lsn is meaningless.  Every observed misjudgement showed
	 * li_lsn < payload_lsn — impossible within one journal (the stamp
	 * is copied FROM li_lsn at submit, and re-logging only moves li_lsn
	 * forward), so the stamp provably came from a peer.  The false
	 * "destaged" verdict let xfs_da_read_buf re-read disk over our own
	 * committed-unwritten dirent inserts — the zero_silent_loss
	 * own-dirent ENOENT + durable-loss family (node5_dir33 et al).
	 *
	 * The node-local logged/written sequence pair is exact: every
	 * xfs_trans_log_buf bumps b_mxfs_logged_seq, every write submit
	 * snapshots it into b_mxfs_written_seq.  Unequal => this buffer
	 * carries local modifications that have not left for disk; equal =>
	 * the last local mods were submitted (the destaged-stale
	 * case stays refreshable, so the lost-update fix is kept).
	 */
	return bp->b_mxfs_logged_seq != bp->b_mxfs_written_seq;
}

/*
 * ROOT FIX for the dir_reuse_coherency round-1
 * format-transition durable loss (PROVEN dirwr trace + 2× design review
 * consult on the captured bytes).  A dir format transition
 * (block->leaf / sf->block / leaf->node) REUSES the SAME daddr for dir
 * block 0 while changing its on-disk magic/ops IN PLACE, WITHOUT advancing
 * any cluster-visible dir generation.  A pre-conversion cached image of
 * that daddr (carrying the OLD format + content) therefore stays
 * b_mxfs_dir_gen == i_dlm_dir_gen = "current" to every gen-keyed
 * read-invalidation (xfs_da_read_buf) and write-submit guard
 * (dir_ex_write_guard / dataclobber, both keyed on bgen < dir_gen); a later
 * AIL/delwri writeback of that stale image overwrites the post-conversion
 * data block, durably dropping the just-added dirent.  PROVEN byte-exact:
 * node7 journals node7_f1 -> daddr120, then daddr120 is written WITHOUT it
 * (24 block-fmt entries), node6 writes daddr120 as xfs_dir3_BLOCK — all
 * gen==2.
 *
 * Bump i_dlm_dir_gen at the conversion site so every pre-conversion cached
 * buffer is now detectably stale (bgen < dir_gen), and stamp the LIVE
 * converted buffers (dbp = block0-now-data, lbp = new leaf) to the new gen
 * so they stay authoritative.  Advance loaded_gen in lockstep: WE did this
 * modification in-core, so our base is NOT a stale peer base
 * (gen==loaded_gen => no spurious self-skip / stale-base reload of our own
 * just-converted fork).  Handoff-independent (unlike mxfs_dir_gen_per_handoff,
 * which is capped <= loaded_gen and misses 2nd+ intra-round fast-path
 * handoffs): the bump happens on the actual conversion, every time.
 */
int mxfs_dir_conv_genbump;	/* DEFAULT 0 — conversion-site gen bump did NOT fix the loss (the root is the modify-evict keep-guard, not a missing conversion bump); kept as an A/B lever. */
module_param_named(dir_conv_genbump, mxfs_dir_conv_genbump, int, 0644);
MODULE_PARM_DESC(dir_conv_genbump,
		 "Bump dir gen on block<->leaf<->node format transition so "
		 "pre-conversion cached blocks are detected stale (1=on default)");

void
mxfs_dir_gen_bump_on_convert(struct xfs_inode *dp, struct xfs_buf *dbp,
			     struct xfs_buf *lbp)
{
	struct xfs_mount	*mp;

	if (!mxfs_dir_conv_genbump || !dp)
		return;
	mp = dp->i_mount;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) ||
	    !S_ISDIR(VFS_I(dp)->i_mode))
		return;

	dp->i_dlm_dir_gen++;
	if (dp->i_dlm_dir_loaded_gen < dp->i_dlm_dir_gen)
		dp->i_dlm_dir_loaded_gen = dp->i_dlm_dir_gen;
	if (dbp)
		dbp->b_mxfs_dir_gen = dp->i_dlm_dir_gen;
	if (lbp)
		lbp->b_mxfs_dir_gen = dp->i_dlm_dir_gen;
	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: P36-CONV-GENBUMP ino=%llu new_gen=%llu loaded=%u",
			(unsigned long long)dp->i_ino,
			(unsigned long long)dp->i_dlm_dir_gen,
			dp->i_dlm_dir_loaded_gen);
}

/*
 * dir data-fork BMBT read coherency (instrumented, PROVEN family:
 * 3 nodes shut down on "ir.loaded != ifp->if_nextents" in
 * xfs_iread_extents during the 16-node dpn=100 mkdir storm once the
 * shared dir's data fork went BTREE).  After a DLM reload of a grown
 * dir, the dinode (and thus if_broot + if_nextents) is FRESH — the
 * reload stales+re-reads the inode cluster buffer — but the bmbt CHILD
 * blocks the lazy xfs_iread_extents walk visits are read through the
 * normal buffer cache, and NOTHING invalidated those: dir DATA/LEAF
 * blocks are covered by the v0.4.7 b_mxfs_dir_gen hook in
 * xfs_da_read_buf, AG btrees by mxfs_ag_meta_invalidate_stale, the
 * dinode by the reload itself — bmbt children were the uncovered
 * class.  A peer's grow rewrites a bmbt block IN PLACE at the same
 * daddr, so our cached copy is stale yet XBF_DONE → the walk loads a
 * prior-tenure record count that mismatches the fresh if_nextents →
 * EFSCORRUPTED shutdown.  Same gen scheme as the da hook: invalidate a
 * CLEAN cached bmbt block whose b_mxfs_dir_gen lags the owning dir's
 * i_dlm_dir_gen (bumped on every reload), stamp on invalidate.
 * Deadlock-safe: XBF_TRYLOCK; skip dirty/in-AIL/pinned/delwri (our
 * copy is then authoritative).  Self-gates: multi-node dirs only.
 */
void
mxfs_dir_bmbt_invalidate_stale(struct xfs_inode *dp, xfs_daddr_t d, int len)
{
	struct xfs_mount	*mp;
	struct xfs_buf		*cbp = NULL;

	if (!dp)
		return;
	mp = dp->i_mount;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) ||
	    !S_ISDIR(VFS_I(dp)->i_mode) || dp->i_dlm_dir_gen == 0)
		return;
	/*
	 * ROOT FIX for zero_silent_loss: only
	 * invalidate the cached bmbt leaf when the in-core extent list is NOT
	 * loaded (need_iread).  When the iext tree IS loaded it is the
	 * authoritative in-core copy of the dir's extent map, and the
	 * transaction machinery keeps the cached bmbt leaf buffer in lockstep
	 * with it.  Clearing XBF_DONE here makes the bmbt cursor's very next
	 * read (e.g. inside xfs_bmap_add_extent_hole_real during a mkdir)
	 * cold-fetch the STALE on-disk leaf, reverting the leaf buffer away
	 * from the loaded iext tree by exactly the in-flight record.  Proven
	 * live on the 16-node dpn=100 storm: P64-LEFTCONTIG-DESYNC ino=131
	 * iext=N leaf_numrecs=N-1 comm=mkdir -> xfs_bmap_add_extent_hole_real
	 * i!=1 -> xfs_trans_cancel -> shutdown; and the torn (dinode=N,
	 * leaf=N-1) image a peer then reads as P59-IREAD-MISMATCH loaded=N-1
	 * if_nextents=N.  This is the exact revert documented for the
	 * sibling evict path (mxfs_dir_evict_bmbt_blocks is gated need_iread at
	 * its call site, mxfs_dir_drain_evict_data_blocks) and the tenure
	 * authority guard the AG sibling carries (mxfs_ag_meta_invalidate_stale,
	 * ); the bmbt hook was added without either guard.
	 * need_iread==1 is precisely the reload / xfs_iread_extents window the
	 * hook was built for (cold-read a peer's fresh children), so the
	 * fix is fully preserved.
	 */
	if (!xfs_need_iread_extents(&dp->i_df))
		return;
	if (xfs_buf_incore(mp->m_ddev_targp, d, len, XBF_TRYLOCK, &cbp) != 0 ||
	    !cbp)
		return;
	{
		struct xfs_buf_log_item	*bip = cbp->b_log_item;
		bool dirty = bip && test_bit(XFS_LI_DIRTY,
					     &bip->bli_item.li_flags);
		bool in_ail = bip && test_bit(XFS_LI_IN_AIL,
					      &bip->bli_item.li_flags);

		/* FIX-14: undestaged check unconditional (the
		 * in_ail gate was the CIL-window bypass — see the P-DE-BLK
		 * site). */
		if ((cbp->b_flags & XBF_DONE) &&
		    cbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen &&
		    !dirty &&
		    !mxfs_dir_buf_is_undestaged(cbp) &&
		    !xfs_buf_ispinned(cbp) &&
		    !(cbp->b_flags & _XBF_DELWRI_Q)) {
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe_ratelimited(
					"mxfs: P133-BMBT-INVAL ino=%llu daddr=%lld buf_gen=%u inode_gen=%u -> re-read\n",
					(unsigned long long)dp->i_ino, (long long)d,
					cbp->b_mxfs_dir_gen, dp->i_dlm_dir_gen);
			cbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			cbp->b_mxfs_dir_gen = dp->i_dlm_dir_gen;
		} else if ((cbp->b_flags & XBF_DONE) &&
			   cbp->b_mxfs_dir_gen != dp->i_dlm_dir_gen) {
			mxfs_probe_ratelimited(
				"mxfs: P133-BMBT-STALE-SKIP ino=%llu daddr=%lld buf_gen=%u inode_gen=%u dirty=%d in_ail=%d pin=%d delwri=%d\n",
				(unsigned long long)dp->i_ino, (long long)d,
				cbp->b_mxfs_dir_gen, dp->i_dlm_dir_gen,
				dirty, in_ail, xfs_buf_ispinned(cbp),
				!!(cbp->b_flags & _XBF_DELWRI_Q));
		}
	}
	xfs_buf_relse(cbp);
}

/*
 * AG free-space read coherency.  Invalidate a cached AG-metadata
 * buffer (agf/agi/agfl/bnobt/cntbt/inobt/finobt) at [d, d+len) whose stamp
 * lags pag->pag_dlm_meta_gen (bumped on every fresh AG acquire), so the
 * caller's sanctioned read FUA-re-reads a peer's committed free-space and we
 * don't double-allocate (-> bmap/SB corruption under concurrent rename).
 * Deadlock-safe: XBF_TRYLOCK, and skip a dirty/pinned/delwri buffer (our copy
 * is then authoritative — clearing XBF_DONE on it would lose our update / trip
 * the write verifier).  Mirrors xfs_da_read_buf's i_dlm_dir_gen invalidation.
 * Multi-node only; no-op single-node or when nothing is cached.
 */
void
mxfs_ag_meta_invalidate_stale(struct xfs_mount *mp, struct xfs_perag *pag,
			      xfs_daddr_t d, int len)
{
	struct xfs_buf	*cbp = NULL;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) ||
	    !pag->pag_dlm_meta_gen)
		return;
	if (xfs_buf_incore(mp->m_ddev_targp, d, len, XBF_TRYLOCK, &cbp) != 0 ||
	    !cbp)
		return;
	{
		struct xfs_buf_log_item *bip = cbp->b_log_item;
		bool dirty = bip && test_bit(XFS_LI_DIRTY,
					     &bip->bli_item.li_flags);
		bool in_ail = bip && test_bit(XFS_LI_IN_AIL,
					      &bip->bli_item.li_flags);

		/*
		 * (design review design-consult) — DLM-TENURE AUTHORITY, the structural
		 * replacement for the gen/LSN preserve-vs-discard heuristics that
		 * lost the AGI unlinked-list head for ~12 sessions.  If this buffer
		 * was read/modified during the CURRENT AG-DLM hold (b_tenure_id ==
		 * ag_dlm_tenure_id), it is this-node-authoritative: we hold the AG
		 * EX, so NO peer can have advanced the on-disk image, and any
		 * in-core modification (e.g. a just-committed iunlink INSERT,
		 * P82-ADD) is the truth.  Discarding it and re-reading disk reverts
		 * our own committed-but-not-yet-durable work (the proven
		 * P82-ADD -> P117-discard -> P71 NULLAGINO corruption -> shutdown in
		 * test_unlink_visibility).  Return immediately — never a discard
		 * candidate mid-tenure.  Only PRIOR-tenure buffers (b_tenure_id !=
		 * current, e.g. a prev-epoch drained log-tail artifact that lingers
		 * in_ail) fall through to the gen-based cold-read below; those ARE
		 * durable on disk (Invariant #1 drained them before we yielded), so
		 * re-reading the peer's image is correct (preserves the
		 * bnobt-double-free fix).  b_tenure_id is stamped to the current
		 * tenure by the AG-meta read sites (xfs_read_agi / xfs_read_agf /
		 * xfs_btree read) after each successful read under the hold.
		 */
		if (pag->ag_dlm_tenure_id &&
		    cbp->b_tenure_id == pag->ag_dlm_tenure_id) {
			xfs_buf_relse(cbp);
			return;
		}

		if (cbp->b_mxfs_ag_gen >= pag->pag_dlm_meta_gen) {
			/* Already at (or past) the current AG generation —
			 * content is fresh, nothing to do.
			 * P101: catch "treated fresh but actually a
			 * pristine (whole-AG-free) bnobt/cntbt leaf" — the
			 * stale-V0-over-V1 clobber.  If this buffer is a level-0
			 * bnobt/cntbt with numrecs<=2 (pristine-ish) we are about
			 * to hand the allocator a pristine free-space tree under
			 * a current gen stamp.  Logs daddr+gen+numrecs so we can
			 * see whether the no-op branch is the clobber source. */
			if (unlikely(mxfs_instr_enabled) && (cbp->b_flags & XBF_DONE) &&
			    cbp->b_addr &&
			    (cbp->b_ops == &xfs_bnobt_buf_ops ||
			     cbp->b_ops == &xfs_cntbt_buf_ops)) {
				struct xfs_btree_block *bb = cbp->b_addr;
				if (be16_to_cpu(bb->bb_level) == 0 &&
				    be16_to_cpu(bb->bb_numrecs) <= 2) {
					__be32 *r0 = (__be32 *)((char *)bb +
						XFS_BTREE_SBLOCK_CRC_LEN);
					mxfs_probe_ratelimited("mxfs: P101-INVAL-NOOP-PRISTINE agno=%u daddr=%lld %s numrecs=%u rec0=[%u,%u] buf_gen=%llu pag_gen=%llu\n",
						pag_agno(pag), (long long)d,
						cbp->b_ops == &xfs_bnobt_buf_ops ? "bno" : "cnt",
						be16_to_cpu(bb->bb_numrecs),
						be32_to_cpu(r0[0]), be32_to_cpu(r0[1]),
						(unsigned long long)cbp->b_mxfs_ag_gen,
						(unsigned long long)pag->pag_dlm_meta_gen);
				}
			}
		} else if ((cbp->b_flags & XBF_DONE) &&
			   !dirty && !in_ail && !xfs_buf_ispinned(cbp) &&
			   !(cbp->b_flags & _XBF_DELWRI_Q) &&
			   !(cbp->b_flags & XBF_WRITE)) {
			/*
			 * REVERT of (instrument step 2b — PROVEN by the
			 * ino=132 AGI-unlinked-loss timeline): the `!in_ail`
			 * exclusion is RESTORED.  removed it on the theory
			 * that a !dirty buffer's content is already on the coherent
			 * SCST cache, so an in-AIL buffer is just a stale prior-hold
			 * snapshot safe to discard.  That theory conflates two
			 * distinct lifecycle points:
			 *   - COMMIT clears XFS_LI_DIRTY (the BLI dirty bit) and moves
			 *     the item into the AIL (XFS_LI_IN_AIL set).  The modified
			 *     block is STILL only in core at this point.
			 *   - WRITEBACK (AIL push) is what actually pushes the block to
			 *     the SCST cache, and only THEN is the item removed from
			 *     the AIL.
			 * So a committed-but-not-yet-written-back buffer has DIRTY
			 * CLEAR but IN_AIL SET, and its content is NOT yet on the
			 * coherent cache.  Discarding+re-reading it loses this node's
			 * committed work.  PROVEN: P82-ADD logs an inode onto the AGI
			 * unlinked bucket (commit succeeds, AGI now in_ail, head=our
			 * agino); the very next AG reacquire hit this branch and
			 * discarded daddr=2 (the AGI); the re-read returned the
			 * pre-ADD head=NULLAGINO; xfs_iunlink_remove_inode then read a
			 * garbage/empty bucket head -> XFS_CORRUPTION_ERROR (line 632,
			 * P71-INSTR) -> shutdown.  An in-AIL AG-meta buffer is ALWAYS
			 * this-node-ahead (the AG-DLM EX serialises peers and a proper
			 * release drains the AIL before unlock, invariant #1), so a
			 * genuine prior-hold stale buffer is NOT in_ail after release —
			 * it is clean+DONE and is still correctly discarded here.  Only
			 * this-node-ahead committed work is in_ail, and that must be
			 * preserved (it falls through to the else branch below).
			 */
			/*
			 * Stale (gen-lagging) and safe to discard: clear DONE
			 * so the read below re-reads the peer's committed
			 * block.  ONLY here do we advance the gen stamp — the
			 * buffer's content is about to become fresh.
			 */
			cbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			cbp->b_mxfs_ag_gen = pag->pag_dlm_meta_gen;
		} else if ((cbp->b_ops == &xfs_bnobt_buf_ops ||
			    cbp->b_ops == &xfs_cntbt_buf_ops ||
			    cbp->b_ops == &xfs_agf_buf_ops ||
			    cbp->b_ops == &xfs_agfl_buf_ops ||
			    cbp->b_ops == &xfs_agi_buf_ops ||
			    cbp->b_ops == &xfs_inobt_buf_ops ||
			    cbp->b_ops == &xfs_finobt_buf_ops) &&
			   in_ail && !dirty && !xfs_buf_ispinned(cbp) &&
			   !(cbp->b_flags & _XBF_DELWRI_Q) &&
			   !(cbp->b_flags & XBF_WRITE) &&
			   (cbp->b_flags & XBF_DONE) &&
			   !mxfs_buf_is_undestaged(cbp)) {
			/*
			 * EXTENDED from {bnobt,cntbt} to the
			 * full AG-meta set {agf,agfl,agi,inobt,finobt}.  The
			 * shared on-disk AG epoch (P102-ACQ) now advances
			 * pag_dlm_meta_gen whenever a PEER touched the AG, so a
			 * prev-epoch in-AIL AGF/AGI log-tail artifact can be just
			 * as stale as a bnobt one.  WITHOUT this, the fresh-acquire
			 * pagf/pagi reset (P102-ACQ) re-reads the SAME stale in-AIL
			 * AGF (the branch below PROTECTs it), so the RMW still
			 * builds on an inconsistent free-space base → the proven
			 * agf_longest>agf_freeblks corruption + xfs_agf_verify
			 * shutdown under 100-file stress.  SAFE: the
			 * mxfs_buf_is_undestaged() guard above already handles
			 * AGF→agf_lsn, AGI→agi_lsn, AGFL→agfl_lsn, btree→bb_lsn
			 * (mxfs_ag_meta_payload_lsn), so a this-node-ahead
			 * un-written AGI iunlink-head buffer is still PROTECTED
			 *  — only truly-destaged prev-epoch artifacts
			 * reach here.
			 */
			/*
			 * the branch below
			 * ONLY runs for a genuinely-DRAINED prev-epoch buffer.
			 * The new mxfs_buf_is_undestaged() LSN check (payload
			 * bb_lsn vs BLI li_lsn) is the reliable A-vs-B
			 * discriminator the in-AIL flags alone could not provide.
			 * If this buffer's content is NOT on disk yet (case B —
			 * un-destaged, the PROVEN single-node self-corruption:
			 * P117 staling it while P110 kept it -> cntbt CRC err74 +
			 * AGF corruption + shutdown), this `else if` is now
			 * FALSE and the buffer falls through to the /43
			 * PROTECT-in-AIL branch (kept, gen left lagging).  Only a
			 * truly-written (li_lsn <= payload_lsn) gen-lagging in-AIL
			 * buffer reaches the discard below, so a peer's newer
			 * split is still cold-read (cross-node fix
			 * preserved) without reverting this node's own work.
			 */
			/*
			 * FIX (design review design-consult ROOT): the "in-AIL AG-meta
			 * is ALWAYS this-node-ahead" assumption (/103) is
			 * WRONG for a PREVIOUS-epoch (gen-lagging) buffer.  AIL
			 * presence OUTLIVES the synchronous buffer write: the BLI
			 * is removed from the AIL on LOG-TAIL advancement (the
			 * next checkpoint), NOT on buffer writeback completion.
			 * So after a node drains+bwrites its bnobt/cntbt at AG
			 * yield (Invariant #1: content durable on disk), the
			 * buffer stays in_ail=1 until the unrelated checkpoint
			 * fires.  A peer then acquires the AG and commits a newer
			 * allocation to disk.  On re-acquire, the gen-based hook
			 * would re-read the peer's image — but the OLD code saw
			 * in_ail=1 and PROTECTED this now-stale log-tail artifact,
			 * so the allocator RMW'd a stale base and xfsaild later
			 * flushed it over the peer's durable split =
			 * P93-REVERT-CLOBBER → `ltbno+ltlen>bno` double-free
			 * shutdown (PROVEN every clobbering write is
			 * in_ail=1 dirty=0 pin=0 delwri=0, buf_gen=0 < pag_gen=5,
			 * disk_nr > buf_nr).
			 *
			 * Since buf_gen < pag_gen, this buffer is from a PRIOR AG
			 * tenure whose durable state was already synchronously
			 * flushed before the previous yield — it CANNOT hold
			 * unsaved local commits (those would be dirty/pinned, not
			 * clean+in_ail).  Discard it (stale + clear DONE) so the
			 * next read cold-reads the peer's committed free-space
			 * tree.  Scoped to bnobt/cntbt (the proven victims) and
			 * gen-lagging + clean-but-in_ail (the log-tail artifact);
			 * a CURRENT-epoch (buf_gen==pag_gen) in-AIL buffer is
			 * genuinely this-node-ahead and is NOT reached here (the
			 * buf_gen>=pag_gen branch above handles it), preserving
			 * the AGI unlinked-list protection.
			 */
			xfs_buf_stale(cbp);
			cbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			mxfs_probe_ratelimited("mxfs: P117-INAIL-STALE-ARTIFACT daddr=%lld %s buf_gen=%llu pag_gen=%llu — discarded prev-epoch in-AIL log-tail artifact\n",
				(long long)cbp->b_maps[0].bm_bn,
				cbp->b_ops == &xfs_bnobt_buf_ops ? "bnobt" :
				cbp->b_ops == &xfs_cntbt_buf_ops ? "cntbt" :
				cbp->b_ops == &xfs_agf_buf_ops ? "agf" :
				cbp->b_ops == &xfs_agfl_buf_ops ? "agfl" :
				cbp->b_ops == &xfs_agi_buf_ops ? "agi" :
				cbp->b_ops == &xfs_inobt_buf_ops ? "inobt" :
				cbp->b_ops == &xfs_finobt_buf_ops ? "finobt" : "?",
				(unsigned long long)cbp->b_mxfs_ag_gen,
				(unsigned long long)pag->pag_dlm_meta_gen);
		} else {
			/*
			 * FIX: stale (gen-lagging) but we CANNOT
			 * invalidate it now (pinned / BLI-dirty / delwri-queued
			 * / not-DONE).  The OLD code stamped b_mxfs_ag_gen to
			 * the current gen here unconditionally — which marked a
			 * STALE, un-refreshed buffer as "fresh", so every later
			 * read-hook saw gen-current and never re-read it.  Under
			 * concurrent 4-node rename this froze a stale bnobt
			 * buffer (whole-AG-free, post-mkfs view) as authoritative
			 * → the allocator double-allocated already-used free
			 * space → cnt/bno disagree → xfs_alloc.c i!=1 corruption
			 * + FS shutdown (P70-INSTR: bno_gen==pag_gen yet
			 * bno_disk_differs=1, pin=1).  Do NOT advance the gen:
			 * leave it lagging so the NEXT read-hook (once the buffer
			 * is unpinned/clean) re-reads the peer's committed block.
			 *
			 * FIX: the OLD guard discarded a buffer that is
			 * committed-but-not-yet-written-back (XFS_LI_IN_AIL set)
			 * yet has XFS_LI_DIRTY clear + pin==0 (P70 proved bno can
			 * be in this state: bno_dirty=0 bno_pin=0 yet
			 * bno_disk_differs=1 = in-core AHEAD of disk).  Discarding
			 * it re-read the STALE on-disk image → LOST the committed
			 * update → cnt/bno diverge → xfs_alloc.c i!=1 shutdown.
			 * An in-AIL AG-meta buffer is ALWAYS this-node-ahead (the
			 * AG-DLM EX serialises peers; release drains the AIL), so
			 * preserving it is correct; the gen stays lagging so once
			 * writeback clears it from the AIL a later read refreshes.
			 */
			if (in_ail)
				mxfs_probe("mxfs: P77-INSTR PROTECT-in-AIL daddr=%lld gen=%llu pag_gen=%llu dirty=%d pin=%d delwri=%d flags=0x%x\n",
					(long long)cbp->b_maps[0].bm_bn,
					(unsigned long long)cbp->b_mxfs_ag_gen,
					(unsigned long long)pag->pag_dlm_meta_gen,
					dirty, xfs_buf_ispinned(cbp) ? 1 : 0,
					(cbp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
					cbp->b_flags);
			/*
			 * (D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399,
			 * Design-consult layer 2): a PRIOR-tenure AG-meta buffer that is
			 * in the AIL, clean, unpinned and UNDESTAGED (its committed
			 * image never reached the medium) is an invariant violation,
			 * not a protect case.  The /103 premise behind this
			 * branch — "in-AIL AG-meta is always this-node-ahead because
			 * release drains" — holds only if every AG-meta modification
			 * ran under tenure; proved the O_TMPFILE linkat and
			 * rename-whiteout xfs_iunlink_remove ran with none, so this
			 * exact state (P77 dirty=0 pin=0 delwri=0 + undestaged AGI)
			 * was the stale base that RMW'd agi_freecount +-1 and then
			 * published it.  Both outcomes from here are corruption:
			 * protecting it RMWs a stale base; writing it clobbers the
			 * peer; discarding it drops our committed update.  With the
			 * callers bracketed (0.23.11) this cannot occur; if it does,
			 * it names a new un-tenured AG-meta writer — alarm with the
			 * tenure pair and a stack so the writer can be found.
			 */
			if (in_ail && !dirty && !xfs_buf_ispinned(cbp) &&
			    !(cbp->b_flags & _XBF_DELWRI_Q) &&
			    mxfs_buf_is_undestaged(cbp)) {
				static atomic_t ptu_n = ATOMIC_INIT(0);
				int ptu_seq = atomic_inc_return(&ptu_n);

				if (ptu_seq <= 200)
					pr_warn("mxfs: P-AGMETA-PRIORTENURE-UNDESTAGED-INAIL agno=%u daddr=%lld ops=%s buf_tenure=%llu cur_tenure=%llu buf_gen=%llu pag_gen=%llu holders=%d comm=%s realns=%llu — committed-unwritten AG-meta image from a PRIOR tenure survived its release: an un-tenured AG-meta writer exists (premise violation)\n",
						pag_agno(pag),
						(long long)cbp->b_maps[0].bm_bn,
						mxfs_agmeta_name(cbp),
						(unsigned long long)cbp->b_tenure_id,
						(unsigned long long)pag->ag_dlm_tenure_id,
						(unsigned long long)cbp->b_mxfs_ag_gen,
						(unsigned long long)pag->pag_dlm_meta_gen,
						READ_ONCE(pag->pag_dlm_holders),
						current->comm,
						(unsigned long long)ktime_get_real_ns());
				if (ptu_seq <= 4)
					dump_stack();
			}
			/*
			 * P86: log EVERY stale-but-skipped AG-meta buffer
			 * (not just in_ail).  A gen-lagging buffer that is pinned /
			 * dirty / delwri / not-DONE is left STALE here — the
			 * allocator then RMWs a stale base = the bnobt lost-update
			 * (pristine-revert) that shuts down at xfs_alloc.c:2231.
			 * P77 only covered in_ail; this catches the pinned/dirty
			 * cases flagged ("can't refresh a locked buffer").
			 * Ratelimited so it surfaces without flooding.
			 */
			mxfs_probe_ratelimited("mxfs: P86-INSTR STALE-SKIP daddr=%lld gen=%llu pag_gen=%llu DONE=%d dirty=%d pin=%d in_ail=%d delwri=%d flags=0x%x\n",
				(long long)cbp->b_maps[0].bm_bn,
				(unsigned long long)cbp->b_mxfs_ag_gen,
				(unsigned long long)pag->pag_dlm_meta_gen,
				(cbp->b_flags & XBF_DONE) ? 1 : 0,
				dirty, xfs_buf_ispinned(cbp) ? 1 : 0,
				in_ail ? 1 : 0,
				(cbp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
				cbp->b_flags);
		}
	}
	xfs_buf_relse(cbp);
}

/*
 * ACQUIRE-SIDE COLD-READ (the second half of design review's design:
 * "pair release-discard + acquire-cold-read; one without the other fails").
 *
 * The gen-based read-time invalidate hook (mxfs_ag_meta_invalidate_stale) is
 * unreliable because pag_dlm_meta_gen is observed FROZEN at 1 (/80/116):
 * buf_gen==pag_gen so a stale cached bnobt/cntbt is treated as fresh and the
 * allocator RMWs it -> P93-REVERT-CLOBBER -> double-free shutdown.  Rather than
 * chase the frozen-gen root for a 50th session, make AG free-space coherency
 * gen-INDEPENDENT: when we take a FRESH AG EX grant (or reclaim one a peer may
 * have modified), DISCARD every CLEAN cached AG-meta buffer in this AG so the
 * first access cold-reads the peer's durable tree.  Covers the free-space
 * btrees (bnobt/cntbt/agf) AND the inode-allocation metadata (agi/inobt/finobt)
 * — the AGI's unlinked-list head must be coherent or xfs_iunlink_remove_inode
 * reads a stale bucket head and shuts the FS down.
 *
 * Safe: only CLEAN buffers are discarded (no li_list, not in-AIL, not pinned,
 * not dirty, not delwri-queued) — they carry NO pending change, so nothing is
 * lost.  An in-AIL/pinned buffer is this-node-ahead (Invariant #1: release
 * drains the AIL before unlock) and is left untouched.
 *
 * Called with NO AG-DLM locks held (just after the grant is taken, before any
 * allocator read), so the pag_bcache walk + trylock cannot deadlock.
 */
void
mxfs_ag_meta_coldread_discard(struct xfs_perag *pag, bool fresh_peer)
{
	struct xfs_mount	*mp = pag_mount(pag);
	struct rhashtable_iter	iter;
	struct xfs_buf		*bp;
	unsigned int		discarded = 0;
	unsigned int		ail_discarded = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;

	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			struct xfs_buf_log_item *bip;
			bool got = false;
			bool ail_artifact = false;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			/*
			 * FIX: cover the AGI + inode-alloc
			 * btrees, not just the free-space btrees.  The old
			 * filter (bnobt/cntbt only) left a CLEAN cached AGI
			 * stale on a fresh acquire — proven root of the
			 * cross-node iunlink corruption: a peer ADDs an inode
			 * to AG's unlinked bucket (commits disk_head=0x95),
			 * this node fresh-acquires the AG but keeps its stale
			 * in-core AGI (bucket=NULLAGINO), then
			 * xfs_iunlink_remove_inode reads the garbage head ->
			 * XFS_CORRUPTION_ERROR -> shutdown (P71-INSTR
			 * agi_disk_differs=1).  Inode REUSE across nodes makes
			 * inobt/finobt coherency matter too; AGF for the
			 * free-space header.  Same CLEAN-only guards below keep
			 * any this-node-ahead (in-AIL/dirty/pinned) buffer
			 * untouched, so nothing pending is lost.
			 */
			if (bp->b_ops != &xfs_bnobt_buf_ops &&
			    bp->b_ops != &xfs_cntbt_buf_ops &&
			    bp->b_ops != &xfs_agi_buf_ops &&
			    bp->b_ops != &xfs_agf_buf_ops &&
			    bp->b_ops != &xfs_inobt_buf_ops &&
			    bp->b_ops != &xfs_finobt_buf_ops)
				continue;
			if (!(bp->b_flags & XBF_DONE))
				continue;
			bip = bp->b_log_item;
			/*
			 * — close the xfsaild
			 * P93-REVERT-CLOBBER gap.  The OLD coldread skipped EVERY
			 * in-AIL buffer ("this-node-ahead, Invariant #1 drains
			 * before unlock").  That is WRONG for a prev-epoch
			 * bnobt/cntbt buffer: AIL presence OUTLIVES writeback (the
			 * BLI is removed on log-tail advancement, not on buffer-
			 * write completion).  After a release drains+writes our
			 * free-space btree the buffer stays in_ail until an
			 * unrelated checkpoint fires; a peer then acquires this AG
			 * and commits a newer split to disk.  On re-acquire the
			 * skipped buffer stays cached+stale, and xfsaild can push
			 * it before any read triggers the read-time invalidate hook
			 * (mxfs_ag_meta_invalidate_stale, which only fires on a READ
			 * of that exact daddr) -> it reverts the peer's durable
			 * split = P93-REVERT-CLOBBER -> ltbno+ltlen>bno double-free
			 * shutdown (PROVEN: comm=xfsaild buf_gen<pag_gen disk_nr>nr
			 * dirty=0 pin=0 in_ail=1).  Reliable A-vs-B discriminator is
			 * the payload-LSN check: an UN-destaged buffer (li_lsn >
			 * stamped payload_lsn) genuinely holds this-node-ahead mods
			 * and MUST be preserved; a DESTAGED in-AIL bnobt/cntbt is a
			 * log-tail artifact whose durable content a peer may have
			 * superseded -> discard so first access cold-reads disk
			 * (re-reading our own destaged content loses nothing).
			 * Scoped to the proven P93 victims (bnobt/cntbt); other
			 * AG-meta (agi/inobt/finobt/agf) keep the conservative
			 * in-AIL skip to preserve the AGI unlinked-list
			 * protection.
			 */
			if (bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) {
				/*
				 * Inv-2 fix: on a GENUINE fresh-from-peer
				 * grant (fresh_peer), a lingering in-AIL bnobt/cntbt is
				 * provably STALE prior-tenure — Invariant #1 drained any
				 * legitimate this-node-ahead AG-meta before we released to
				 * the peer, and the peer's durable writes have since
				 * superseded the AG.  Discard it UNCONDITIONALLY (the
				 * undestaged li_lsn check misclassified it as this-node-
				 * ahead and PRESERVED it — the proven hole: fresh-acquire
				 * STALED agf/agi but left the in-AIL bnobt/cntbt, which
				 * xfsaild then pushed over the peer's allocation =
				 * P124-ALLOC-REVERT double-free).  On a RECLAIM of our own
				 * cached/pending EX (fresh_peer=false, Invariant #1 NOT
				 * run), keep the conservative undestaged guard — an
				 * undestaged buffer there is genuinely this-node-ahead.
				 */
				if ((bp->b_ops == &xfs_bnobt_buf_ops ||
				     bp->b_ops == &xfs_cntbt_buf_ops) &&
				    (fresh_peer || !mxfs_buf_is_undestaged(bp)))
					ail_artifact = true;
				else
					continue;
			} else if (!list_empty_careful(&bp->b_li_list)) {
				continue;
			}
			if (bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags))
				continue;
			if (xfs_buf_ispinned(bp))
				continue;
			if (bp->b_flags & (_XBF_DELWRI_Q | XBF_WRITE))
				continue;

			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				got = true;
			}
			spin_unlock(&bp->b_lock);
			if (!got)
				continue;
			if (!xfs_buf_trylock(bp)) {
				xfs_buf_rele(bp);
				continue;
			}
			/* re-check under the buffer lock — state may have changed */
			bip = bp->b_log_item;
			{
			bool in_ail_now = bip &&
				test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
			bool dirty_now = bip &&
				test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
			/* a destaged in-AIL bnobt/cntbt log-tail artifact
			 * (ail_artifact) is also discardable — re-validate it is
			 * still in-AIL + still destaged under the lock. */
			bool ail_ok = ail_artifact && in_ail_now &&
				(bp->b_ops == &xfs_bnobt_buf_ops ||
				 bp->b_ops == &xfs_cntbt_buf_ops) &&
				(fresh_peer || !mxfs_buf_is_undestaged(bp));
			if ((bp->b_flags & XBF_DONE) &&
			    (ail_ok ||
			     (list_empty_careful(&bp->b_li_list) && !in_ail_now)) &&
			    !dirty_now &&
			    !xfs_buf_ispinned(bp) &&
			    !(bp->b_flags & (_XBF_DELWRI_Q | XBF_WRITE))) {
				xfs_buf_stale(bp);
				bp->b_flags &= ~XBF_DONE;
				discarded++;
				if (ail_ok) {
					ail_discarded++;
					pr_warn_ratelimited("mxfs: P121-COLDREAD-AIL-ARTIFACT agno=%u daddr=%lld %s — discarded destaged prev-epoch in-AIL free-space buf (xfsaild revert-clobber prevented)\n",
						pag_agno(pag),
						(long long)bp->b_maps[0].bm_bn,
						bp->b_ops == &xfs_bnobt_buf_ops ?
							"bnobt" : "cntbt");
				}
			}
			}
			xfs_buf_unlock(bp);
			xfs_buf_rele(bp);
		}
		rhashtable_walk_stop(&iter);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);

	if (discarded)
		mxfs_probe_ratelimited("mxfs: P117-COLDREAD-DISCARD agno=%u discarded=%u clean ag-meta bufs (bnobt/cntbt/agi/agf/inobt/finobt) ail_artifact=%u\n",
			pag_agno(pag), discarded, ail_discarded);
}

int
mxfs_ag_buf_disk_differs(struct xfs_buf *bp)
{
	uint32_t	len;
	uint64_t	lba;
	void		*tmp;
	int		rc;

	if (!bp || !bp->b_addr || !bp->b_target || !bp->b_target->bt_bdev)
		return -EINVAL;
	len = BBTOB(bp->b_length);
	if (len == 0 || (len & 511))
		return -EINVAL;
	lba = (uint64_t)bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	rc = mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev, lba, tmp, len);
	if (rc) {
		kfree(tmp);
		return rc < 0 ? rc : -EIO;
	}
	rc = memcmp(tmp, bp->b_addr, len) ? 1 : 0;
	if (rc && mxfs_diff_detail) {
		/*
		 * P35D (instrumented, run14d): localize the divergence.  Set
		 * mxfs_diff_detail=1 to dump the first differing offset, the
		 * byte count that differs, and 16 bytes from each side, so a
		 * persistent post-flush diff can be classified (LSN/CRC field
		 * vs dirent payload vs wholesale different image).
		 */
		uint32_t	off = 0, ndiff = 0, first = len;
		const u8	*a = tmp, *b = bp->b_addr;

		for (off = 0; off < len; off++) {
			if (a[off] != b[off]) {
				if (first == len)
					first = off;
				ndiff++;
			}
		}
		mxfs_probe("mxfs: P35D-DIFF-DETAIL daddr=%lld len=%u first=%u ndiff=%u disk=%16ph core=%16ph\n",
			(long long)bp->b_maps[0].bm_bn, len, first, ndiff,
			a + (first & ~15U), b + (first & ~15U));
	}
	kfree(tmp);
	return rc;
}

/*
 * instrumented DIRECTION PROBE.  For a bnobt/cntbt buffer we are about to
 * WRITE, FUA-read the SAME block from the medium and extract the on-disk
 * level-0 numrecs and first record (start,len).  Decides the /
 * stale-in-AIL question: if the in-core buffer we are writing has FEWER
 * records than disk (and a different rec0), our buffer is BEHIND the medium
 * (a peer wrote a newer version while we did not hold the AG, and our cached
 * in-AIL buffer survived the release) -> we are clobbering a durable peer
 * version.  Returns 0 on success and fills *disk_nr, *disk_s0, *disk_l0;
 * negative on error.
 */
int
mxfs_ag_buf_disk_bnobt(struct xfs_buf *bp, uint16_t *disk_nr,
		       uint32_t *disk_s0, uint32_t *disk_l0)
{
	uint32_t	len;
	uint64_t	lba;
	void		*tmp;
	int		rc;
	struct xfs_btree_block *db;
	__be32		*r0;

	if (!bp || !bp->b_addr || !bp->b_target || !bp->b_target->bt_bdev)
		return -EINVAL;
	len = BBTOB(bp->b_length);
	if (len == 0 || (len & 511))
		return -EINVAL;
	lba = (uint64_t)bp->b_maps[0].bm_bn + bp->b_target->bt_sector_offset;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	rc = mxfs_pal_scsi_read_fua_bdev(bp->b_target->bt_bdev, lba, tmp, len);
	if (rc) {
		kfree(tmp);
		return rc < 0 ? rc : -EIO;
	}
	db = (struct xfs_btree_block *)tmp;
	r0 = (__be32 *)((char *)db + XFS_BTREE_SBLOCK_CRC_LEN);
	if (disk_nr)
		*disk_nr = be16_to_cpu(db->bb_numrecs);
	if (disk_s0)
		*disk_s0 = be32_to_cpu(r0[0]);
	if (disk_l0)
		*disk_l0 = be32_to_cpu(r0[1]);
	kfree(tmp);
	return 0;
}
