// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- buffer tracking, xfsaild write gates and cached-view invalidation
 */
#define MXFS_TU_ID 31	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
/*
 * (0.39.12, D-0353, design-consult ruling ccmemory ccloop-c7ee71c6-sess432-
 * GPT-ruling-single-node-false-fresh-discard): the fresh-acquire AG-meta
 * invalidation is FAIL-CLOSED.  agmeta_inval_enforce=1: before anything is
 * staled, a dry preflight pass looks for AG-metadata buffers that still carry
 * this node's un-landed committed content (pinned = CIL-resident, bli DIRTY or
 * IN_AIL, delwri-queued); any hit shuts the filesystem down and stales NOTHING
 * (P131-INVAL-REFUSED) instead of discarding the update — the proven silent
 * lost-update / double-allocation.  false_fresh_enforce=1: a fresh CAW grant
 * that finds the AG's lineage still OPEN (no release checkpoint ran) is an
 * invariant violation, not a diagnostic — shut down (P130-FALSE-FRESH-REFUSED).
 * Both are measurement knobs only; never run a correctness campaign with
 * either off.
 */
int mxfs_agmeta_inval_enforce = 1;
module_param_named(agmeta_inval_enforce, mxfs_agmeta_inval_enforce, int, 0644);

/*
 * (design review): the EX-HELD clobber FIX that the
 * gen/content suppression arms (dir_stale_incarn_skip, catastrophic) and the
 * mid-op re-read (hard-wedges) both failed to solve.
 *
 * PROVEN ROOT (dataclobber=1 detect run): the dir_reuse 8/tcp readdir=799
 * single-entry lost-update is a BACKGROUND xfsaild / AIL-push destage (in_ail=1,
 * bdirty=0, pin=0, in_txn=0, comm=dd/bash — NOT the release-drain) of a
 * STALE-content in-core dir DATA/LEAF block by the node that GENUINELY HOLDS the
 * dir EX (mode=5 real_mode=5).  The buffer is stamped CURRENT-gen (stale=0) so
 * every gen/epoch guard is blind; the divergence is content-level (the block was
 * RMW'd on a base seeded by a PRIOR background clobber of the shared LUN — a
 * feedback loop: stale async write -> stale disk -> stale acquire-reread).
 *
 * THE FIX (the GFS2 invariant): while the dir is CONTENDED (a peer BAST is
 * pending), a multi-node dir DATA/LEAF block's on-disk image may change ONLY via
 * the EX holder's synchronous release-drain (Invariant #1), NEVER via a
 * background xfsaild destage.  Then between an EX holder's acquire (coherent
 * disk re-read) and its release the LUN is FROZEN -> the holder's in-core view =
 * acquire-disk + its own mods = coherent superset -> release-drain lands it ->
 * the next node reads coherent.  Inductively (LUN starts coherent round 1) the
 * LUN stays coherent forever.  Handles ADD and REMOVE alike (release-drain
 * writes the CURRENT post-op image), so it sidesteps the merge/remove-
 * resurrection wall that sank every content-based suppression.
 *
 * Implemented as a DEFER (xfs_buf_item_push returns XFS_ITEM_LOCKED): the BLI
 * stays in the AIL with NO I/O and is retried later — NOT staled (which would
 * drop our own un-destaged content) and NOT fake-ioend'd (which would lie to the
 * release-drain's in-AIL durability check).  Gated on mode==EX && bast_pending so
 * (a) an uncontended long EX hold still destages normally (no log-tail
 * starvation) and (b) the gate self-clears the instant we release EX (mode->NL)
 * so any block the release-drain missed destages normally afterward (no
 * permanent AIL stall).
 */
int mxfs_dir_ail_defer;	/* default OFF — defer-on REGRESSES 4/tcp dir_reuse (round14 lost node2's whole 49-file md5 batch, readdir=351/400) and intermittently starvation-shuts-down 8/tcp (DLM acquire rc=-110 184s).  ROOT: deferring background dir-block destages (XFS_ITEM_LOCKED) withholds writes the release-drain does NOT reliably make up (whole-batch loss) AND pins the log tail -> DLM acquire starvation.  design review's design needs the missing liveness valve (prompt quiesced checkpoint on contention/pressure + a release-drain proven to flush EVERY deferred block).  Kept as a modarg for continued work; the diagnosis (background-aild-destage clobber) stands. */
module_param_named(dir_ail_defer, mxfs_dir_ail_defer, int, 0644);
MODULE_PARM_DESC(dir_ail_defer,
                 "Defer (keep in AIL, no I/O) a background xfsaild destage of a "
                 "multi-node dir DATA/LEAF block while this node holds EX and a "
                 "peer BAST is pending; land it only via the release-drain "
                 "(1=on default, 0=off)");

/*
 * SKIP an xfsaild reflush of an already-destaged,
 * clean dir DATA/leaf buffer while this node holds the owner dir EX.  PROVEN
 * (instrumented, P-WGHOST=0 + P-WMERGE) root of the 8/tcp dir_reuse readdir=799
 * single-dirent durable loss: the loss-causing write is the CANONICAL dir
 * buffer (not a ghost) re-flushed by xfsaild with held_mode=EX in_ail=1
 * dirty=0 pin=0 lseq==wseq — i.e. a PURE REDUNDANT REFLUSH of content already
 * on disk, whose cached image has since gone stale (a peer added a dirent we
 * lack -> disk_extra>0).  Re-writing our already-destaged image can only
 * REVERT the peer's add (clobber) or be a no-op; it never carries un-landed
 * local work (that would be dirty or undestaged, lseq>wseq).  So dropping it
 * (emulate clean ioend -> retires the lingering BLI, NO log-tail starvation,
 * unlike dir_ail_defer) is loss-safe and symmetric across nodes: with every
 * node skipping reverting reflushes, each node's active-tenure write (fresh
 * RMW base, proven superset) is the only writer -> the durable image only
 * ever GAINS dirents.  Local read-staleness self-heals via the dir_gen FUA
 * re-read hook.  Unlike the merge/graft (dir_write_merge, REFUTED: over-grafts
 * to 803 + corruption) this changes NOTHING in the block, only suppresses a
 * redundant write.  Gated; default ON.
 * v2 (design review consult): refined to the PROVEN-safe predicate — only a
 * COHERENCY-INVALIDATED (!XBF_DONE: the acquire-evict cleared DONE to force a
 * re-read) buffer that is ALSO clean (BLI !dirty), already-destaged (lseq==wseq
 * && !pinned), in the AIL, and !delwri.  Such a buffer is a "zombie BLI": its
 * content is non-authoritative (DONE cleared) and there is nothing of ours to
 * land (clean+destaged), yet a lingering in-AIL BLI re-flushes its STALE b_addr
 * over a peer's durable add (the dir_reuse 799 loss; P-WMERGE DONE=0 dirty=0
 * in_ail=1 lseq==wseq held_mode=EX comm=dd).  Keying on !XBF_DONE is what makes
 * this safe where the earlier (DONE-blind) suppression was the corruptor:
 * a legit write is DONE=1 (read/modified, authoritative); a freshly get_buf'd
 * block is DONE=0 but dirty/undestaged (excluded).  The skip path emulates a
 * clean write ioend, whose iodone RETIRES the BLI from the AIL (no log-tail
 * starvation, unlike dir_ail_defer).  ENFORCED independently of the refuted
 * mxfs_dirskip_enabled gate.
 * v2 REFUTED — default 0: enforcing this is CATASTROPHIC (readdir=0/1 all
 * nodes).  A legit dir-block content write is frequently DONE=0 at submit time
 * too (the FUA/_XBF_FUA_FRESH read-coherency cycle + acquire-evict clear DONE on
 * every tenure), so the !XBF_DONE key STILL drops needed writes -> the dir never
 * persists.  Write-side suppression of dir buffers is the corruptor in ALL forms
 * .  Kept inert; the fix is acquire-side BLI-retire (NOT dropping a
 * write — removing an already-durable clean buffer's zombie BLI + stale). */
int mxfs_dir_reflush_skip;
module_param_named(dir_reflush_skip, mxfs_dir_reflush_skip, int, 0644);
MODULE_PARM_DESC(dir_reflush_skip,
                 "Skip an xfsaild reflush of an already-destaged clean dir "
                 "DATA/leaf buffer while holding the owner dir EX (prevents "
                 "the dir_reuse stale-reflush durable dirent loss) "
                 "(1=on default, 0=off)");

/*
 * — the SYNTHESIS of (zombie-reflush mechanism) and
 * (bgen<dir_gen prior-tenure discriminator).  Skip an xfsaild reflush of
 * a CLEAN, already-destaged, in-AIL dir buffer that this EX holder last READ in
 * a PRIOR tenure (b_mxfs_dir_gen < i_dlm_dir_gen) — its cached image is
 * superseded by a peer's durable add and re-writing it durably reverts that add
 * (the 8/tcp dir_reuse readdir=799 loss).  No disk content-compare (immune to
 * the reused-daddr ghost false-skip that sank dataclobber>=2); keyed on the
 * tenure-gen (not !XBF_DONE, which sank dir_reflush_skip); emulates a clean
 * ioend (retires the BLI, advances the log tail — no defer/deadlock unlike
 * dir_ail_defer).  Full reasoning at the arm in mxfs_buf_xfsaild_skip_dir_write.
 * DEFAULT 0 while A/B-validated; flip to 1 once proven on 8/tcp dir_reuse.
 */
int mxfs_dir_tenure_reflush_skip;
module_param_named(dir_tenure_reflush_skip, mxfs_dir_tenure_reflush_skip,
                   int, 0644);
MODULE_PARM_DESC(dir_tenure_reflush_skip,
                 "Skip an xfsaild reflush of a clean destaged in-AIL dir buffer "
                 "whose b_mxfs_dir_gen < owner i_dlm_dir_gen (prior-tenure "
                 "zombie reflush of a superseded image) while holding the dir "
                 "EX (1=on, 0=off default)");

/* ─── AG-metadata coherency hooks ─── */

/*
 * Stale every AG-metadata buffer (matched by b_ops) cached in the
 * given perag's xfs_buf_cache.  Called on a fresh DLM AG-lock
 * acquire: a peer may have modified AGF/AGI/AGFL/btree blocks while
 * we did not hold the lock, so any cached copy on this node is
 * potentially stale and must be re-read from disk on next access.
 *
 * Safe at this point because:
 *  - We just won the DLM EX grant; no peer can be writing now.
 *  - Our deferred-release machinery guarantees that any AG-metadata
 *    buffer we previously dirtied has completed writeback (and the
 *    DLM was actually released) before this fresh acquire could
 *    happen — so staling discards no un-persisted work of ours.
 *  - We filter by b_ops to avoid touching dir/attr/symlink buffers
 *    (which are protected by per-inode DLM locks, not the AG lock)
 *    and avoid cluster init buffers (handled by alloc_buflist).
 */
/*
 * (design review step-4a review item 2/5) — report what the walk could NOT
 * invalidate.
 *
 * Every `continue` below leaves a buffer in pag_bcache with XBF_DONE set and
 * this node's older content in it.  That is deliberately conservative (the
 * alternative — clearing DONE on un-destaged committed content — is the proven
 * P47/P131 bnobt lost-update), but it means the AG's cached view SURVIVES the
 * walk.  Callers that use the walk to declare "this AG is no longer cached by
 * us" (peer-joined transition, mount recovery barrier) must not do so when
 * that happened, or a later writeback of the retained buffer publishes over
 * whatever the peer — or a foreign-slice replay — put there in the meantime.
 *
 * Returns the total number of retained buffers; *ag_preserved (optional)
 * receives the AG-METADATA subset, which is what the pag lineage flags govern.
 */
/*
 * (D-0353): does this AG-metadata buffer still carry THIS node's
 * committed-but-not-landed content?  pinned = the CIL window (committed,
 * bli attached, DIRTY and IN_AIL both clear — exactly the state P131 caught);
 * bli DIRTY = logged in a transaction not yet through commit; bli IN_AIL =
 * committed, home write not complete; _XBF_DELWRI_Q = queued for that write.
 * Readable under b_lock (the spinlock) without the buffer semaphore.
 */
static bool
mxfs_agmeta_buf_unlanded(
	struct xfs_buf		*bp)
{
	struct xfs_buf_log_item	*bip = READ_ONCE(bp->b_log_item);

	if (xfs_buf_ispinned(bp))
		return true;
	if (bp->b_flags & _XBF_DELWRI_Q)
		return true;
	if (bip && (test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags) ||
		    test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)))
		return true;
	return false;
}

/*
 * (D-0353, design-consult ruling Q2): the fresh-acquire PREFLIGHT.  A dry
 * walk over the AG's cached buffers that stales nothing and reports the first
 * AG-metadata buffer still carrying un-landed local content.  Run BEFORE the
 * staling walk so the decision is all-or-nothing: either every AG-meta buffer
 * is clean and the walk proceeds, or the filesystem shuts down with its
 * cached view intact (no partial invalidation, no home writes issued).
 */
static unsigned int
mxfs_dlm_agmeta_preflight(
	struct xfs_perag	*pag,
	xfs_daddr_t		*first_daddr,
	const char		**first_ops)
{
	struct rhashtable_iter	iter;
	struct xfs_buf		*bp;
	unsigned int		unlanded = 0;

	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			bool hit;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (!mxfs_buf_is_ag_metadata(bp))
				continue;
			spin_lock(&bp->b_lock);
			hit = bp->b_hold > 0 && !(bp->b_flags & XBF_STALE) &&
			      mxfs_agmeta_buf_unlanded(bp);
			spin_unlock(&bp->b_lock);
			if (!hit)
				continue;
			if (!unlanded) {
				*first_daddr = bp->b_maps[0].bm_bn;
				*first_ops =
				    bp->b_ops == &xfs_agf_buf_ops ? "agf" :
				    bp->b_ops == &xfs_agi_buf_ops ? "agi" :
				    bp->b_ops == &xfs_agfl_buf_ops ? "agfl" :
				    bp->b_ops == &xfs_bnobt_buf_ops ? "bnobt" :
				    bp->b_ops == &xfs_cntbt_buf_ops ? "cntbt" :
				    bp->b_ops == &xfs_inobt_buf_ops ? "inobt" :
				    bp->b_ops == &xfs_finobt_buf_ops ? "finobt" :
				    "agmeta";
			}
			unlanded++;
		}
		rhashtable_walk_stop(&iter);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);
	return unlanded;
}

unsigned int
mxfs_dlm_invalidate_ag_meta(
	struct xfs_perag	*pag,
	unsigned int		*ag_preserved)
{
	struct rhashtable_iter	iter;
	struct xfs_buf		*bp;
	unsigned int		staled = 0;
	/* (D-0353): NULL ag_preserved = the fresh-acquire caller
	 * (fail closed); non-NULL = a census caller (join barrier, recovery
	 * barrier) that RETAINS un-landed buffers and retries the destage. */
	bool			fresh_caller = (ag_preserved == NULL);
	bool			refused = false;
	unsigned int		ag_pres = 0;	/* AG-meta views retained */
	unsigned int		ino_pres = 0;	/* inode-cluster views retained */
	struct mxfs_v5_dlm	*p14_dlm = pag_mount(pag)->m_mxfs_dlm;
	int			p14_slot = p14_dlm ?
				   mxfs_v5_dlm_get_node_slot(p14_dlm) : -1;
	/* P22-INSTR per-acquire walk census */
	unsigned int		p22_total = 0;
	unsigned int		p22_null_ops = 0;
	unsigned int		p22_bnobt = 0, p22_cntbt = 0;
	unsigned int		p22_agf = 0, p22_agi = 0, p22_agfl = 0;
	unsigned int		p22_inobt = 0, p22_finobt = 0;
	unsigned int		p22_inode = 0, p22_other = 0;
	unsigned int		p22_null_stale = 0;

	if (fresh_caller && READ_ONCE(mxfs_agmeta_inval_enforce)) {
		xfs_daddr_t	pf_daddr = 0;
		const char	*pf_ops = "?";
		unsigned int	pf_n = mxfs_dlm_agmeta_preflight(pag, &pf_daddr,
								   &pf_ops);

		if (pf_n) {
			xfs_alert(pag_mount(pag),
				"P131-INVAL-REFUSED agno=%u unlanded=%u first=%s@%lld — fresh acquire found this node's committed-but-unlanded AG metadata in cache; invalidating would discard it (silent lost update / double allocation). Nothing staled; shutting down",
				pag_agno(pag), pf_n, pf_ops, (long long)pf_daddr);
			xfs_force_shutdown(pag_mount(pag),
					   SHUTDOWN_CORRUPT_INCORE);
			return 0;
		}
	}

	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			const char	*p14_ops_name = "?";
			bool		p14_is_agmeta;
			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (refused)
				break;

			p14_is_agmeta = mxfs_buf_is_ag_metadata(bp);
			p22_total++;
			if (!bp->b_ops) {
				p22_null_ops++;
				if (bp->b_flags & XBF_STALE)
					p22_null_stale++;
			} else if (bp->b_ops == &xfs_inode_buf_ops ||
				   bp->b_ops == &xfs_inode_buf_ra_ops) {
				p22_inode++;
			} else if (p14_is_agmeta) {
				if (bp->b_ops == &xfs_agf_buf_ops) {
					p14_ops_name = "agf"; p22_agf++;
				} else if (bp->b_ops == &xfs_agi_buf_ops) {
					p14_ops_name = "agi"; p22_agi++;
				} else if (bp->b_ops == &xfs_agfl_buf_ops) {
					p14_ops_name = "agfl"; p22_agfl++;
				} else if (bp->b_ops == &xfs_bnobt_buf_ops) {
					p14_ops_name = "bnobt"; p22_bnobt++;
				} else if (bp->b_ops == &xfs_cntbt_buf_ops) {
					p14_ops_name = "cntbt"; p22_cntbt++;
				} else if (bp->b_ops == &xfs_inobt_buf_ops) {
					p14_ops_name = "inobt"; p22_inobt++;
				} else if (bp->b_ops == &xfs_finobt_buf_ops) {
					p14_ops_name = "finobt"; p22_finobt++;
				} else if (bp->b_ops == &xfs_rmapbt_buf_ops) {
					p14_ops_name = "rmapbt";
				} else if (bp->b_ops == &xfs_refcountbt_buf_ops) {
					p14_ops_name = "refcbt";
				}
			} else {
				p22_other++;
			}

			{
				bool is_inode_buf =
					bp->b_ops == &xfs_inode_buf_ops ||
					bp->b_ops == &xfs_inode_buf_ra_ops;

				if (!mxfs_buf_is_ag_metadata(bp) &&
				    !is_inode_buf)
					continue;

				/*
				 * v0.3.28 (sess18): for AG-meta bufs, do NOT
				 * skip on BLI attached or on delwri-queued.
				 * The original rationale ("cached-AG release
				 * flushes those before peer acquires") is
				 * empirically wrong for AGI specifically: the
				 * IN-MEMORY content of the buf was last written
				 * by US (before yield), and even though the
				 * disk has since been modified by peer, our
				 * cached buf retains our prior content.  Next
				 * xfs_read_agi returns cached buf → stale view
				 * → xfs_iunlink_insert reads stale agi_unlinked
				 * → "next_agino == agino" corruption (sess18
				 * iter-4 H1 family).
				 *
				 * Solution: stale ALL AG-meta bufs unconditionally.
				 * For inode cluster bufs, keep the BLI-attached
				 * skip (avoids racing concurrent iflush mid-pack);
				 * we still stale even when b_li_list non-empty.
				 *
				 * If a BLI is attached at stale time, xfs_buf_stale
				 * removes the BLI from AIL and frees it.  The
				 * cached-AG release path's drain (Phase-2b) ran
				 * just before peer's hold, so any in-flight write
				 * has either completed or our drain submitted it.
				 */
				if (is_inode_buf && READ_ONCE(bp->b_log_item)) {
					if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
						mxfs_probe("P14-INSTR realns=%llu slot=%d agno=%u blkno=%llu ops=inode verdict=SKIP-bli-unlocked\n",
							(unsigned long long)ktime_get_real_ns(),
							p14_slot, pag_agno(pag),
							(unsigned long long)bp->b_maps[0].bm_bn);
					ino_pres++;
					continue;
				}
				/*
				 * v0.3.81 attempted skip-on-bli for bnobt/cntbt — made
				 * things worse (avg 3.2 / 5 runs vs v0.3.80's ~7).  Skip
				 * prevents seeing peer's modifications via cache miss
				 * → still showing local stale state.  Reverted v0.3.82.
				 */
			}

			/*
			 * Pin the buffer so it cannot be freed while we
			 * try to lock it.  b_hold is a plain unsigned int
			 * protected by b_lock (matches the static
			 * xfs_buf_try_hold pattern in xfs_buf.c); skip
			 * buffers whose hold count has already dropped to
			 * zero (in the process of being freed).
			 */
			{
				bool got = false;

				spin_lock(&bp->b_lock);
				if (bp->b_hold > 0) {
					bp->b_hold++;
					got = true;
				} else if (p14_is_agmeta) {
					/*
					 * FIX: b_hold==0 AG-meta buffer.  We
					 * cannot bump+lock it for a full xfs_buf_stale,
					 * but the OLD code just skipped it — leaving a
					 * cached buffer with XBF_DONE + STALE content
					 * that a later lookup reuses as-is.  PROVEN:
					 * the EX-acquire walk logged SKIP-no-hold for
					 * the AGI (daddr 2087322) 1.6ms before
					 * xfs_iunlink_remove_inode read it stale
					 * (P71: agi_disk_differs=1) → AGI unlinked-list
					 * corruption + FS shutdown under 4-node rename.
					 * No active holder (b_hold==0) means no one is
					 * using the content, so clear XBF_DONE (+
					 * _XBF_FUA_FRESH so the re-read goes FUA) under
					 * b_lock: the next access (cached reuse) sees
					 * !DONE and re-reads the peer's committed block.
					 *
					 * FIX: but NOT if this buffer carries
					 * un-destaged THIS-node committed content
					 * (DIRTY / IN_AIL / pinned / delwri).  Clearing
					 * DONE then would make the next FUA re-read REVERT
					 * the buffer to the pre-commit on-disk version (our
					 * allocation not yet destaged) — the bnobt
					 * lost-update → unmount "ltbno+ltlen>bno"
					 * double-free.  Mirrors the proven guard in
					 * mxfs_ag_meta_invalidate_stale (this is its missing
					 * sibling).  An IN_AIL buffer is this-node-
					 * authoritative-ahead-of-disk; leave DONE set and let
					 * its writeback complete.
					 */
					{
						struct xfs_buf_log_item *p47bip =
							bp->b_log_item;
						bool p47_keep = (p47bip &&
						    (test_bit(XFS_LI_DIRTY, &p47bip->bli_item.li_flags) ||
						     test_bit(XFS_LI_IN_AIL, &p47bip->bli_item.li_flags))) ||
						    xfs_buf_ispinned(bp) ||
						    (bp->b_flags & _XBF_DELWRI_Q);
						if (p47_keep) {
							mxfs_probe_ratelimited("mxfs: P47-INVAL-SKIP-INAIL agno=%u daddr=%lld ops=%s flags=0x%x (b_hold==0; un-destaged committed buf — NOT reverting)\n",
								pag_agno(pag),
								(long long)bp->b_maps[0].bm_bn,
								p14_ops_name, bp->b_flags);
							ag_pres++;
						} else {
							bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
						}
					}
				}
				spin_unlock(&bp->b_lock);
				if (!got) {
					if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
					    p14_is_agmeta)
						mxfs_probe("P14-INSTR realns=%llu slot=%d agno=%u blkno=%llu ops=%s verdict=SKIP-no-hold-INVAL\n",
							(unsigned long long)ktime_get_real_ns(),
							p14_slot, pag_agno(pag),
							(unsigned long long)bp->b_maps[0].bm_bn,
							p14_ops_name);
					/*
					 * item 2/5: a b_hold==0 INODE buffer gets
					 * no treatment at all here (the DONE-clear above
					 * is AG-meta only), so its cached view survives
					 * intact.
					 */
					if (!p14_is_agmeta)
						ino_pres++;
					continue;
				}
			}

			/*
			 * Try-lock only — a buffer currently held by
			 * another in-flight transaction on this node
			 * cannot be one a peer modified (we hold EX), so
			 * skipping is safe.  In practice on fresh acquire
			 * no other thread on this AG should be active.
			 */
			if (!xfs_buf_trylock(bp)) {
				/*
				 * FIX: at a FRESH acquire a peer just
				 * modified this AG, so EVERY cached AG-meta buffer
				 * is potentially stale and MUST be invalidated.
				 * The old code SKIPPED a trylock-fail buffer —
				 * PROVEN to leave the AGI stale: P14 ops=agi
				 * verdict=SKIP-trylock-fail immediately preceded
				 * P71 agi_disk_differs=1 → xfs_iunlink_remove_inode
				 * read a stale (peer-behind) AGI → corruption +
				 * shutdown.  The lock holder here cannot be a live
				 * transaction modifying this AG (we only just
				 * acquired the AG-DLM; modifications require it) —
				 * it is async writeback / I/O completion of a PRIOR
				 * epoch's content.  So force-clear XBF_DONE (+
				 * _XBF_FUA_FRESH) under b_lock (the spinlock, not the
				 * held buffer semaphore): the next access re-reads
				 * the peer's committed block via FUA.  Clearing a
				 * flag under b_lock does not touch b_addr, so it
				 * does not disturb an in-flight bio; a concurrent
				 * READ completion that re-sets XBF_DONE just leaves
				 * fresh content (also fine).
				 */
				if (p14_is_agmeta) {
					/*
					 * FIX: same IN_AIL/dirty/pinned guard as
					 * the b_hold==0 branch above.  A trylock-fail
					 * buffer that is IN_AIL/dirty/pinned carries our
					 * own un-destaged committed content; clearing DONE
					 * → next FUA re-read reverts it to the pre-commit
					 * disk version = bnobt lost-update → corruption.
					 */
					struct xfs_buf_log_item *p47bip;
					bool p47_keep;
					spin_lock(&bp->b_lock);
					p47bip = bp->b_log_item;
					p47_keep = (p47bip &&
					    (test_bit(XFS_LI_DIRTY, &p47bip->bli_item.li_flags) ||
					     test_bit(XFS_LI_IN_AIL, &p47bip->bli_item.li_flags))) ||
					    xfs_buf_ispinned(bp) ||
					    (bp->b_flags & _XBF_DELWRI_Q);
					if (!p47_keep)
						bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
					spin_unlock(&bp->b_lock);
					if (p47_keep)
						ag_pres++;
					if (p47_keep)
						mxfs_probe_ratelimited("mxfs: P47-INVAL-SKIP-INAIL agno=%u daddr=%lld ops=%s flags=0x%x (trylock-fail; un-destaged committed buf — NOT reverting)\n",
							pag_agno(pag),
							(long long)bp->b_maps[0].bm_bn,
							p14_ops_name, bp->b_flags);
					if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
						mxfs_probe("P14-INSTR realns=%llu slot=%d agno=%u blkno=%llu ops=%s verdict=SKIP-trylock-fail-INVAL b_log_item=%p flags=0x%x li_empty=%d\n",
							(unsigned long long)ktime_get_real_ns(),
							p14_slot, pag_agno(pag),
							(unsigned long long)bp->b_maps[0].bm_bn,
							p14_ops_name,
							bp->b_log_item,
							bp->b_flags,
							list_empty_careful(&bp->b_li_list));
				} else {
					/*
					 * item 2/5: trylock-fail on an INODE
					 * cluster buffer does nothing at all — the
					 * cached view survives.
					 */
					ino_pres++;
				}
				xfs_buf_rele(bp);
				continue;
			}

			/*
			 * Re-check under the buffer lock — the bli may
			 * have been attached or delwri queue set after we
			 * read the unlocked snapshot above.  Inode cluster
			 * buffers are staled even with a non-empty
			 * b_li_list: see commentary above.
			 */
			/*
			 * v0.3.36: the previous condition skipped AG-meta
			 * bufs whenever ANY bli was attached.  For pure AG-meta bufs
			 * (bnobt/cntbt/agf/agi/agfl/inobt/finobt/...), having bli
			 * attached is the NORMAL state after we logged a modification
			 * in our prior trans.  Skipping those means our local cached
			 * buf retains pre-release content while peer's modifications
			 * sit on disk un-merged.  Next bnobt scan via the cached buf
			 * sees stale free-space → "ltbno + ltlen > bno" or the
			 * symmetric RIGHT-FAIL.
			 *
			 * v0.3.28 documented this fix at the unlocked check
			 * (lines ~1934) but the under-lock check below was left as-is.
			 * Now consistent: AG-meta bufs are ALWAYS staled regardless of
			 * b_log_item / b_li_list / _XBF_DELWRI_Q state.  Inode cluster
			 * bufs keep the bli-attached skip (avoids racing concurrent
			 * iflush mid-pack — different rationale, see comment above).
			 */
			{
				bool is_inode_buf =
					bp->b_ops == &xfs_inode_buf_ops ||
					bp->b_ops == &xfs_inode_buf_ra_ops;

				if (is_inode_buf && bp->b_log_item) {
					if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
						mxfs_probe("P14-INSTR realns=%llu slot=%d agno=%u blkno=%llu ops=inode verdict=SKIP-bli-locked b_log_item=%p flags=0x%x\n",
							(unsigned long long)ktime_get_real_ns(),
							p14_slot, pag_agno(pag),
							(unsigned long long)bp->b_maps[0].bm_bn,
							bp->b_log_item,
							bp->b_flags);
					ino_pres++;
					xfs_buf_unlock(bp);
					xfs_buf_rele(bp);
					continue;
				}
			}

			/*
			 * P79-INSTR: the walk stales AG-meta
			 * UNCONDITIONALLY.  xfs_buf_stale on a buffer whose BLI
			 * is still in the AIL (committed but not yet written
			 * back) removes the BLI from the AIL and DISCARDS the
			 * committed update — a lost update that, once the
			 * sibling tree's update IS written, leaves the on-disk
			 * bno/cnt trees inconsistent (P70 disk_differs=0
			 * variant).  At a genuine fresh acquire there should be
			 * NO in-AIL AG-meta for this AG (the prior release
			 * drained it), so this firing pinpoints a release-drain
			 * gap.  Fires only on the anomaly.
			 */
			if (p14_is_agmeta && bp->b_log_item &&
			    test_bit(XFS_LI_IN_AIL,
				     &bp->b_log_item->bli_item.li_flags))
				mxfs_probe("mxfs: P79-INSTR WALK-STALES-in-AIL agno=%u blkno=%llu ops=%s flags=0x%x dirty=%d pin=%d\n",
					pag_agno(pag),
					(unsigned long long)bp->b_maps[0].bm_bn,
					p14_ops_name, bp->b_flags,
					test_bit(XFS_LI_DIRTY,
						 &bp->b_log_item->bli_item.li_flags) ? 1 : 0,
					atomic_read(&bp->b_pin_count));

			/*
			 * P131-INVAL-DISCARD (design review probe 2).
			 * Superset of P79: the in-AIL test alone MISSES the
			 * CIL-resident window (bli attached / li_list non-empty /
			 * pinned but AIL insertion not yet run) and the delwri
			 * case.  Staling ANY of those discards a committed-but-
			 * not-home free-space update with no write ever issued —
			 * the silent bnobt lost-update (disk stays coherently
			 * pre-alloc; every write-side probe silent).  Log-only.
			 */
			if (p14_is_agmeta &&
			    (bp->b_log_item ||
			     !list_empty_careful(&bp->b_li_list) ||
			     xfs_buf_ispinned(bp) ||
			     (bp->b_flags & _XBF_DELWRI_Q))) {
				struct xfs_buf_log_item *p131bip = bp->b_log_item;
				static atomic_t p131_n = ATOMIC_INIT(0);
				int p131_seq = atomic_inc_return(&p131_n);

				mxfs_probe("mxfs: P131-INVAL-DISCARD agno=%u daddr=%lld ops=%s flags=0x%x bli=%d li_nonempty=%d dirty=%d in_ail=%d pin=%d delwri=%d comm=%s realns=%llu\n",
					pag_agno(pag),
					(long long)bp->b_maps[0].bm_bn,
					p14_ops_name, bp->b_flags,
					p131bip ? 1 : 0,
					!list_empty_careful(&bp->b_li_list) ? 1 : 0,
					(p131bip && test_bit(XFS_LI_DIRTY,
						&p131bip->bli_item.li_flags)) ? 1 : 0,
					(p131bip && test_bit(XFS_LI_IN_AIL,
						&p131bip->bli_item.li_flags)) ? 1 : 0,
					atomic_read(&bp->b_pin_count),
					(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
					current->comm,
					(unsigned long long)ktime_get_real_ns());
				if (p131_seq <= 8)
					mxfs_probe_stack();
			}

			/*
			 * (D-0353, design-consult ruling Q2): the locked branch
			 * no longer discards un-landed local content.  Census
			 * callers RETAIN it (same verdict as the b_hold==0 and
			 * trylock-fail branches, P47) and retry the destage; the
			 * fresh-acquire caller — which already passed the dry
			 * preflight, so this is a race with a local commit — shuts
			 * down and stops staling.
			 */
			if (p14_is_agmeta && mxfs_agmeta_buf_unlanded(bp)) {
				if (!fresh_caller ||
				    !READ_ONCE(mxfs_agmeta_inval_enforce)) {
					mxfs_probe_ratelimited("mxfs: P47-INVAL-SKIP-INAIL agno=%u daddr=%lld ops=%s flags=0x%x (locked; un-destaged committed buf — retained, caller retries the destage)\n",
						pag_agno(pag),
						(long long)bp->b_maps[0].bm_bn,
						p14_ops_name, bp->b_flags);
					ag_pres++;
					xfs_buf_unlock(bp);
					xfs_buf_rele(bp);
					continue;
				}
				xfs_alert(pag_mount(pag),
					"P131-INVAL-REFUSED agno=%u daddr=%lld ops=%s pin=%d — committed-but-unlanded AG metadata reached the staling walk after a clean preflight; refusing to discard it; shutting down",
					pag_agno(pag),
					(long long)bp->b_maps[0].bm_bn,
					p14_ops_name,
					atomic_read(&bp->b_pin_count));
				xfs_buf_unlock(bp);
				xfs_buf_rele(bp);
				refused = true;
				xfs_force_shutdown(pag_mount(pag),
						   SHUTDOWN_CORRUPT_INCORE);
				break;
			}

			xfs_buf_stale(bp);
			/*
			 * v0.3.99: xfs_buf_stale does NOT clear
			 * XBF_DONE despite the apparent assumption (e.g.,
			 * comment in mxfs_dlm_reload_inode at line 496).
			 * If XBF_DONE remains, subsequent xfs_buf_get may
			 * reuse the staled buf without re-reading from disk
			 * — peer's modifications never picked up → bnobt
			 * LEFT/RIGHT-FAIL.  Force-clear XBF_DONE here.
			 */
			bp->b_flags &= ~XBF_DONE;
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
			    p14_is_agmeta)
				mxfs_probe("P14-INSTR realns=%llu slot=%d agno=%u blkno=%llu ops=%s verdict=STALED flags=0x%x\n",
					(unsigned long long)ktime_get_real_ns(),
					p14_slot, pag_agno(pag),
					(unsigned long long)bp->b_maps[0].bm_bn,
					p14_ops_name,
					bp->b_flags);
			xfs_buf_unlock(bp);
			xfs_buf_rele(bp);
			staled++;
		}
		rhashtable_walk_stop(&iter);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);

	if (staled)
		mxfs_pal_log(MXFS_LOG_DEBUG,
			"mxfs: AG %u staled %u AG-meta buffers on fresh acquire",
			pag_agno(pag), staled);

	/*
	 * v0.3.105: blkdev_issue_flush after invalidate.
	 * Ensures any pending writes from peer side are committed
	 * to backing storage before we read fresh.
	 */
	if (staled)
		mxfs_blkdev_flush_epoch(pag_mount(pag));
	mxfs_idbg("mxfs: P22-INSTR walk-census slot=%d agno=%u total=%u "
		"agf=%u agi=%u agfl=%u bnobt=%u cntbt=%u inobt=%u finobt=%u "
		"inode=%u other=%u null_ops=%u null_stale=%u staled=%u\n",
		p14_slot, pag_agno(pag), p22_total,
		p22_agf, p22_agi, p22_agfl, p22_bnobt, p22_cntbt,
		p22_inobt, p22_finobt, p22_inode, p22_other,
		p22_null_ops, p22_null_stale, staled);

	/*
	 * v0.3.21: Clear pag init flags so that the next xfs_alloc_read_agf /
	 * xfs_ialloc_read_agi calls re-populate pag->pagf_* / pag->pagi_*
	 * fields from the freshly-read disk buffer.  Without this, those
	 * functions early-return when xfs_perag_initialised_agf/agi() is true,
	 * leaving pag fields stale relative to a peer's modifications since
	 * we last released the AG.
	 *
	 * Symptom captured by P15 LEFT-FAIL at v0.3.20:
	 *   agf_freeblks=191509 (on-disk via agbp->b_addr, current)
	 *   pagf_freeblks=257029 (in-memory pag, stale by request len)
	 * The 65520 delta == request len indicates the in-memory pag was
	 * frozen at a state preceding the peer's allocation that consumed
	 * those blocks.  bnobt scan then trips bno+len > gtbno because the
	 * stale pag-derived caller logic disagrees with the live agf btrees.
	 *
	 * Same family as session 13's H1 ("AGI SKIP-survives-stale") audit.
	 */
	clear_bit(XFS_AGSTATE_AGF_INIT, &pag->pag_opstate);
	clear_bit(XFS_AGSTATE_AGI_INIT, &pag->pag_opstate);
	mxfs_idbg("mxfs: P17-INSTR pag-init-cleared agno=%u\n", pag_agno(pag));

	/*
	 * item 2/5: hand the retained-view census back.  ag_pres is the
	 * subset the pag lineage flags are allowed to be cleared on; ino_pres
	 * is reported so a caller that cares about inode-cluster coherency
	 * (the foreign-replay barrier does) can refuse to publish.
	 */
	if (ag_pres || ino_pres)
		mxfs_probe_ratelimited(
			"mxfs: P232-INVAL-INCOMPLETE agno=%u staled=%u retained: ag_meta=%u inode=%u — cached view survives this walk\n",
			pag_agno(pag), staled, ag_pres, ino_pres);
	if (ag_preserved)
		*ag_preserved = ag_pres;
	return ag_pres + ino_pres;
	/*
	 * v0.3.72 attempted blkdev_issue_flush here — caused DLM timeouts on
	 * inode 128.  invalidate_ag_meta runs from contexts that include
	 * mxfs_ag_dlm_lock fresh-acquire path.  blkdev_issue_flush from
	 * those contexts blocks on outstanding writes that include our own
	 * b_iodone-driven AG-DLM release sequencing → cascading timeout.
	 * Reverted.
	 */
}


/*
 * Identify AG-metadata buffers by their b_ops.  These are the buffer
 * types that contain per-AG state which a peer reads from the home
 * block location after acquiring the AG DLM lock — AGF, AGI, AGFL,
 * and the per-AG btree blocks (free-space, inode, rmap, refcount).
 *
 * Other logged buffers (dquot, dinode buffers, dir/attr blocks, etc.)
 * are NOT covered here: dquot/dinode have their own b_iodone hooks
 * already, and dir/attr blocks are protected by per-inode DLM locks,
 * not the AG lock.
 */
bool
mxfs_buf_in_fua_window(
	struct xfs_buf	*bp)
{
	struct xfs_perag	*pag;
	unsigned long		until;

	if (!bp || !bp->b_pag)
		return false;
	pag = bp->b_pag;
	until = READ_ONCE(pag->pag_dlm_fua_window_until);
	if (!until)
		return false;
	return time_before_eq(jiffies, until);
}

bool
mxfs_buf_is_ag_metadata(
	struct xfs_buf	*bp)
{
	const struct xfs_buf_ops *ops = bp->b_ops;

	if (!ops)
		return false;
	return ops == &xfs_agf_buf_ops    ||
	       ops == &xfs_agi_buf_ops    ||
	       ops == &xfs_agfl_buf_ops   ||
	       ops == &xfs_bnobt_buf_ops  ||
	       ops == &xfs_cntbt_buf_ops  ||
	       ops == &xfs_inobt_buf_ops  ||
	       ops == &xfs_finobt_buf_ops ||
	       ops == &xfs_rmapbt_buf_ops ||
	       ops == &xfs_refcountbt_buf_ops;
}

/*
 * — xfsaild AG-meta writeback interlock at the
 * iop_push layer (the DEFINITIVE fix for the held=1 P93/P124 bnobt/cntbt
 * revert-clobber that ~70 sessions of acquire/release/write-side band-aids
 * could not close).
 *
 * PROVEN root (this run): EVERY P93/P124 revert fired with on-disk held=1
 * and P125 (on-disk not-held assert) = 0.  That looked like "we revert while
 * holding the AG", which is impossible under correct exclusion — until you
 * separate the two checkpoints.  xfsaild's push DECISION (xfs_buf_item_push /
 * iop_push) happens while a PEER owns the AG (we released it, pag_dlm_cached=
 * false): a stale prior-tenure bnobt/cntbt BLI still lingers in OUR per-mount
 * AIL (the per-AG release drain is bounded and the BLI outlives writeback), so
 * xfsaild queues it for delwri write.  By the time the bio reaches
 * xfs_buf_submit (where P93/P124 sample state) we have RE-ACQUIRED the AG, so
 * the held check there reads held=1 — a pure timing artifact of the late
 * sample point.  The push itself reverted the peer's durable split while we
 * did NOT hold the AG.  The SAME stale-in-core buffer then poisons our own
 * allocator -> `ltbno+ltlen>bno` in-core double-free shutdown.
 *
 * Fix: at iop_push, if this is an AG-allocation-metadata buffer and we do NOT
 * currently hold the AG's DLM grant in-core (pag_dlm_cached / holders), xfsaild
 * MUST NOT write it — a peer owns the AG and our cached image is stale.
 * Invariant #1 (drain-before-release) guarantees every legitimate this-node
 * AG-meta change was made durable before we released, so the lingering BLI here
 * carries nothing we still need; the peer's on-disk image supersedes it.
 * Caller stales the buffer (removes the BLI from the AIL, the same mechanism
 * mxfs_dlm_invalidate_ag_meta relies on) and reports the push handled, so
 * xfsaild advances the log tail with NO I/O and the peer's allocation stands.
 * When we DO hold the AG (cached, steady state or demoting) our in-core IS
 * authoritative (fresh-acquire cold-read + our own mods, drained at release),
 * so the normal delwri write is correct and is left untouched — this also means
 * single-node / uncontended mounts (always cached) are completely unaffected,
 * so the log tail never pins on us.
 *
 * Scoped to the AG free-space + inode-alloc btrees and the AG headers (the
 * proven coherency-critical set); rmapbt/refcountbt are excluded (not used by
 * mkfs_mxfs's default geometry) and the inode CLUSTER buffer is excluded (its
 * coherency runs through a separate, working reload path).
 */
bool
mxfs_buf_xfsaild_skip_agmeta_write(struct xfs_buf *bp)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	const struct xfs_buf_ops *ops;

	if (!bp)
		return false;
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	ops = bp->b_ops;
	if (ops != &xfs_bnobt_buf_ops  &&
	    ops != &xfs_cntbt_buf_ops  &&
	    ops != &xfs_agf_buf_ops    &&
	    ops != &xfs_agfl_buf_ops   &&
	    ops != &xfs_agi_buf_ops    &&
	    ops != &xfs_inobt_buf_ops  &&
	    ops != &xfs_finobt_buf_ops)
		return false;
	pag = bp->b_pag;
	if (!pag)
		return false;
	/*
	 * Racy read of the in-core hold state is fine: the only UNSAFE error is
	 * a false "we hold it" (which would let a stale revert through), and
	 * pag_dlm_cached is set true on the acquire path and is true throughout
	 * the demote window (cleared only after mxfs_v5_dlm_ag_unlock).  A false
	 * "we don't hold it" merely forces a harmless cold re-read on next
	 * access.  So testing cached||holders is conservative in the safe
	 * direction.
	 */
	if (pag->pag_dlm_cached || pag->pag_dlm_holders > 0)
		return false;
	return true;
}

/*
 * (instrumented, zero_silent_loss residual) — the bmbt analogue of
 * mxfs_buf_xfsaild_skip_agmeta_write.
 *
 * Proven residual: a peer cold-reads a BTREE-format storm-dir's extent map
 * and trips `ir.loaded != if_nextents` (loaded < if_nextents) — the on-disk
 * bmbt LEAF holds FEWER records than the (atomically-consistent) dinode root +
 * di_nextents expect.  Reads hit the COHERENT SCST shared cache (fua_disable=1
 * default), so this is not a per-initiator read-cache artifact: a bmbt leaf
 * write genuinely lost records.  Same mechanism proved for AG-meta:
 * after this node released the dir's per-inode DLM grant (i_dlm_mode -> NL),
 * a stale prior-tenure bmbt BLI lingers in OUR AIL; xfsaild pushes it and
 * writes our OLDER leaf image over the peer's newer one in the shared cache,
 * reverting the records the peer added after we handed off.  bmbt blocks are
 * NOT AG-metadata, so the agmeta skip above never covered them.
 *
 * Fix: at iop_push, if this is a bmbt block whose owner is an in-core
 * DIRECTORY inode we no longer hold (i_dlm_mode == NL), do NOT write it — the
 * release drain (Invariant #1: mxfs_dir_flush_data_blocks before unlock) made
 * every legitimate this-node bmbt change durable before NL, so the lingering
 * BLI carries only a superseded prior-tenure image.  Caller stales it (drops
 * the BLI from the AIL, no I/O) so the peer's leaf stands.
 *
 * Scoped conservatively to avoid losing legitimate writeback:
 *  - only xfs_bmbt_buf_ops (the inode extent-map btree blocks);
 *  - only when the owner inode is IN-CORE and a DIRECTORY and provably
 *    released (NL).  A regular file, a dir we still hold (EX/PR), or an inode
 *    not in cache all fall through to the normal write — so single-node /
 *    uncontended mounts and all file writeback are completely unaffected.
 * Racy i_dlm_mode read is safe in the conservative direction: a false "we
 * still hold it" just lets the normal write run (status quo); only a false
 * "released" could over-stale, and that merely forces a cold re-read.
 */
bool
mxfs_buf_xfsaild_skip_bmbt_write(struct xfs_buf *bp)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint64_t		owner;
	bool			skip = false;

	if (!bp || bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr)
		return false;
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	owner = be64_to_cpu(((struct xfs_btree_block *)
			     bp->b_addr)->bb_u.l.bb_owner);
	if (owner == 0)
		return false;
	agno = XFS_INO_TO_AGNO(mp, owner);
	if (agno >= mp->m_sb.sb_agcount)
		return false;
	agino = XFS_INO_TO_AGINO(mp, owner);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return false;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (ip && ip->i_ino == owner && S_ISDIR(VFS_I(ip)->i_mode)) {
		if (ip->i_dlm_mode == MXFS_LOCK_NL) {
			/* Fully released: lingering BLI is a superseded image. */
			skip = true;
		} else if (bp->b_tenure_id != ip->i_mxfs_ex_grant_seq) {
			/*
			 * ROOT FIX for zero_silent_loss.
			 * TENURE-AUTHORITY gate for the bmbt leaf, mirroring the
			 * proven AG-meta b_tenure_id mechanism 
			 * and the inode P17B epoch-ghost guard.  The NL check
			 * above is INSUFFICIENT: a node that RE-ACQUIRES EX after a
			 * peer grew the dir still has its prior-tenure leaf BLI in
			 * the AIL (mode now EX, not NL), so xfsaild wrote that
			 * stale leaf (numrecs=N-1) over the peer's durable leaf at
			 * the SAME shared daddr — PROVEN by P66-LEAFWRITE
			 * (owner=131 comm=xfsaild, different nodes writing
			 * different counts to one daddr) -> on-disk di>leaf torn
			 * pair -> P59-IREAD-MISMATCH loaded=N-1 if_nextents=N ->
			 * EFSCORRUPTED shutdown, the whole 1600-dirent cascade.
			 * b_tenure_id is stamped at MODIFY time (mxfs_dir_bmbt_track
			 * from xfs_trans_log_buf) with the owner dir's EX-tenure
			 * epoch i_mxfs_ex_grant_seq; if it differs from the dir's
			 * CURRENT epoch the leaf was logged in a PRIOR tenure (we
			 * yielded EX and a peer advanced the leaf on disk), so its
			 * image is superseded.  Stale it (no I/O) so the peer's
			 * leaf stands.  A leaf genuinely modified THIS tenure has
			 * b_tenure_id == i_mxfs_ex_grant_seq and writes normally.
			 */
			skip = true;
		}
	}
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
	return skip;
}

/*
 * MODIFY-TIME tenure stamp for a directory's bmbt
 * (extent-map) buffers, the bmbt analogue of mxfs_ag_meta_track.
 * Called from xfs_trans_log_buf whenever a bmbt block is logged.  Records, in
 * the buffer's b_tenure_id, the EX-tenure epoch (owner dir's
 * i_mxfs_ex_grant_seq) under which this image was produced.  A bmbt block is
 * only ever modified while this node holds the owner dir EX, so the lookup
 * always hits (we hold the inode), and the stamp marks the buffer
 * this-tenure-authoritative.  mxfs_buf_xfsaild_skip_bmbt_write compares it to
 * the dir's CURRENT epoch to drop a superseded prior-tenure leaf instead of
 * clobbering a peer's durable image.  Reuses b_tenure_id (a bmbt block is
 * never AG-metadata, so the AG-meta stamping is disjoint).  No iodone / no
 * deferred-release counter (unlike mxfs_ag_meta_track) — bmbt release
 * durability is handled by mxfs_dir_bmbt_scan at unlock.
 */
void
mxfs_dir_bmbt_track(struct xfs_buf *bp)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint64_t		owner;

	if (!bp || bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr)
		return;
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	owner = be64_to_cpu(((struct xfs_btree_block *)
			     bp->b_addr)->bb_u.l.bb_owner);
	if (owner == 0)
		return;
	agno = XFS_INO_TO_AGNO(mp, owner);
	if (agno >= mp->m_sb.sb_agcount)
		return;
	agino = XFS_INO_TO_AGINO(mp, owner);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (ip && ip->i_ino == owner && S_ISDIR(VFS_I(ip)->i_mode)) {
		/*
		 * LAUNDERING DETECTOR (instrumented).  Run
		 * 072239Z movie (daddr=23025584): logged BACKWARD images land
		 * mid-run (nr=23 w/ later LSN over nr=25; test32 nr=30 logged
		 * at :58 against a 33/34 cluster) and re-growth sequences
		 * (test9 redoing 23->25) — a tenure's FIRST modify of a bmbt
		 * child it never re-read this tenure RMWs the prior-tenure
		 * content and this restamp marks it current — the gate
		 * is defeated by design from that instant.  Fire when the old
		 * stamp is from another tenure while the buffer still carries
		 * prior-tenure dirt (dirty/in-AIL): the exact laundering
		 * moment, naming node + daddr + numrecs.
		 */
		if (bp->b_tenure_id != ip->i_mxfs_ex_grant_seq &&
		    bp->b_log_item &&
		    (test_bit(XFS_LI_DIRTY,
			      &bp->b_log_item->bli_item.li_flags) ||
		     test_bit(XFS_LI_IN_AIL,
			      &bp->b_log_item->bli_item.li_flags))) {
			static atomic_t p67n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p67n) <= 2000)
				mxfs_probe("mxfs: P67-STALE-BASE-RMW owner=%llu daddr=%lld numrecs=%u old_tenure=%llu cur_tenure=%llu dirty=%d in_ail=%d comm=%s\n",
					(unsigned long long)owner,
					(long long)bp->b_maps[0].bm_bn,
					be16_to_cpu(((struct xfs_btree_block *)
						bp->b_addr)->bb_numrecs),
					(unsigned long long)bp->b_tenure_id,
					(unsigned long long)ip->i_mxfs_ex_grant_seq,
					test_bit(XFS_LI_DIRTY,
						 &bp->b_log_item->bli_item.li_flags) ? 1 : 0,
					test_bit(XFS_LI_IN_AIL,
						 &bp->b_log_item->bli_item.li_flags) ? 1 : 0,
					current->comm);
		}
		bp->b_tenure_id = ip->i_mxfs_ex_grant_seq;
	}
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
}

/*
 * extract the owner inode number from a dir3 namespace
 * buffer's self-describing header.  data/block/free carry xfs_dir3_blk_hdr;
 * leaf1/leafn/node carry xfs_da3_blkinfo.  Returns 0 (no owner) for any other
 * buffer type.  Mirrors mxfs_dir_buf_owned_by's header decode.
 */
uint64_t
mxfs_dir_buf_owner(struct xfs_buf *bp)
{
	const struct xfs_buf_ops *ops;

	if (!bp || !bp->b_addr)
		return 0;
	ops = bp->b_ops;
	if (ops == &xfs_dir3_data_buf_ops ||
	    ops == &xfs_dir3_block_buf_ops ||
	    ops == &xfs_dir3_free_buf_ops)
		return be64_to_cpu(((struct xfs_dir3_blk_hdr *)bp->b_addr)->owner);
	if (ops == &xfs_dir3_leaf1_buf_ops ||
	    ops == &xfs_dir3_leafn_buf_ops ||
	    ops == &xfs_da3_node_buf_ops)
		return be64_to_cpu(((struct xfs_da3_blkinfo *)bp->b_addr)->owner);
	return 0;
}

/*
 * MODIFY-TIME tenure stamp for a directory's DATA/leaf/block/
 * free/node buffers — the dir-dirent analogue of mxfs_dir_bmbt_track.
 * Called from xfs_trans_log_buf whenever a dir3 namespace block is logged.  A
 * dir block is only ever modified while this node holds the owner dir EX, so
 * the lookup always hits; the stamp marks the buffer this-tenure-authoritative.
 * mxfs_buf_xfsaild_skip_dir_write compares it to the dir's CURRENT epoch to drop
 * a superseded prior-tenure image rather than clobber a peer's durable dirent
 * block.  Reuses b_tenure_id (a dir block is never AG-metadata or bmbt, so the
 * three stamping domains are disjoint per buffer type).
 */
void
mxfs_dir_data_track(struct xfs_buf *bp)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint64_t		owner;

	if (!bp)
		return;
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	owner = mxfs_dir_buf_owner(bp);
	if (owner == 0)
		return;
	agno = XFS_INO_TO_AGNO(mp, owner);
	if (agno >= mp->m_sb.sb_agcount)
		return;
	agino = XFS_INO_TO_AGINO(mp, owner);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (ip && ip->i_ino == owner && S_ISDIR(VFS_I(ip)->i_mode)) {
		bp->b_tenure_id = ip->i_mxfs_ex_grant_seq;
		/* stamp the RELIABLE local release-epoch at modify.
		 * The writeback gate (mxfs_buf_xfsaild_skip_dir_write) skips a clean
		 * reflush whose stamp is older than ip->i_dlm_epoch (= we released the
		 * grant since, so a peer may have superseded this block). */
		bp->b_mxfs_relepoch = (uint32_t)ip->i_dlm_epoch;
		/*
		 * stamp the CURRENT incarnation on every
		 * dir block this node MODIFIES (logs) under the owner dir EX.  Uniform
		 * modify-time guarantee backing the writeback ABA guard
		 * (mxfs_buf_xfsaild_skip_dir_write): a block carrying THIS incarnation's
		 * logged work always has b_mxfs_dir_incarn == the live i_generation, so
		 * the guard never suppresses legitimate current work — only a buffer
		 * never re-modified since a prior incarnation (a dead ABA leftover at a
		 * reused daddr) keeps the stale stamp and is skipped.
		 */
		bp->b_mxfs_dir_incarn = VFS_I(ip)->i_generation;
		/*
		 * P33-LOGSTALE: a dir buffer being LOGGED (this is the
		 * xfs_trans_log_buf hook → BLI enters the AIL on commit) while
		 * XBF_DONE is CLEAR means it is being re-logged on an
		 * acquire-evict-invalidated (possibly STALE) base without a
		 * fresh re-read — the suspected in-tenure source of the zombie
		 * in-AIL BLI that later reflushes stale (dir_reuse 799).  Cheap
		 * (no I/O, under spinlock); gated by dirwr/instr. */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    !(bp->b_flags & XBF_DONE))
			mxfs_probe_ratelimited("mxfs: P33-LOGSTALE owner=%llu daddr=%lld mode=%d dgen=%u incarn=%u comm=%s — dir buffer LOGGED with XBF_DONE clear (re-log on invalidated base)\n",
				(unsigned long long)owner,
				(long long)bp->b_maps[0].bm_bn,
				ip->i_dlm_mode, ip->i_dlm_dir_gen,
				VFS_I(ip)->i_generation, current->comm);
	}
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
}

int mxfs_dir_zombie_push;	/* default 0 — fires 0x (the loss-write is
				 * the release-drain xfs_bwrite, not xfsaild iop_push). */
module_param_named(dir_zombie_push, mxfs_dir_zombie_push, int, 0644);
MODULE_PARM_DESC(dir_zombie_push,
		 "At xfs_buf_item_push (AIL), stale+retire (no I/O, no log-tail "
		 "starvation) a COHERENCY-INVALIDATED (XBF_DONE clear) dir DATA "
		 "buffer that is clean+destaged+in_ail — its content is on disk "
		 "(destaged) but stale (a peer superseded it), so writing it would "
		 "revert the peer's add (the dir_reuse readdir=799 zombie reflush). "
		 "(1=on default, 0=off)");

/*
 * (design review consult #2 — Layer 3): the LAST-LINE guard
 * for the dir_reuse readdir=799 durable dirent loss.  At the AIL push (iop_push,
 * BEFORE the buffer is queued for write) detect the proven "zombie BLI" state:
 *   owner is a shared multi-node dir; XBF_DONE is CLEAR (the buffer was
 *   coherency-invalidated by an evict/read-path so its cached content is
 *   non-authoritative); the BLI is in the AIL but CLEAN (!XFS_LI_DIRTY),
 *   unpinned, !delwri, and DESTAGED (b_mxfs_logged_seq==b_mxfs_written_seq).
 * Such a buffer has NO un-landed local work (destaged => its content already
 * reached disk) yet a lingering BLI would re-flush its now-STALE image over a
 * peer's durable add.  Caller (xfs_buf_item_push) xfs_buf_stale()s it (drops it
 * from the AIL with NO I/O, like the proven P126/P60 guards) and returns
 * XFS_ITEM_SUCCESS so xfsaild advances the log tail (no starvation).  The next
 * read cache-misses -> fresh FUA refetch of the peer's union.
 *
 * SAFE (not the suppression trap): a legit dir-content write at iop_push
 * is either DONE=1 (authoritative, read-then-modified) or UNDESTAGED
 * (lseq>wseq, un-landed — must write); BOTH are excluded by the !DONE +
 * destaged predicate, so no needed write is ever dropped.  Symmetric across
 * nodes: every node retires its reverting zombie, so each dirent made durable
 * by its creator's active write stays durable.
 */
bool
mxfs_dir_zombie_push_retire(struct xfs_buf *bp)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	struct xfs_buf_log_item	*bip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint64_t		owner;
	bool			retire = false;

	if (!mxfs_dir_zombie_push || !bp || !bp->b_addr)
		return false;
	/* only a coherency-invalidated, clean, destaged, in-AIL buffer */
	if (bp->b_flags & XBF_DONE)
		return false;
	if (bp->b_flags & _XBF_DELWRI_Q)
		return false;
	bip = bp->b_log_item;
	if (!bip || !test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))
		return false;
	if (test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags))
		return false;
	if (xfs_buf_ispinned(bp))
		return false;
	if (mxfs_dir_buf_is_undestaged(bp))	/* pinned || lseq!=wseq */
		return false;
	owner = mxfs_dir_buf_owner(bp);
	if (owner == 0)
		return false;			/* not a dir3 namespace buffer */
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	agno = XFS_INO_TO_AGNO(mp, owner);
	if (agno >= mp->m_sb.sb_agcount)
		return false;
	agino = XFS_INO_TO_AGINO(mp, owner);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return false;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	/* v2: scope to a dir held in-core (any mode).  Dropped the
	 * dir_gen>0 gate — a freshly rm+recreated dir (new inode#) can have
	 * dir_gen==0 yet still be the contended shared dir, so that gate made
	 * the guard miss (P33-PUSH-RETIRE=0).  multinode already gated above. */
	if (ip && ip->i_ino == owner && S_ISDIR(VFS_I(ip)->i_mode))
		retire = true;
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
	return retire;
}

/*
 * dir DATA/leaf-block analogue of
 * mxfs_buf_xfsaild_skip_bmbt_write — the FIX for 2/tcp
 * crash_consistency.  PROVEN vector (P35E-DIRWR): after this node
 * releases a dir's EX grant, a stale lingering dir-block BLI (li_empty=1,
 * in_ail=1) is re-flushed by xfsaild over the daddr the peer (or a later
 * tenure) already made durable -> the peer's dirents are durably lost.  The
 * bmbt guard already suppresses this for extent-map blocks; this is the same
 * mechanism for the dirent carriers (data/block/leaf/free/node).
 *
 * Skip predicate (identical rationale to the bmbt guard):
 *  - owner dir released (i_dlm_mode == NL): the release drain (Invariant #1)
 *    already made every legitimate this-node change durable before NL, so the
 *    lingering BLI is a superseded prior-tenure image; OR
 *  - owner dir still held (EX) but the buffer's modify-time tenure stamp
 *    (b_tenure_id) differs from the dir's CURRENT EX epoch: the image was
 *    logged in a PRIOR tenure (we yielded EX, a peer advanced the block on
 *    disk, we re-acquired) so it is superseded.
 *
 * Fills @info (when non-NULL) for the chokepoint detector regardless of the
 * skip decision, from the SAME single inode lookup.  Conservative: a dir we
 * still hold this tenure (EX/PR, tenure-match), a regular file, an owner not
 * in cache, and single-node mounts all fall through to the normal write.
 */
bool
mxfs_buf_xfsaild_skip_dir_write(struct xfs_buf *bp, struct mxfs_dir_skip_info *info)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint64_t		owner;
	bool			skip = false;

	if (info) {
		info->owner = 0;
		info->is_dir_buf = false;
		info->in_core = false;
		info->mode = -1;
		info->tenure_id = bp ? bp->b_tenure_id : 0;
		info->cur_epoch = 0;
		info->nl_released = false;
		info->tenure_mismatch = false;
		info->incarn_aba = false;
		info->reflush_skip = false;
		info->tenure_reflush = false;
		info->relepoch_skip = false;
		info->dir_gen = 0;
		info->loaded_gen = 0;
		info->buf_incarn = bp ? bp->b_mxfs_dir_incarn : 0;
		info->cur_incarn = 0;
		info->active_count = -1;
		info->realns = 0;
		info->cached_grant_gen = 0;
	}
	if (!bp || !bp->b_addr)
		return false;
	owner = mxfs_dir_buf_owner(bp);
	if (owner == 0)
		return false;			/* not a dir3 namespace buffer */
	if (info) {
		info->is_dir_buf = true;
		info->owner = owner;
		info->realns = ktime_get_real_ns();
		/*
		 * write-ordering trace: active dirents in the BLOCK being
		 * written (count-stale from the block tail, incl . + ..).  The
		 * decisive measurement for the durable stale-base clobber: which
		 * node writes the block with the peer's already-deleted dirents
		 * still present, and when.  Block format only (the uv/dir_reuse
		 * contended case); leaf/data left -1.
		 */
		if (bp->b_mount && bp->b_mount->m_dir_geo &&
		    (bp->b_ops == &xfs_dir3_block_buf_ops)) {
			struct xfs_dir2_data_hdr *h = bp->b_addr;
			struct xfs_dir2_block_tail *bt =
				xfs_dir2_block_tail_p(bp->b_mount->m_dir_geo, h);
			info->active_count = (int)be32_to_cpu(bt->count) -
					     (int)be32_to_cpu(bt->stale);
		}
	}
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	agno = XFS_INO_TO_AGNO(mp, owner);
	if (agno >= mp->m_sb.sb_agcount)
		return false;
	agino = XFS_INO_TO_AGINO(mp, owner);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return false;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (ip && ip->i_ino == owner && S_ISDIR(VFS_I(ip)->i_mode)) {
		if (info) {
			info->in_core = true;
			info->mode = ip->i_dlm_mode;
			info->cur_epoch = ip->i_mxfs_ex_grant_seq;
			info->dir_gen = ip->i_dlm_dir_gen;
			info->loaded_gen = ip->i_dlm_dir_loaded_gen;
			info->cur_incarn = VFS_I(ip)->i_generation;
			info->cached_grant_gen = ip->i_dlm_cached_grant_gen;
		}
		/*
		 * (PROVEN by iter3 P29-DATAWRITE
		 * CLOBBER): the dir inode# was freed+recreated (rm-rf + mkdir each
		 * round) so VFS_I(ip)->i_generation is the LIVE incarnation, but a
		 * dir DATA/leaf buffer at the reused daddr still carries the DEAD
		 * prior incarnation's stamp (b_mxfs_dir_incarn, set at read time in
		 * xfs_da_btree.c:3484).  xfsaild flushing that dead-incarnation image
		 * over the live block durably clobbers the current incarnation's
		 * dirents (PROVEN: node1_f1..f13 lost from block-0 @ daddr 120,
		 * bufincarn 1517736483 != live gen 2642423927, lookup_fail=0).  The
		 * read-path ABA bypass (xfs_da_btree.c:3484 + evict) only catches it
		 * on a READ; an xfsaild writeback never reads, so it slips through.
		 * Suppress the write here.  SAFE: a dead-incarnation buffer belongs
		 * to a FREED inode — its content is garbage that can only corrupt;
		 * dropping the bio (emulate clean ioend at the call site) loses
		 * nothing live.  Guard incarn != 0 so a freshly get_buf'd (unstamped)
		 * block of the CURRENT incarnation is never mistaken for a leftover
		 * (the fresh-block hazard).  Fires for NL/PR/EX alike — a dead
		 * incarnation is dead regardless of the current grant mode.
		 */
		if (bp->b_mxfs_dir_incarn != 0 &&
		    bp->b_mxfs_dir_incarn != VFS_I(ip)->i_generation) {
			skip = true;
			if (info)
				info->incarn_aba = true;
		}
		if (ip->i_dlm_mode == MXFS_LOCK_NL) {
			skip = true;
			if (info)
				info->nl_released = true;
		} else if (mxfs_dir_reflush_skip &&
			   ip->i_dlm_mode == MXFS_LOCK_EX &&
			   ip->i_dlm_dir_gen > 0 &&
			   !(bp->b_flags & XBF_DONE) &&
			   !(bp->b_flags & _XBF_DELWRI_Q) &&
			   bp->b_log_item &&
			   test_bit(XFS_LI_IN_AIL,
				    &bp->b_log_item->bli_item.li_flags) &&
			   !test_bit(XFS_LI_DIRTY,
				     &bp->b_log_item->bli_item.li_flags) &&
			   !mxfs_dir_buf_is_undestaged(bp)) {
			/*
			 * (PROVEN): EX-held, shared
			 * (dir_gen>0), CLEAN (BLI not dirty) and ALREADY-DESTAGED
			 * (lseq==wseq && !pinned) dir buffer => a pure redundant
			 * reflush whose cached image may have gone stale (a peer
			 * added a dirent during our prior NL window).  Re-writing
			 * it can only revert the peer's durable add; it carries
			 * NO un-landed local work.  Drop it (clean ioend retires
			 * the lingering BLI).  An active modify is dirty or
			 * undestaged (lseq>wseq) and is NEVER caught here, so our
			 * own adds are never lost.  Requires b_log_item != NULL,
			 * guaranteed because an in-AIL/xfsaild-pushed buffer
			 * always has its BLI attached.
			 */
			if (bp->b_log_item) {
				skip = true;
				if (info)
					info->reflush_skip = true;
			}
		} else if (mxfs_dir_tenure_reflush_skip &&
			   ip->i_dlm_mode == MXFS_LOCK_EX &&
			   ip->i_dlm_dir_gen > 0 &&
			   (bp->b_ops == &xfs_dir3_data_buf_ops ||
			    bp->b_ops == &xfs_dir3_block_buf_ops) &&
			   bp->b_log_item &&
			   test_bit(XFS_LI_IN_AIL,
				    &bp->b_log_item->bli_item.li_flags) &&
			   !test_bit(XFS_LI_DIRTY,
				     &bp->b_log_item->bli_item.li_flags) &&
			   !xfs_buf_ispinned(bp) &&
			   !(bp->b_flags & _XBF_DELWRI_Q) &&
			   !mxfs_dir_buf_is_undestaged(bp)) {
			/*
			 * sess37 (ccloop) — fix for the 8/tcp dir_reuse
			 * readdir=799 durable single/contiguous dirent loss.
			 * The loss write (PROVEN sess25/32/33, instrumented) is a
			 * "zombie BLI": a dir DATA/BLOCK buffer that is CLEAN
			 * (BLI !dirty), already-DESTAGED (b_mxfs_logged_seq ==
			 * b_mxfs_written_seq && !pinned: its last logged content
			 * is already on disk) yet still lingers in the AIL, and
			 * is re-pushed by background xfsaild under a genuine EX
			 * hold.  Because it is destaged it carries NO un-landed
			 * local work, but a PEER (during a brief window) wrote a
			 * newer image to the same daddr on disk; re-flushing our
			 * now-superseded in-core copy durably REVERTS the peer's
			 * dirent (the readdir=799 loss).  Skipping the write
			 * (emulate clean ioend at the call site -> RETIRES the
			 * zombie BLI -> the log tail advances) loses nothing live
			 * and stops the revert.
			 *
			 * Why this is safe where prior arms were not:
			 *  - destaged (lseq==wseq) is the key, NOT sess33's
			 *    !XBF_DONE (which CATASTROPHICALLY dropped fresh
			 *    undestaged writes).  A legit active write is DIRTY or
			 *    undestaged (lseq>wseq) -> EXCLUDED here.  Only a
			 *    buffer whose content is provably already on disk is
			 *    dropped, so no needed bytes are ever lost.
			 *  - NO disk content-compare -> immune to the reused-daddr
			 *    GHOST false-skip that sank dataclobber>=2.
			 *  - NO defer (XFS_ITEM_LOCKED) -> no log-tail starvation
			 *    deadlock unlike dir_ail_defer.
			 *  - DATA/BLOCK only (the dirent carriers).  Leaf/node/
			 *    free index blocks are NOT skipped — dropping those
			 *    breaks the da-btree mapping (sess37 v1 DABUF_MAP_HOLE
			 *    corruption); the dirents themselves live only in
			 *    DATA/BLOCK blocks so DATA coverage is sufficient.
			 *  - Gen-blind on purpose: the 8/tcp loss buffer is
			 *    stamped CURRENT gen (bgen==dir_gen, stale=0), so a
			 *    bgen<dir_gen gate misses it entirely (sess37 v1
			 *    P37=2x).  Destaged-zombie is the right discriminator.
			 * A destaged buffer whose BLI is still in the AIL is the
			 * anomaly itself (a completed write normally retires the
			 * BLI), so this fires only on the zombie, not normal IO.
			 */
			skip = true;
			if (info)
				info->tenure_reflush = true;
		} else if (bp->b_tenure_id != ip->i_mxfs_ex_grant_seq) {
			/*
			 * sess17 (ccloop, instrumented): the tenure-mismatch arm is
			 * recorded for the DETECTOR only — it must NOT drive a
			 * skip for dir blocks.  PROVEN false-positive: a
			 * freshly-created leaf during block->leaf conversion has
			 * its header owner unset at the first xfs_trans_log_buf,
			 * so mxfs_dir_data_track can't stamp it and b_tenure_id
			 * stays 0 != epoch on a LEGIT comm=dd write -> skipping
			 * it would drop the whole leaf (corruption, the sess23
			 * suppression-was-corruptor class).  Only the
			 * NL-released arm above is safe to enforce.
			 */
			if (info)
				info->tenure_mismatch = true;
		}
		/*
		 * PROVEN cross-node clobber gate (instrumented: xnode=1
		 * confirmed — wrcnt_max==buf_cnt, disk_cnt==buf_cnt+1, a PEER wrote
		 * the extra dirent).  A CLEAN dir buffer whose coherent image predates
		 * a grant RELEASE by THIS node (b_mxfs_relepoch < ip->i_dlm_epoch) is a
		 * stale pre-release snapshot; a peer may have superseded the block on
		 * the shared LUN since.  xfsaild flushing it durably REVERTS the peer's
		 * add — the dir_reuse readdir=799 single-dirent loss.  SAFE: the buffer
		 * is CLEAN (no un-checkpointed local work) and its content was already
		 * drained durable at the release (Architectural Invariant 1), so
		 * skipping the reflush loses nothing; the next read cold-fetches the
		 * peer's durable image.  Uses the RELIABLE local i_dlm_epoch (bumped on
		 * every grant loss, xfs_mxfs_dlm.c:9327) — immune to the grant_gen /
		 * i_mxfs_ex_grant_seq handoff-underfire that made every prior gate
		 * inert (measured gg_mismatch=0 / prior_tenure=0 false-neg).
		 * relepoch==0 (fresh block, never read/modified this image) excluded so
		 * a freshly-created current block is never mistaken for a stale one.
		 * Independent of grant MODE: a pre-release stale image is stale whether
		 * we currently hold EX (re-acquired) or not.
		 */
		if (bp->b_mxfs_relepoch != 0 &&
		    bp->b_mxfs_relepoch < (uint32_t)ip->i_dlm_epoch) {
			struct xfs_buf_log_item *rbli = bp->b_log_item;
			bool rdirty = rbli && test_bit(XFS_LI_DIRTY,
					&rbli->bli_item.li_flags);
			if (!rdirty && !xfs_buf_ispinned(bp)) {
				skip = true;
				if (info)
					info->relepoch_skip = true;
			}
		}
	}
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
	return skip;
}

/*
 * DEFER a background xfsaild push of a multi-node dir
 * DATA/LEAF/BLOCK/FREE/NODE buffer when this node holds the owner dir's DLM EX
 * and a peer BAST is pending (the dir is contended).  Returns true => caller
 * (xfs_buf_item_push) must keep the BLI in the AIL with NO I/O (XFS_ITEM_LOCKED)
 * so the block lands only via the synchronous release-drain.  See the big
 * comment at mxfs_dir_ail_defer.  False for: single-node, non-dir buffers, owner
 * not in-core, mode != EX, or no pending BAST (uncontended -> normal destage is
 * coherent and must proceed to avoid log-tail starvation).
 */
bool
mxfs_dir_ail_push_defer(struct xfs_buf *bp)
{
	struct xfs_mount	*mp;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;
	uint64_t		owner;
	bool			defer = false;

	if (!mxfs_dir_ail_defer || !bp || !bp->b_addr)
		return false;
	owner = mxfs_dir_buf_owner(bp);
	if (owner == 0)
		return false;			/* not a dir3 namespace buffer */
	mp = bp->b_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	agno = XFS_INO_TO_AGNO(mp, owner);
	if (agno >= mp->m_sb.sb_agcount)
		return false;
	agino = XFS_INO_TO_AGINO(mp, owner);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return false;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	/*
	 * Gate: this node holds the dir EX AND the dir is SHARED (i_dlm_dir_gen>0
	 * = it has had at least one cross-node handoff/reload).  bast_pending is
	 * too narrow — it is sampled at iop_push (delwri-queue) time and the
	 * dangerous background destage usually fires in the EX window BEFORE the
	 * peer BAST arrives, so the transient flag rarely matches (P25 fired 1x).
	 * dir_gen>0 is STICKY (monotonic) so every shared-dir EX-held background
	 * push is deferred to the release-drain.  A truly private dir keeps
	 * dir_gen==0 and destages normally (no log-tail starvation).  The gate
	 * self-clears the instant we release EX (mode->NL), so a block the
	 * release-drain missed destages normally afterward.
	 */
	if (ip && ip->i_ino == owner && S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_dlm_mode == MXFS_LOCK_EX &&
	    (ip->i_dlm_dir_gen != 0 || ip->i_dlm_dir_contended))
		defer = true;
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
	if (defer)
		mxfs_probe_ratelimited(
		    "mxfs: P25-AILDEFER owner=%llu daddr=%lld ops=%s — EX-held contended dir block; deferring background destage to release-drain\n",
		    (unsigned long long)owner,
		    (long long)bp->b_maps[0].bm_bn,
		    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?");
	return defer;
}

/*
 * Phase 4 D6 / extended FUA-read gate.
 *
 * Returns true if @bp is a buffer type whose READS need FUA passthrough
 * to bypass per-initiator iSCSI/LIO read caches.  Superset of
 * mxfs_buf_is_ag_metadata: adds the inode cluster buf, which the
 * v0.3.67 comment claimed to cover but wasn't actually included in the
 * gate.  Reads of inode cluster bufs without FUA can return stale
 * pre-modification content even after the local cache is staled, if
 * the storage stack below has its own read cache.
 *
 * This is where transport-invariant Mode A (`xfs_dir_removename rc=-2`)
 * is hypothesized to live: peer modifies inode 128 (dir size, format,
 * SF entries), commits with FUA WRITE, releases lock.  Acquirer's
 * reload_inode stales its local buf and re-reads — but the read is
 * plain bio (not FUA), so a per-initiator cache returns pre-mod content.
 * Acquirer sees empty/stale dir, subsequent rm hits ENOENT.
 *
 * Currently only inode cluster bufs are added; if Mode A persists,
 * extending to dir-block buf_ops (xfs_dir3_*_buf_ops) is the next step.
 *
 * NOTE: dirty-BLI-attached check at xfs_buf.c (the existing v0.3.68
 * skip-read logic) MUST cover the buf types added here, else FUA-read
 * could overwrite in-memory modifications mid-trans.
 */
bool
mxfs_buf_needs_fua_read(
	struct xfs_buf	*bp)
{
	const struct xfs_buf_ops *ops;

	if (mxfs_buf_is_ag_metadata(bp))
		return true;
	ops = bp->b_ops;
	if (!ops)
		return false;
	return ops == &xfs_inode_buf_ops ||
	       ops == &xfs_inode_buf_ra_ops ||
	       /* Phase 4 D6 / dir-block reads — Mode A
		* dir-removename ENOENT survives transport switch (TCP),
		* implying cache-on-acquire stale read of dir blocks. */
	       ops == &xfs_dir3_data_buf_ops ||
	       ops == &xfs_dir3_block_buf_ops ||
	       ops == &xfs_dir3_leaf1_buf_ops ||
	       ops == &xfs_dir3_leafn_buf_ops ||
	       ops == &xfs_dir3_free_buf_ops ||
	       /*
		* sess63 (instrumented): FUA-pierce BTREE-dir extent-map (bmbt) leaf
		* reads.  This is the READ-side complement to the sess63
		* writer-side fix (route bmbt-leaf WRITES through the SCSI FUA
		* passthrough in xfs_buf_submit, so the leaf lands durably and
		* pierces the SCST write cache).  P63-TORN-FLUSH proved the
		* residual: between the (consistent) btree insert and the next
		* iflush, a PLAIN-bio re-read pulls a STALE on-disk leaf image
		* (numrecs=N-1) over the in-core buffer while the iext skiplist
		* keeps N -> the writer then flushes di_nextents=N over a leaf
		* it just reverted to N-1.  FUA-reading the leaf makes the
		* re-read return the true latest durable image.
		*
		* This was tried & reverted in sess60 (made it WORSE) but that
		* predated BOTH (a) the durable FUA bmbt WRITE (sess60's leaf
		* writes were failing -EIO so FUA-read surfaced a real on-disk
		* lag) and (b) the read-over-logged guards that refuse to DMA
		* disk over a bmbt buffer carrying uncheckpointed mods
		* (mxfs_buf_read_fua P91 backstop + P61-BIO-OVER-LOGGED-BMBT in
		* xfs_buf_submit).  With all three in place the FUA-read only
		* refreshes CLEAN/checkpointed leaves to their true durable
		* image, which is exactly what the torn-flush needs.
		*/
	       ops == &xfs_bmbt_buf_ops;
}

/*
 * Buffer-write-completion callback.  Fires from __xfs_buf_ioend on
 * every successful WRITE of an AG-metadata buffer that was tracked
 * by mxfs_ag_meta_track.  At this point the buffer's bytes are at
 * the on-disk home location and a peer that subsequently acquires
 * the AG DLM lock and reads the block will see our changes.
 *
 * Decrement the owning AG's pending-writeback counter.  If it hits
 * zero AND a previous mxfs_ag_dlm_unlock deferred the actual DLM
 * release, fire mxfs_v5_dlm_ag_unlock now so peers can acquire.
 */
/*
 * deferred-release worker.  Runs on system_wq (NOT the xfs-buf
 * workqueue), so it can safely blkdev_issue_flush the device write cache to
 * the backing store BEFORE the on-disk AG unlock.  This closes the
 * Invariant-#1 gap in mxfs_dlm_ag_meta_iodone: without the flush, a peer's
 * FUA read of the AG free-space btrees reads the backing store and misses our
 * just-completed (but still write-cached) allocation, double-allocating the
 * block.
 */
void
mxfs_dlm_ag_release_work_fn(
	struct work_struct	*work)
{
	struct xfs_perag	*pag =
		container_of(work, struct xfs_perag, pag_dlm_release_work);
	struct xfs_mount	*mp = pag_mount(pag);
	struct mxfs_v5_dlm	*dlm = mp ? mp->m_mxfs_dlm : NULL;
	xfs_agnumber_t		agno = pag_agno(pag);

	if (!dlm) {
		/* Shouldn't happen; clear state and bail. */
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		mxfs_ag_demote_clear(pag);
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);
		return;
	}

	/* Push the SCST write cache to the platter so a peer's FUA read sees
	 * our AG-metadata writes, THEN release the on-disk grant. */
	mxfs_blkdev_flush_epoch(mp);

	pag->pag_dlm_lineage_open = false;	/* P130: sanctioned release */
	if (unlikely(mxfs_ag_strand_inject_hit(agno, "release_work_fn"))) {
		atomic64_inc(&mxfs_dlm_stat_ag_release);
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		mxfs_ag_demote_clear(pag);
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);
		return;
	}
	/* v5: tenure-scoped iunlink records die with the grant. */
	mxfs_iunl_store_purge_ag(mp, agno, "deferred");
	/* (0.39.2): the SAME publication gate as the inline path —
	 * this path let committed FREE obligations cross the release
	 * un-audited (P-FREEOB-CHAIN-BROKEN on the next local re-allocation). */
	mxfs_ag_release_publish_gate(pag, "deferred");
	if (xfs_is_shutdown(mp)) {
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		mxfs_ag_demote_clear(pag);
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		wake_up_all(&pag->pag_dlm_demote_wq);
		return;
	}
	mxfs_agifc_release_audit(pag, "deferred");
	/* this worker completes a release whose COMMIT + drain ran
	 * in the bast worker (release_pending); re-publishing the marker is
	 * idempotent (pass-1 table dedups) and covers the case where the
	 * inline publish did not happen. */
	mxfs_ag_relmark_before_unlock(pag, "ag-deferred");
	{
		enum mxfs_unlock_state us = mxfs_v5_dlm_ag_unlock(dlm, agno);

		if (us != MXFS_UNLOCK_RELEASED)
			pr_warn("mxfs: P275-AGUNLK-DEFERRED-NOTREL ag=%u state=%d — deferred release did not prove the bit clear; rx watchdog/readopt is the recovery path\n",
				agno, us);
	}
	atomic64_inc(&mxfs_dlm_stat_ag_release);

	if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
		mxfs_probe("P10-INSTR realns=%llu slot=%d agno=%u REL-DEFERRED-FLUSHED\n",
			(unsigned long long)ktime_get_real_ns(),
			mxfs_v5_dlm_get_node_slot(dlm), agno);

	mxfs_pag_dlm_lock(pag, MXFS_SITE);
	mxfs_ag_demote_clear(pag);
	pag->pag_dlm_bast_pending = false;	/* 0.22.2: revocation honored */
	mxfs_pag_dlm_unlock(pag, MXFS_SITE);
	wake_up_all(&pag->pag_dlm_demote_wq);
}

/*
 * 0.87.14 (D-...-0924), TEST ONLY: make the next N tracked write completions
 * behave as if the callback had not consumed the token — return before the
 * cmpxchg, leaving the token armed for the completion epilogue in
 * __xfs_buf_ioend to return.  That epilogue is the second choke point of the
 * tracking contract and a healthy build never reaches it (the callback
 * consumes every token), so without this knob the epilogue would ship
 * unexercised.  Counts down; 0 in production.
 */
int mxfs_dbg_agmeta_iodone_skip;
module_param_named(dbg_agmeta_iodone_skip, mxfs_dbg_agmeta_iodone_skip, int,
		   0644);

void
mxfs_dlm_ag_meta_iodone(
	struct xfs_buf	*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct mxfs_v5_dlm	*dlm;
	struct xfs_perag	*pag;
	xfs_agnumber_t		agno;
	bool			do_release = false;
	int			new_pending;

	if (unlikely(READ_ONCE(mxfs_dbg_agmeta_iodone_skip) > 0) &&
	    atomic_read(&bp->b_mxfs_agmeta_hold) == 1) {
		WRITE_ONCE(mxfs_dbg_agmeta_iodone_skip,
			   READ_ONCE(mxfs_dbg_agmeta_iodone_skip) - 1);
		mxfs_probe("mxfs: P-AGMETA-IODONE-SKIP daddr=%lld — TEST ONLY: callback leaving the token armed for the completion epilogue\n",
			(long long)bp->b_maps[0].bm_bn);
		return;
	}

	/*
	 * sess-pve: consume the one-shot AG-meta track token.  If it is not
	 * ours — already reclaimed by mxfs_ag_meta_reclaim on a shutdown/abort
	 * detach or a stale completion, or a write/read completion with no associated
	 * mxfs_ag_meta_track — there is no extra hold or pending count that
	 * belongs to us; return without touching either (dropping here would
	 * double-free the hold and underflow pag_dlm_meta_pending).
	 */
	if (atomic_cmpxchg(&bp->b_mxfs_agmeta_hold, 1, 0) != 1) {
		mxfs_agmeta_consume_misses++;
		return;
	}
	mxfs_agmeta_returns_iodone++;

	if (!mp || !mp->m_mxfs_dlm)
		goto out_rele;
	dlm = mp->m_mxfs_dlm;

	agno = xfs_daddr_to_agno(mp, bp->b_maps[0].bm_bn);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		goto out_rele;

	new_pending = atomic_dec_return(&pag->pag_dlm_meta_pending);
	if (new_pending == 0) {
		/*
		 * Counter drained.  If a deferred release is pending and
		 * no local holder has re-acquired in the meantime, fire
		 * the actual DLM release now.
		 *
		 * If a local re-acquire DID happen, mxfs_ag_dlm_lock
		 * cleared release_pending — we observe that under
		 * pag_dlm_lock and skip the release; the next unlock
		 * will redo the deferral check.
		 */
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		if (pag->pag_dlm_release_pending &&
		    pag->pag_dlm_holders == 0) {
			pag->pag_dlm_release_pending = false;
			do_release = true;
		}
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);

		if (do_release) {
			/*
			 * FIX (Invariant #1): we MUST flush the block
			 * device's write cache before the on-disk AG unlock, so a
			 * peer's FUA read of the AG free-space btrees sees our
			 * just-written allocation.  The AG-meta write bio
			 * completing only means the SCST target ACKed the write
			 * into its WRITE CACHE — a peer FUA read reads from the
			 * backing store and would miss it, leaving the freed/used
			 * block looking free -> DOUBLE ALLOCATION (block used as
			 * both inode cluster and dir block -> EFSBADCRC shutdown,
			 * a timing-sensitive Heisenbug under concurrent rename).
			 *
			 * blkdev_issue_flush CANNOT run here: this is xfs-buf
			 * workqueue context, and the synchronous flush serializes
			 * the queue and deadlocks (v0.3.26 regression).  Hand the
			 * flush + unlock + demote-clear off to a system_wq worker
			 * (pag_dlm_release_work) instead.  Take a pag ref for it;
			 * the worker drops it.  release_pending was already
			 * consumed under the lock above, so exactly one worker is
			 * queued per deferred release.
			 */
			if (!queue_work(system_wq, &pag->pag_dlm_release_work)) {
				/*
				 * Already queued (shouldn't happen — release_pending
				 * has a single consumer).  Fall back to an inline
				 * unlock WITHOUT flush rather than leak the grant.
				 * The pag is stable for the mount lifetime; unmount
				 * (mxfs_dlm_ag_force_release_all) cancel_work_syncs
				 * pag_dlm_release_work before perags are freed.
				 */
				pag->pag_dlm_lineage_open = false;	/* P130 */
				if (!unlikely(mxfs_ag_strand_inject_hit(agno,
							"ag_meta_iodone"))) {
					enum mxfs_unlock_state us;

					mxfs_iunl_store_purge_ag(
						pag_mount(pag), agno,
						"iodone-fallback");
					/* no audit possible in iodone
					 * context — at least name the crossing */
					mxfs_pubob_unlock_census(pag, "iodone-fallback");
					us = mxfs_v5_dlm_ag_unlock(dlm, agno);
					if (us != MXFS_UNLOCK_RELEASED)
						mxfs_probe("mxfs: P275-AGUNLK-IODONE-NOTREL ag=%u state=%d — fallback release did not prove the bit clear\n",
							agno, us);
				}
				atomic64_inc(&mxfs_dlm_stat_ag_release);
				mxfs_pag_dlm_lock(pag, MXFS_SITE);
				mxfs_ag_demote_clear(pag);
				pag->pag_dlm_bast_pending = false;	/* 0.22.2 */
				mxfs_pag_dlm_unlock(pag, MXFS_SITE);
				wake_up_all(&pag->pag_dlm_demote_wq);
			}
		}
	}

	xfs_perag_put(pag);

out_rele:
	/*
	 * Drop the extra buffer reference taken by mxfs_ag_meta_track.
	 * The buffer may still be live (held by readers, AIL, etc.);
	 * xfs_buf_rele only frees it when the last ref drops.
	 */
	xfs_buf_rele(bp);
}

/*
 * sess-pve (AGI umount-wedge fix): reclaim an outstanding mxfs_ag_meta_track
 * hold on a shutdown/abort bli-detach that will NEVER writeback.
 *
 * On a forced shutdown the dirty AG-meta buffers (AGI/AGF/inobt/finobt) logged
 * by an in-flight dialloc/dfree transaction are aborted without writeback:
 * xfs_buf_item_release's (aborted || xlog_is_shutdown) branch detaches the bli
 * via xfs_buf_item_done, which never runs xfs_buf_ioend — so bp->b_iodone
 * (mxfs_dlm_ag_meta_iodone) never fires and the extra hold + pag_dlm_meta_pending
 * taken by mxfs_ag_meta_track leak forever, pinning the buffer at b_hold=2 so
 * xfs_buftarg_drain spins at unmount (the reproduced 2/tcp Proxmox wedge on
 * daddr=2/24/32, xfs_create->xfs_dialloc dirty-cancel shutdown).
 *
 * Consume the one-shot token so exactly one of {iodone, this} drops the hold;
 * on this path iodone can never fire, so we do it here.  No deferred DLM unlock:
 * this is the shutdown/withdraw path, and mxfs_dlm_ag_force_release_all performs
 * the final AG-lock release at unmount.  Idempotent + safe on any buffer: if no
 * track hold is outstanding the cmpxchg fails and this is a no-op.
 *
 * 0.75.62: the second caller is the STALE completion (xfs_buf_item_finish_stale).
 * An AG-metadata btree block freed after being logged in the same dirty epoch —
 * xfs_trans_binval on a bnobt/cntbt/inobt/finobt leaf merge or root collapse —
 * is a committed-never-written buffer too: its log item is freed at unpin (or
 * at the last transaction release) with no ioend, so b_iodone never fires and
 * the hold + pending count leaked exactly as on the abort path.  Because the
 * AG release pipeline waits on pag_dlm_meta_pending (Phase 3, 2 s bound), one
 * such leak made EVERY later release of that AG on this node wait the full
 * 2 s (P55-STUCKMETA pending=N write_inflight=0 dirty=0 inAIL=0) and expire
 * the peer's 1 s request deadline (s542e truncate 2045 ms, s543b unlinks 2.05 s).
 * `why` names the caller in the probe line.  The stale case is ordinary (any
 * free-space tree that grows and shrinks), so its probe is rate-limited rather
 * than capped.
 */
void
mxfs_ag_meta_reclaim(
	struct xfs_buf	*bp,
	const char	*why)
{
	struct xfs_mount	*mp = bp->b_mount;

	if (atomic_cmpxchg(&bp->b_mxfs_agmeta_hold, 1, 0) != 1) {
		mxfs_agmeta_consume_misses++;
		return;
	}
	mxfs_agmeta_returns_reclaim++;

	/*
	 * Prove the reclaim fires (instrumented).  Each line is one AG-meta track
	 * hold that the OLD code leaked at this exact completion.
	 */
	if (why[0] == 's' && why[1] == 't') {
		mxfs_probe_ratelimited("mxfs: P-AGMETA-RECLAIM daddr=%lld ops=%s flags=0x%x why=%s — dropped AG-meta track hold (no writeback; iodone never fires)\n",
			(long long)bp->b_maps[0].bm_bn,
			(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
			bp->b_flags, why);
	} else {
		static atomic_t rcl_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&rcl_n) <= 200)
			mxfs_probe("mxfs: P-AGMETA-RECLAIM daddr=%lld ops=%s flags=0x%x why=%s — dropped AG-meta track hold (no writeback; iodone never fires)\n",
				(long long)bp->b_maps[0].bm_bn,
				(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
				bp->b_flags, why);
	}

	if (mp && mp->m_mxfs_dlm) {
		xfs_agnumber_t		agno =
			xfs_daddr_to_agno(mp, bp->b_maps[0].bm_bn);
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);

		if (pag) {
			atomic_dec(&pag->pag_dlm_meta_pending);
			xfs_perag_put(pag);
		}
	}

	xfs_buf_rele(bp);
}

/*
 * Called from xfs_trans_log_buf for every AG-metadata buffer logged
 * in multi-node mode.  Within a single dirty epoch (one bli lifetime,
 * which spans from first attachment to writeback completion) this
 * runs at most once per buffer, deduplicated via
 * XFS_BLI_MXFS_AGMETA_TRACKED on bli_flags.
 *
 * Increments the owning AG's pag_dlm_meta_pending counter, holds an
 * extra reference on the buffer so it cannot be freed before our
 * iodone fires, and installs mxfs_dlm_ag_meta_iodone as the
 * per-buffer write-completion callback.
 *
 * The bli is freed by xfs_buf_item_done when writeback completes,
 * resetting bli_flags to 0 for the next dirty epoch.  bp->b_iodone
 * is left set to mxfs_dlm_ag_meta_iodone — that is fine because
 * the next dirty epoch will register again, and any spurious iodone
 * fire (i.e. a write that completes without an associated
 * mxfs_ag_meta_track) would underflow the counter, so we guard
 * against that by checking the per-bli flag rather than reusing the
 * b_iodone slot for state.
 *
 * b_iodone is NULL for upstream AG-metadata buffers (only
 * inode/dquot buffers set it via xfs_trans_inode_buf and
 * xfs_dquot_buf_ops machinery), so installing ours does not stomp
 * on existing handlers.
 */
void
mxfs_ag_meta_track(
	struct xfs_buf	*bp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct xfs_mount	*mp = bp->b_mount;
	struct xfs_perag	*pag;
	xfs_agnumber_t		agno;

	if (!bip || !mp || !mp->m_mxfs_dlm)
		return;

	agno = xfs_daddr_to_agno(mp, bp->b_maps[0].bm_bn);
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return;

	/*
	 * MODIFY-TIME tenure stamping (replaces the former
	 * read-time stamps at xfs_read_agi / xfs_alloc_read_agf / xfs_btree
	 * read).  b_tenure_id now records the tenure in which this AG-meta
	 * buffer was last MODIFIED, not last READ.  A cache-hit READ no longer
	 * re-stamps a prior-tenure stale buffer to the current tenure, so such
	 * a buffer is no longer protected by the tenure guard in
	 * mxfs_ag_meta_invalidate_stale and correctly falls through to the
	 * gen-based cold-read refresh (fixing the P124 prior-tenure
	 * alloc-revert / read-side staleness).  A buffer genuinely modified
	 * this tenure (e.g. an iunlink INSERT on the AGI) IS stamped current
	 * here and stays tenure-guarded — preserving the AGI fix.
	 * Stamp unconditionally (before the AGMETA_TRACKED early-return) so a
	 * second modify within the same tenure still records the current
	 * tenure even when tracking is already installed.
	 */
	bp->b_tenure_id = pag->ag_dlm_tenure_id;

	if (bip->bli_flags & XFS_BLI_MXFS_AGMETA_TRACKED) {
		xfs_perag_put(pag);
		return;
	}

	bip->bli_flags |= XFS_BLI_MXFS_AGMETA_TRACKED;
	xfs_buf_hold(bp);
	atomic_inc(&pag->pag_dlm_meta_pending);
	/*
	 * sess-pve: arm the one-shot ownership token — CHECKED 0->1.  Exactly
	 * one of mxfs_dlm_ag_meta_iodone (writeback) or mxfs_ag_meta_reclaim
	 * (shutdown/abort detach, or stale completion of a freed block) consumes
	 * it and drops the hold + pending — so a
	 * forced shutdown that aborts this buffer without writeback can no longer
	 * leak the hold (the drain wedge).  The token MUST read 0 here (fresh
	 * dirty epoch: the AGMETA_TRACKED bli flag we just set was clear, so the
	 * prior epoch's token was already consumed).  A non-zero token means a
	 * PRIOR epoch's hold leaked via a detach path we don't yet cover — WARN
	 * (tripwire) and roll back the hold+pending we just took so we don't
	 * compound the leak; the next writeback's iodone consumes the stale token
	 * and heals the prior generation.
	 */
	if (WARN_ON_ONCE(atomic_cmpxchg(&bp->b_mxfs_agmeta_hold, 0, 1) != 0)) {
		mxfs_agmeta_arm_failures++;
		atomic_dec(&pag->pag_dlm_meta_pending);
		xfs_buf_rele(bp);
	} else {
		mxfs_agmeta_acquires++;
	}

	/*
	 * Install our per-buffer iodone.  AG-metadata buffers do not
	 * use b_iodone upstream, so a non-NULL value here that is not
	 * already ours indicates an unexpected stomping; warn but
	 * proceed (we still own the counter increment, so chaining
	 * would be needed to honour both).
	 */
	if (bp->b_iodone && bp->b_iodone != mxfs_dlm_ag_meta_iodone) {
		mxfs_pal_log(MXFS_LOG_WARN,
			"mxfs: AG-meta buf agno=%u blkno=%llu has unexpected "
			"b_iodone=%pS — overriding for deferred-release",
			(unsigned)agno,
			(unsigned long long)bp->b_maps[0].bm_bn,
			bp->b_iodone);
	}
	bp->b_iodone = mxfs_dlm_ag_meta_iodone;

	xfs_perag_put(pag);
}

/*
 * ── THE b_iodone SLOT HAS ONE SEAT AND SEVERAL WRITERS ──────────────────
 *
 * INSTRUMENT, not a fix.  D-STALE-AGMETA-... asks for a probe at the
 * OVERWRITE rather than at the completion, and this is it.
 *
 * mxfs_ag_meta_track above arms a one-shot token on the BUFFER and installs
 * mxfs_dlm_ag_meta_iodone to consume it at writeback.  It already warns when
 * it finds somebody else's callback in the slot — but only in that direction.
 * The reverse is unguarded: every other writer of bp->b_iodone assigns
 * unconditionally.  If one of them lands between the track and the writeback,
 * the completion runs THEIR callback, nothing consumes our token, and the
 * extra xfs_buf reference and the AG's pending count leak.  Nothing reports
 * it at the time; the first sign is the tripwire in mxfs_ag_meta_track firing
 * a whole dirty epoch later, by which point the route is gone.
 *
 * Reading the tree says this should be impossible, because mxfs_buf_is_ag_
 * metadata matches a b_ops set disjoint from the inode and dquot buffers the
 * other writers tag.  Reading said the same about two earlier candidate
 * routes for this leak and was wrong about the reason both times, so this
 * asks the buffer instead of asking the code.  A buffer can change what it is
 * between lives — a btree block that is freed and whose blocks come back as
 * an inode chunk is the obvious way for one xfs_buf to meet both writers.
 *
 * The counter is the measurement; the log line is budgeted and is only there
 * to name the site.  Counting printed lines of a budgeted probe measures the
 * budget, not the events.
 */
int mxfs_agmeta_iodone_stomps;
module_param_named(agmeta_iodone_stomps, mxfs_agmeta_iodone_stomps, int, 0644);
/*
 * The DENOMINATOR, and it is not optional.  "stomps=0" on its own is equally
 * consistent with "no writer ever landed on an AG-meta buffer" and "this
 * probe is never called at all", and those are opposite conclusions about
 * whether a route has been eliminated.  Every foreign writer of the slot
 * increments this, so a zero numerator only means something beside a
 * non-zero one.
 */
int mxfs_agmeta_iodone_installs;
module_param_named(agmeta_iodone_installs, mxfs_agmeta_iodone_installs, int,
		   0644);

/*
 * ── CONSERVATION, WHICH IS THE THING THE TRIPWIRE CANNOT TELL YOU ───────
 *
 * The one-shot token is armed by mxfs_ag_meta_track and returned by exactly
 * one of mxfs_dlm_ag_meta_iodone or mxfs_ag_meta_reclaim.  The existing
 * tripwire fires only when a NEW dirty epoch finds the PREVIOUS epoch's token
 * still armed — so it detects a strand on a buffer that is logged again, and
 * says nothing at all about a buffer that strands and is never touched again.
 * That is the shape this leak actually has: the count it corrupts is per-AG
 * and permanent, and the buffer leaves the LRU, so nothing goes looking.
 *
 * These count the obligation instead of waiting for a coincidence.  At a
 * quiescent point — no I/O in flight, everything synced — the identity that
 * must hold is
 *
 *	acquires == returns_iodone + returns_reclaim
 *
 * and the difference IS the number of outstanding holds and the sum of every
 * AG's pending count.  A non-zero difference at rest is the leak, named at
 * the moment it can still be attributed rather than a dirty epoch later.
 *
 * arm_failures is counted separately and deliberately: the tripwire beside it
 * is WARN_ON_ONCE, which prints once per boot however many times it fires, so
 * its log line measures the print budget and not the events.  (The failure
 * path itself rolls the hold and the pending charge back, so a failure is not
 * also an accounting leak.)
 *
 * consume_misses counts a consumer that arrived to find the token not armed.
 * That is legitimate and common — the two consumers race by design and only
 * one may win — but a miss count that tracks the acquire count rather than
 * sitting well below it would mean the two are racing far more than the
 * design assumes, which is worth seeing.
 */
int mxfs_agmeta_acquires;
module_param_named(agmeta_acquires, mxfs_agmeta_acquires, int, 0644);
int mxfs_agmeta_arm_failures;
module_param_named(agmeta_arm_failures, mxfs_agmeta_arm_failures, int, 0644);
int mxfs_agmeta_returns_iodone;
module_param_named(agmeta_returns_iodone, mxfs_agmeta_returns_iodone, int, 0644);
int mxfs_agmeta_returns_reclaim;
module_param_named(agmeta_returns_reclaim, mxfs_agmeta_returns_reclaim, int,
		   0644);
int mxfs_agmeta_consume_misses;
module_param_named(agmeta_consume_misses, mxfs_agmeta_consume_misses, int,
		   0644);

void
mxfs_buf_iodone_install(
	struct xfs_buf	*bp,
	void		(*fn)(struct xfs_buf *),
	const char	*why)
{
	static int stomp_logs;

	if (!bp)
		return;

	mxfs_agmeta_iodone_installs++;

	if (fn != mxfs_dlm_ag_meta_iodone &&
	    (bp->b_iodone == mxfs_dlm_ag_meta_iodone ||
	     atomic_read(&bp->b_mxfs_agmeta_hold) != 0)) {
		mxfs_agmeta_iodone_stomps++;
		if (stomp_logs < 16) {
			stomp_logs++;
			mxfs_pal_log(MXFS_LOG_WARN,
				"mxfs: P-AGMETA-IODONE-STOMP site=%s daddr=%lld "
				"token=%d old=%pS new=%pS bli=%p flags=0x%x "
				"n=%d — a writer is replacing the AG-meta write "
				"completion while its one-shot token is still "
				"armed; if this buffer now writes back, nothing "
				"consumes the token and the buffer hold plus the "
				"AG's pending count leak from this point\n",
				why ? why : "?",
				(long long)bp->b_maps[0].bm_bn,
				atomic_read(&bp->b_mxfs_agmeta_hold),
				bp->b_iodone, fn, bp->b_log_item,
				bp->b_log_item ? bp->b_log_item->bli_flags : 0,
				mxfs_agmeta_iodone_stomps);
		}
	}

	bp->b_iodone = fn;
}

/* ─── Single→multi transition sync ─── */

/*
 * Fired once by v5_discovery_peer_cb when the first peer appears.
 *
 * In single-node mode XFS treats the disk as its own and relies on the
 * normal delayed-write machinery to flush dirty cluster buffers.  The
 * DLM is bypassed, so there is no per-resource "release → flush" that
 * would force these writes out.  When a peer arrives, the v5 layer
 * switches to multi-node mode and the inode reload path will start
 * staling cluster buffers and re-reading from disk.  If our dirty
 * clusters have not yet been written, that re-read returns zero bytes
 * (or — on a disk with residual mkfs data — stale dinodes from an
 * earlier filesystem), which xfs_inode_buf_verify rejects and the
 * filesystem shuts down.
 *
 * Force everything out to disk before the transition is visible.
 */
/*
 * (D-FOREIGN-REPLAY step 4a item 1) — the cached-view invalidation
 * half of the peer-joined flush, split out so the pre-xfs_mountfs recovery
 * barrier can reuse it.
 *
 * The barrier needs exactly this walk and MUST NOT call the flush half:
 * at barrier time the AIL holds recovered INTENT items that
 * xlog_recover_finish has not processed yet, and xfs_ail_push_all_sync on
 * those never completes (upstream refuses the same thing for the same
 * reason — xfs_log.c, xlog_force_shutdown's comment on pushing before
 * recovery finishes).  Nothing here forces the log or pushes the AIL: it
 * only drops CACHED state, which is always safe.
 *
 * Callers: mxfs_dlm_peer_joined_flush (single→multi transition) and
 * mxfs_dlm_mount_recovery_barrier (before and after each foreign slice
 * replay).
 */
/*
 * 0.83.4 (D-0959): the AG-meta walk above stales AG headers, btree blocks
 * and inode clusters and leaves every OTHER cached block alone -- directory
 * data/leaf/node blocks, bmbt blocks, symlink and attr blocks.  Those were
 * read while this mount had no peer, so nothing about them is represented
 * at a DLM master: a peer's change to one of them after the join raises no
 * epoch this node could compare against, and the in-core inode reload that
 * the epoch advance forces keeps a "loaded fork" whose blocks are served from
 * this cache.  At a join both sides are clean (the incumbent is frozen, the
 * newcomer has modified nothing), so the correct view of every such block is
 * the platter's: mark each clean, unlocked, unpinned one for a re-read
 * (clear DONE + FUA-fresh, the treatment the AG-meta walk applies at
 * b_hold==0) and count the ones that could not be treated so the caller
 * retries the walk rather than declare the view dropped.
 */
static unsigned int
mxfs_dlm_drop_clean_cached_blocks(
	struct xfs_perag	*pag,
	unsigned int		*dropped)
{
	struct rhashtable_iter	iter;
	struct xfs_buf		*bp;
	unsigned int		retained = 0;

	rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
	do {
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			struct xfs_buf_log_item	*bip;
			bool			got = false;
			bool			keep;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (mxfs_buf_is_ag_metadata(bp) ||
			    bp->b_ops == &xfs_inode_buf_ops ||
			    bp->b_ops == &xfs_inode_buf_ra_ops)
				continue;	/* the AG-meta walk's business */
			if (!(bp->b_flags & XBF_DONE) ||
			    (bp->b_flags & XBF_STALE))
				continue;	/* already a re-read on next use */

			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				got = true;
			}
			spin_unlock(&bp->b_lock);
			if (!got)
				continue;	/* being freed: nothing cached */

			if (!xfs_buf_trylock(bp)) {
				retained++;
				xfs_buf_rele(bp);
				continue;
			}
			spin_lock(&bp->b_lock);
			bip = bp->b_log_item;
			keep = (bip &&
				(test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags) ||
				 test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))) ||
			       xfs_buf_ispinned(bp) ||
			       (bp->b_flags & _XBF_DELWRI_Q);
			if (!keep) {
				bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				(*dropped)++;
			} else {
				retained++;
			}
			spin_unlock(&bp->b_lock);
			xfs_buf_unlock(bp);
			xfs_buf_rele(bp);
		}
		rhashtable_walk_stop(&iter);
	} while (bp == ERR_PTR(-EAGAIN));
	rhashtable_walk_exit(&iter);
	return retained;
}

int
mxfs_dlm_invalidate_cached_views(
	struct xfs_mount	*mp)
{
	struct xfs_perag	*pag = NULL;
	xfs_agnumber_t		agno;
	unsigned int		invalidated = 0;
	/* item 2/5 — incompleteness census */
	unsigned int		ags_retained = 0;	/* AGs with retained bufs */
	unsigned int		ags_held = 0;		/* AGs busy with holders */
	unsigned int		bufs_retained = 0;
	unsigned int		blocks_dropped = 0;	/* 0.83.4: non-AG-meta */

	if (!mp)
		return -EINVAL;

	/*
	 * v0.3.63: invalidate cached AG-metadata bufs across every perag.
	 *
	 * AG-meta bufs are read into pag_bcache during mount, when
	 * mxfs_v5_dlm_is_single_node() returns true, so my SCSI READ FUA
	 * hook in xfs_buf_submit is bypassed and the buf is populated via
	 * the regular bio path.  After peer-join, single_node→false, but
	 * those cached bufs persist with XBF_DONE forever and subsequent
	 * reads hit cache without ever going through the FUA path.  Peer
	 * writes to AG-meta then become invisible to us until a BAST
	 * triggers a fresh-acquire that walks pag_bcache and stales them.
	 *
	 * Capture at v0.3.62 stress: T2 alloc'd agbno=22456 len=65520 at
	 * 179860.910, fail at 179864.180 — bnobt walk shows gtbno=22456
	 * gtlen=239678, the pre-alloc state.  T1 then acquired AG=0,
	 * FUA-read bnobt at fresh-acquire, saw pre-alloc state, allocated
	 * the same blocks T2 had — double-allocation.  Root cause: T2's
	 * bnobt updates never reached disk before T1 read; T1's read saw
	 * bio-cached pre-T2-alloc state because T1's bnobt was cached at
	 * mount via bio (single_node=true), and the cached buf's content
	 * was wrong relative to disk after T2's writes.
	 *
	 * Stale every AG-meta buf in every pag_bcache so next reads
	 * round-trip through the FUA hook.
	 */
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		unsigned int	ag_pres = 0;
		unsigned int	retained;

		pag = xfs_perag_get(mp, agno);
		if (!pag)
			continue;
		retained = mxfs_dlm_invalidate_ag_meta(pag, &ag_pres);
		retained += mxfs_dlm_drop_clean_cached_blocks(pag,
							      &blocks_dropped);
		if (retained) {
			ags_retained++;
			bufs_retained += retained;
		}

		/*
		 * 0.41.0 (sess434, D-0354 candidate A): the v0.3.86/sess25
		 * single→multi SURRENDER of cached AG-DLM and per-inode
		 * grants that used to live here is gone.  It existed because
		 * a lone node's grants were memory-only (the disk slot held
		 * no bit, so a cached EX on both sides of a join was silently
		 * stale).  A lone node now acquires REAL on-disk grants and
		 * mints real epochs through the normal CAW state machine, so
		 * at the join its cached grants are exactly what a cohort
		 * member's are: held on disk, revocable by a peer's BAST
		 * through the ordinary demote/drain/unlock pipeline.
		 *
		 * Surrendering them here would be worse than useless: the
		 * next acquire re-enters caw_lock_body's self-hold check with
		 * the epoch cleared, fails closed (-EDEADLK), releases and
		 * RE-MINTS a new epoch — and every image this node journaled
		 * under the old epoch becomes `staleep` to a successor's
		 * replay.  The ruling's invariant (a grant must not change
		 * identity while journal records bearing its token can still
		 * require replay) forbids that.  Retained buffers (ag_pres)
		 * are still reported, since a caller may act on them.
		 */
		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		if (pag->pag_dlm_holders || pag->pag_dlm_demoting)
			ags_held++;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);

		xfs_perag_put(pag);
		invalidated++;
	}

	/*
	 * item 2/5 — the verdict.
	 *
	 * A retained BUFFER is a hard incompleteness: its content is this
	 * node's and it will be written back, so anyone who treats the walk as
	 * "our view is gone" can be overwritten later.  Both callers act on
	 * it (peer-joined retries the destage; the recovery barrier refuses to
	 * publish the slice).  AGs with live holders are counted for the log
	 * only; their grants are retained by design (above).
	 */
	if (bufs_retained)
		xfs_warn(mp,
			"mxfs: cached-view invalidation INCOMPLETE (%u perags): "
			"%u AG(s) retained %u buffer(s), %u AG(s) had live "
			"holders, %u cached block(s) marked for re-read (P232-INVAL-BUSY)",
			invalidated, ags_retained, bufs_retained, ags_held,
			blocks_dropped);
	else
		mxfs_pal_log(MXFS_LOG_INFO,
			"mxfs: cached-view invalidation complete (%u perags, "
			"%u AG(s) with live holders, grants retained, "
			"%u cached block(s) marked for re-read)",
			invalidated, ags_held, blocks_dropped);

	return bufs_retained ? -EBUSY : 0;
}
