// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- directory and file bmbt block tracking, eviction and recovery images
 */
#define MXFS_TU_ID 8	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * BMBT-block durability/flush companion for BTREE-format dir forks
 * (instrumented, dpn=100 storm).  Once the shared dir's data fork converts to
 * BTREE, its mapping lives in separate bmbt BLOCKS (buffer log items) that
 * NO release path covered: mxfs_dir_data_durable/flush bail on fmt!=EXTENTS
 * (so even the dir DATA blocks went unchecked — fixed below by accepting
 * BTREE), and nothing ever destaged the bmbt blocks themselves before the
 * on-disk DLM unlock.  A peer then reads a fresh dinode root whose on-disk
 * children are stale/un-landed → ir.loaded != if_nextents or
 * xfs_iread_bmbt_block content corruption → EFSCORRUPTED shutdowns
 * (proven: failures appear exactly when reloads report fmt=3).
 *
 * Walk every AG's buffer cache for xfs_bmbt_buf_ops buffers whose payload
 * bb_owner is this inode (bmbt block AGs are unknown a priori).  In check
 * mode just report whether all are durable; in flush mode take holds inside
 * the (RCU) walk, then lock + re-check + xfs_bwrite each candidate after
 * leaving the walk so no blocking work happens under RCU.  Bounded: a dir
 * needs only a handful of bmbt blocks; the walk runs only for fmt=BTREE.
 */
/* D-0974: stale (freed) bmbt buffers the scan's flush half declined to write. */
atomic_t mxfs_bmbt_scan_stale_skip = ATOMIC_INIT(0);

bool
mxfs_dir_bmbt_scan(struct xfs_inode *ip, bool flush)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
	bool			durable = true;
#define MXFS_BMBT_SCAN_MAX	64
	struct xfs_buf		*held[MXFS_BMBT_SCAN_MAX];
	int			nheld = 0, i;
	/* instrumented decisive probe state (flush path only): how many leaf
	 * buffers owned by this inode the walk SAW (any level), how many were
	 * level-0 leaves, how many of those were flush candidates (needs=true),
	 * how many were actually xfs_bwrite'n, and the leaf numrecs seen. */
	int			p61_seen = 0, p61_leaf = 0, p61_cand = 0,
				p61_wrote = 0, p61_leafrecs = -1;

	/* D-0975 audit: the walk keys on bb_owner, which an attr-fork bmbt
	 * block carries too, so a btree-format attr fork is scanned as well;
	 * only an inode with neither fork in btree format has nothing here. */
	if (ip->i_df.if_format != XFS_DINODE_FMT_BTREE &&
	    !(xfs_inode_has_attr_fork(ip) &&
	      ip->i_af.if_format == XFS_DINODE_FMT_BTREE))
		return true;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			struct xfs_buf_log_item	*bip;
			bool			needs;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr)
				continue;
			if (be64_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_u.l.bb_owner) !=
			    ip->i_ino)
				continue;
			p61_seen++;
			if (be16_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_level) == 0) {
				p61_leaf++;
				p61_leafrecs = be16_to_cpu(
					((struct xfs_btree_block *)
					 bp->b_addr)->bb_numrecs);
			}
			bip = bp->b_log_item;
			/* !XBF_DONE excluded — an invalidated clean
			 * buffer has nothing of ours to land and reporting it
			 * un-durable spins the release loop (see
			 * mxfs_dir_data_durable).  The under-lock re-check
			 * below decides actual writes and already excludes
			 * it. */
			/* ROOT FIX: UNDESTAGED (logged_seq
			 * ahead of written_seq) is needs-flush even with the
			 * BLI retired and nothing dirty/in-AIL/pinned/queued.
			 * Two proven windows escaped the old predicate: (a)
			 * the async CIL->AIL insertion gap (committed,
			 * checkpointed, not yet in AIL at fence time), and (b)
			 * a P61-skip-emulated write whose image never reached
			 * the LUN (re-marked undestaged by
			 * mxfs_bmbt_skip_preserve_truth).  Both carry
			 * committed local bmbt content the LUN lacks; the
			 * fence must land them before the DLM handoff or a
			 * peer adopts the pre-commit leaf (i!=1 family).
			 * XBF_DONE + !XBF_STALE guard (owner_scan idiom): an
			 * invalidated or binval'd image must never be
			 * flushed. */
			/* v0.10.32 (46efd8b6): the undestaged arm must NOT
			 * require XBF_DONE.  A peer BAST's modify-evict clears
			 * XBF_DONE mid-tenure; a leaf logged AFTER the clear
			 * (rank1 rm churn) then carried committed content the
			 * LUN lacked, was invisible to this fence (needs=false),
			 * and the release handed EX away without landing it —
			 * the 12-era stranded leaf (P77 undest=1 lseq=7 wseq=5
			 * walls, dir_reuse@16 run 154203Z).  b_addr still holds
			 * our logged image after a DONE-clear (invalidation
			 * clears the flag, not the memory), so writing it under
			 * our still-held EX is safe and correct; only
			 * XBF_STALE (binval'd = intentionally dead) excludes. */
			needs = (bip && test_bit(XFS_LI_DIRTY,
						 &bip->bli_item.li_flags)) ||
				(bip && test_bit(XFS_LI_IN_AIL,
						 &bip->bli_item.li_flags)) ||
				xfs_buf_ispinned(bp) ||
				(bp->b_flags & _XBF_DELWRI_Q) ||
				(!(bp->b_flags & XBF_STALE) &&
				 mxfs_dir_buf_is_undestaged(bp));
			if (!needs)
				continue;
			durable = false;
			p61_cand++;
			if (!flush || nheld >= MXFS_BMBT_SCAN_MAX)
				continue;
			/* non-sleeping hold under the walk's RCU section */
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				held[nheld++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}

	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = held[i];
		struct xfs_buf_log_item	*bip;

		xfs_buf_lock(bp);
		bip = bp->b_log_item;
		/*
		 * D-0974: never write a stale buffer.  XBF_STALE is a freed
		 * block whose free is logged; its payload is dead and the
		 * block may already hold something else.  The log force the
		 * caller issues retires it (a committed stale buffer stays
		 * locked by its log item until the unpin, so reaching here
		 * with one is not expected — counted).
		 */
		if (bp->b_flags & XBF_STALE) {
			atomic_inc(&mxfs_bmbt_scan_stale_skip);
			xfs_buf_relse(bp);
			continue;
		}
		if ((bip && (test_bit(XFS_LI_DIRTY,
				      &bip->bli_item.li_flags) ||
			     test_bit(XFS_LI_IN_AIL,
				      &bip->bli_item.li_flags))) ||
		    xfs_buf_ispinned(bp) ||
		    (bp->b_flags & _XBF_DELWRI_Q) ||
		    (!(bp->b_flags & XBF_STALE) &&
		     mxfs_dir_buf_is_undestaged(bp))) {	/* v0.10.32: no XBF_DONE gate — see scan needs */
			int werr;

			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe_ratelimited(
					"mxfs: P133-BMBT-RELFLUSH ino=%llu daddr=%lld pin=%d realns=%llu\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn,
					xfs_buf_ispinned(bp) ? 1 : 0,
					(unsigned long long)ktime_get_real_ns());
			bp->b_flags &= ~_XBF_DELWRI_Q;
			/*
			 * xfs_bwrite returns with the buffer still
			 * LOCKED (sync submit; callers relse).  The original
			 * "unlocks on completion" assumption leaked b_sema on
			 * every RELFLUSH — the next bmbt read on this node
			 * blocked forever in xfs_buf_lock while its lookup
			 * held the dir's DLM PR, starving all EX waiters
			 * cluster-wide (proven: test12 mkdir D-state 614s,
			 * slot holders_pr stuck, zero grants for 282s).
			 */
			/* run14d: same pinned-wait stall as the dir-data
			 * flush — drive the unpin instead of sleeping for the
			 * log-worker tick (async: we hold bp locked). */
			if (xfs_buf_ispinned(bp))
				xfs_log_force(ip->i_mount, 0);
			werr = xfs_bwrite(bp);
			p61_wrote++;
			if (werr)
				mxfs_probe_ratelimited(
					"mxfs: P133-BMBT-RELFLUSH-ERR ino=%llu daddr=%lld rc=%d\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn, werr);
		}
		xfs_buf_relse(bp);
	}
	/*
	 * instrumented decisive probe (always-on, rate-limited, BTREE flush
	 * only — low volume: a dir has a handful of bmbt blocks).  Distinguishes
	 * the three live hypotheses for the on-disk dinode(N)/leaf(N-1) skew:
	 *   seen=0            -> leaf buffer not in THIS node's cache / owner
	 *                        mismatch (daddr aliasing, family)
	 *   leaf>0 cand=0     -> leaf is CLEAN at release (already written, or
	 *                        evicted) -> the missing flush is elsewhere
	 *   cand>0 wrote>0    -> xfs_bwrite IS called; if P60-BMBTWRITE still 0
	 *                        the write short-circuits below xfs_bwrite
	 */
	if (flush && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		mxfs_probe_ratelimited(
			"mxfs: P61-BMBTSCAN ino=%llu if_nextents=%llu need_iread=%d seen=%d leaf=%d leafrecs=%d cand=%d wrote=%d mode=%u\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)ip->i_df.if_nextents,
			xfs_need_iread_extents(&ip->i_df) ? 1 : 0,
			p61_seen, p61_leaf, p61_leafrecs, p61_cand,
			p61_wrote, ip->i_dlm_mode);
	return durable;
}

/* OWNER-SCAN dir-data durability/flush.  DEFAULT ON.
 * Both mxfs_dir_data_durable and mxfs_dir_flush_data_blocks iterate the inode's
 * CURRENT in-core extent map (for_each_xfs_iext).  A dir DATA/leaf/free block
 * that was DIRTIED this EX tenure but is no longer in that map — because the
 * inode was RELOADED to a smaller disk map mid-tenure (the cached-EX stale-grant
 * demote / P62-RELOAD-FORK-SHRINK path), or the block's logical offset sits
 * beyond a stale/short in-core map — is NEVER seen by either path: the release
 * loop's data_durable reports the dir durable and hands EX to a peer while that
 * block is still only in-core+AIL, the peer cold-reads the lagging shared store
 * (stale base) and RMW+rewrites it, durably reverting our committed dirent (the
 * dir_reuse readdir=799 single-entry loss; PROVEN this session: node2_f29.md5
 * lost durably on ALL nodes incl creator, serialization clean).  This is the
 * EXTENT-MAP-INDEPENDENT companion: walk every AG's buffer cache for dir3
 * data/block/leaf/free/node buffers whose on-disk header owner == this inode and
 * land (flush mode) / report (check mode) every one carrying genuine pending
 * local work (dirty | in-AIL | pinned | delwri).  Modeled exactly on
 * mxfs_dir_bmbt_scan (same RCU-walk + non-sleeping hold + lock+recheck+bwrite),
 * so the lock context at each call site (check under i_lock-read like
 * bmbt_scan(false); flush from mxfs_dir_flush_data_blocks like bmbt_scan(true))
 * is identical.  ONLY dirty/in-AIL/pinned/delwri are landed — a live BLI is
 * authoritative for THIS inode's committed work (never an ABA reflush of a
 * reused daddr); a clean DONE-but-undestaged or evict-invalidated buffer is
 * deliberately left (matching the read-coherency invariants in the extent-map
 * path).  Multi-node + S_ISDIR only; bounded (a dir has a handful of blocks). */
/* PACE: per-dirop durability barriers are TRANSPORT-
 * scoped.  On TCP every peer read/modify coordinates through the DLM — a PR
 * or EX request BASTs the holder, whose release pipeline (Invariant 1, now
 * gen-aware + dwork-re-armed) drains dir data blocks AND the inode cluster
 * durable BEFORE the grant.  The per-create/unlink/rename barriers
 * (mxfs_dlm_dir_durable_signal flush + mxfs_dlm_dir_inode_durable) are
 * therefore redundant on TCP and cost ~7-10ms of synchronous log-force+FUA
 * per operation (run47 ddwatch: rm blocked in flush_one_daddr /
 * inode_cluster_durable per unlink; rm phase 10.6s for 800 unlinks).  CAW
 * KEEPS them: its disk-polling readers never BAST the holder, so per-op
 * publish is the only way peers see fresh state (/48/49 proven).
 * Set dirop_durable_tcp=1 to restore the legacy always-on barriers. */
/* DEFAULT 0 (final): with barriers ON the pace floor is
 * structural — P137/P128 timing shows ~14.5ms per rm-phase unlink (per-op
 * ifree log_force+drain+flush) and P138 ~10-13ms per file handoff, so
 * 24 rounds cannot fit 480s (best measured 21.2s/round, budget needs <20).
 * Barriers OFF met pace with 2x margin (run48: 8-14s/round).  The three
 * barrier-off failure families are handled at root instead: iunlink
 * B5-leak FIXED+verified (P2I/P2L, xfs_inactive); the leaf-bests MAP_HOLE
 * and round-1 dirent loss are under instrumented diagnosis (P2R/P2W/P2U
 * leaf provenance) — the release drain is the architecturally-intended
 * coherency mechanism on TCP (Invariant #1) and must be made airtight,
 * not masked per-op. */
int mxfs_dirop_durable_tcp = 0;
module_param_named(dirop_durable_tcp, mxfs_dirop_durable_tcp, int, 0644);

/* EXPERIMENT KNOB: per-op durable barriers on CAW.
 * Default 1 = the Road-B status quo (every create/remove/rename publishes
 * durably, ~14.5ms/unlink + ~7-10ms/create — dominates dir_reuse rounds:
 * measured 40s/round at 8/caw vs the 33s/round the 100*N budget allows).
 * Hypothesis tested: barriers REDUNDANT post-v0.6.4/0.6.5 because
 * caw_wait_for_grant() only grants on slot compatibility (no self-grant past
 * a live EX holder) and the release/demote drain is ungated on every
 * transport — so an acquiring peer always reads post-drain state.
 * REFUTED (instrumented 2a, 8/caw dir_reuse build 9C1728FB, 2026-07-06): with 0,
 * round 17 durably lost node8_f15 from readdir on ALL 8 nodes (799/800,
 * lookup_fail=0) — the dirent-loss family returns.  Root: CAW's coherency is
 * FUA-READ based — peers read the PLATTER, so anything parked in the target
 * write-back cache between release drains is invisible to them; per-op
 * platter publish is load-bearing, exactly as the Road-B comment above says
 * (/48/49).  Create-side pace with 0 did improve (create wave 9-16s ->
 * 2.7-7.5s early rounds), confirming the barriers ARE the create-phase cost,
 * but correctness rules the knob out.  KEEP DEFAULT 1; the knob remains for
 * future A/B only. */
int mxfs_dirop_durable_caw = 1;
module_param_named(dirop_durable_caw, mxfs_dirop_durable_caw, int, 0644);
MODULE_PARM_DESC(dirop_durable_caw,
	"Per-op dir durable-publish barriers on CAW transport (default 1)");

/* lightweight gate for the P2R-LEAFR/P2W-LEAFW dir-leaf
 * provenance probes (xfs_dir2_leaf.c verifiers).  Separate from mxfs.instr
 * (which is 100x-slow full instrumentation): leaf IO with barriers off is
 * per-release, not per-op, so these are cheap enough to keep on while the
 * leaf-bests MAP_HOLE family is under diagnosis. */
int mxfs_leafprobe = 0;	/* default 0 — the rm-phase P2R/P2W storm
			 * (~700 lines/s) throttles the serial console and
			 * costs real round pace; re-enable via modarg when
			 * chasing leaf provenance. */
module_param_named(leafprobe, mxfs_leafprobe, int, 0644);
MODULE_PARM_DESC(leafprobe,
	"Log dir leaf block read/write provenance (P2R-LEAFR/P2W-LEAFW; default 0)");

/* the storm-dir probe family (P9-LFREE, P13-LADD,
 * P11-DATALOG, P49-STALEBASE, P13-COLLIDE, P10-RDBLK, P-DIRWR) is scoped by
 * mxfs_ino_watched() (xfs_mxfs_dlm.h), which reuses the EXISTING
 * mxfs_watch_ino modparam (defined near the P-watch probes, ~line 22360):
 * 0 = legacy ino<=256; nonzero = ONLY that inode.  The dir_reuse test writes
 * the storm dir's ino each round; 1 = impossible-ino sentinel that silences
 * the family so earlier suite tests don't burn the probe caps. */
int mxfs_watch_light = 0;
module_param_named(watch_light, mxfs_watch_light, int, 0644);
MODULE_PARM_DESC(watch_light,
	"1 = watched-ino probes skip the heavy per-placement platter reads (near-natural timing)");

MODULE_PARM_DESC(dirop_durable_tcp,
	"Run per-dirop durability barriers on the TCP DLM transport too (1=legacy always-on; default 0: TCP relies on the BAST-release drain)");

/* instrumented probe: format the CURRENT task's transaction
 * held-AG set (t_mxfs_ag_unlocks = AG DLM grants this trans will release at
 * commit) — the discriminator for the run96 cross-AG convoy (test8 held
 * AG-14 122s while its mv blocked on AG-3 → test4's defer-finish rc=-110 →
 * shutdown): held set non-empty at the wait = true transactional
 * hold-and-wait (needs ordering/backoff); empty = only node-level caching
 * holds (honor pending BASTs on other cached AGs before blocking). */
void
mxfs_fmt_trans_held_ags(char *buf, size_t sz)
{
	struct xfs_trans *wtp = current->journal_info;
	struct mxfs_pending_ag_unlock *pe;
	size_t off = 0;

	buf[0] = '\0';
	if (!wtp)
		return;
	list_for_each_entry(pe, &wtp->t_mxfs_ag_unlocks, list) {
		off += scnprintf(buf + off, sz - off, "%u,",
				 pag_agno(pe->pag));
		if (off >= sz - 8)
			break;
	}
}

/*
 * Does the CURRENT task's transaction already retain `pag`'s AG grant
 * (t_mxfs_ag_unlocks: released at its commit)?  The obligation freeze in
 * __mxfs_ag_dlm_lock lets such a holder through: it was admitted before the
 * freeze, and the custodian waits for it to commit before its first
 * completion transaction.
 */
bool
mxfs_trans_retains_ag(struct xfs_perag *pag)
{
	struct xfs_trans *wtp = current->journal_info;
	struct mxfs_pending_ag_unlock *pe;

	if (!wtp)
		return false;
	list_for_each_entry(pe, &wtp->t_mxfs_ag_unlocks, list)
		if (pe->pag == pag)
			return true;
	return false;
}

/* format a shortform dir fork's entry names into buf —
 * shared by the dlm_fairness resurrection tracers (P8-SFRM at dirent remove,
 * P8-SFIFLUSH at the dinode platter copy, P8-SFADOPT at reload adopt).
 * Diagnostic only; callers gate on mxfs_dir_relverify. */
void
mxfs_sf_fmt_names(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *sfp,
		  char *buf, size_t sz)
{
	struct xfs_dir2_sf_entry *sfe;
	size_t off = 0;
	int i;

	if (!buf || sz < 16)
		return;
	buf[0] = '\0';
	if (!sfp)
		return;
	sfe = xfs_dir2_sf_firstentry(sfp);
	for (i = 0; i < sfp->count && off < sz - 14; i++) {
		int l = min_t(int, sfe->namelen, 11);

		off += scnprintf(buf + off, sz - off, "%.*s ", l, sfe->name);
		sfe = xfs_dir2_sf_nextentry(mp, sfp, sfe);
	}
}

/* stamp the EX-admission holder at every ex_holders 0->1
 * transition (caller holds i_dlm_lock at every ++ site).  b58r1 forensics:
 * both nodes' 184s stall was pinned by ONE live rm holding an EX admission
 * the whole time, blocked at an invisible wait site.  P36-MHT-REARM prints
 * these stamps and dumps the holder's stack at sustained-refusal strikes. */
void
mxfs_exh_stamp_locked(struct xfs_inode *ip)
{
	if (ip->i_dlm_ex_holders == 1) {
		ip->i_dlm_exh_pid = current->pid;
		strscpy(ip->i_dlm_exh_comm, current->comm,
			sizeof(ip->i_dlm_exh_comm));
		ip->i_dlm_exh_since_ns = ktime_get_real_ns();
	}
}

bool
mxfs_dirop_durable_needed(struct xfs_mount *mp)
{
	if (mxfs_dirop_durable_tcp)
		return true;
	if (!mp || !mp->m_mxfs_dlm)
		return true;
	if (mxfs_v5_dlm_is_tcp(mp->m_mxfs_dlm))
		return false;
	return mxfs_dirop_durable_caw != 0;	/* CAW A/B knob, default on */
}

int mxfs_dir_owner_scan = 1;	/* DEFAULT 1 — see below. The four
				 * coherency levers (owner_scan + grant_evict +
				 * modify_target_flush + release_flush_all_done) were
				 * each PROVEN INSUFFICIENT ALONE in prior sessions,
				 * but PROVED the COMBINATION drives 8/tcp
				 * dir_reuse_coherency to a clean 24-round PASS: each
				 * closes a different facet (owner_scan=acquire base
				 * coherency+release durability, grant_evict=RMW base
				 * refresh, target_flush=reader platter-lag pull,
				 * release_flush_all_done=writer push every DONE dir
				 * DATA block to the platter).  ORIGINAL 
				 * DEFAULT 0 — the two-sided owner-scan
				 * (release-flush + acquire retire-evict) is map-
				 * INDEPENDENT and the release-flush DID land real
				 * out-of-map blocks (P43-OWNERSCAN cand>0), but it
				 * did NOT fix the 8/tcp readdir=799 loss (PROVEN
				 * insufficient: release durability alone fails, and
				 * the acquire-evict is INERT — at the handoff the
				 * stale base is the node's OWN pinned/dirty work,
				 * not a clean cached block, so evicted=0).  The
				 * dland ring proved the loss is a stale-base RMW
				 * clobber (count 143->98: one node overwrites a
				 * peer's durable adds with its stale base) tangled
				 * with the rm-rf-per-round daddr REUSE stressor.
				 * Kept default-OFF (keeper-equivalent for 1/2/4)
				 * with the P43 probes for the next session's A/B. */
module_param_named(dir_owner_scan, mxfs_dir_owner_scan, int, 0644);
MODULE_PARM_DESC(dir_owner_scan,
	"owner-scan release flush+durability for dir blocks out of the in-core extent map (default 1)");

static bool
mxfs_dir_buf_is_owned_dir3(struct xfs_buf *bp, uint64_t ino)
{
	if (!bp->b_addr || !bp->b_ops)
		return false;
	if (bp->b_ops == &xfs_dir3_data_buf_ops ||
	    bp->b_ops == &xfs_dir3_block_buf_ops ||
	    bp->b_ops == &xfs_dir3_free_buf_ops)
		return be64_to_cpu(((struct xfs_dir3_blk_hdr *)
				    bp->b_addr)->owner) == ino;
	if (bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	    bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	    bp->b_ops == &xfs_da3_node_buf_ops)
		return be64_to_cpu(((struct xfs_da3_blkinfo *)
				    bp->b_addr)->owner) == ino;
	return false;
}

bool
mxfs_dir_data_owner_scan(struct xfs_inode *ip, bool flush)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
	bool			durable = true;
#define MXFS_OWNER_SCAN_MAX	64
	struct xfs_buf		*held[MXFS_OWNER_SCAN_MAX];
	int			nheld = 0, i;
	int			seen = 0, cand = 0, wrote = 0;

	if (!mxfs_dir_owner_scan)
		return true;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return true;
	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return true;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			struct xfs_buf_log_item	*bip;
			bool			needs;

			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (!mxfs_dir_buf_is_owned_dir3(bp, ip->i_ino))
				continue;
			seen++;
			bip = bp->b_log_item;
			/* genuine pending local work only (live BLI / pin /
			 * delwri) — never an ABA reflush of a clean stale buf.
			 * Require a valid, non-discarded in-core image: a !DONE
			 * buffer is evict-invalidated (nothing of ours to land,
			 * ) and an XBF_STALE buffer is a freed/binval'd
			 * block being reused (flushing it would clobber). */
			needs = (bp->b_flags & XBF_DONE) &&
				!(bp->b_flags & XBF_STALE) &&
				((bip && test_bit(XFS_LI_DIRTY,
						  &bip->bli_item.li_flags)) ||
				 (bip && test_bit(XFS_LI_IN_AIL,
						  &bip->bli_item.li_flags)) ||
				 xfs_buf_ispinned(bp) ||
				 (bp->b_flags & _XBF_DELWRI_Q));
			if (!needs)
				continue;
			durable = false;
			cand++;
			if (!flush || nheld >= MXFS_OWNER_SCAN_MAX)
				continue;
			/* non-sleeping hold under the walk's RCU section */
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				held[nheld++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}

	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = held[i];
		struct xfs_buf_log_item	*bip;

		xfs_buf_lock(bp);
		bip = bp->b_log_item;
		if ((bp->b_flags & XBF_DONE) &&
		    !(bp->b_flags & XBF_STALE) &&
		    ((bip && (test_bit(XFS_LI_DIRTY,
				      &bip->bli_item.li_flags) ||
			      test_bit(XFS_LI_IN_AIL,
				      &bip->bli_item.li_flags))) ||
		     xfs_buf_ispinned(bp) ||
		     (bp->b_flags & _XBF_DELWRI_Q))) {
			int werr;

			bp->b_flags &= ~_XBF_DELWRI_Q;
			/* drive the unpin (we hold bp locked; async log worker
			 * tick would otherwise stall us — same as bmbt_scan) */
			if (xfs_buf_ispinned(bp))
				xfs_log_force(mp, 0);
			werr = xfs_bwrite(bp);
			wrote++;
			if (werr)
				mxfs_probe_ratelimited(
					"mxfs: P43-OWNERSCAN-FLUSH-ERR ino=%llu daddr=%lld rc=%d\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn, werr);
		}
		xfs_buf_relse(bp);
	}

	if (ip->i_ino <= 256 && (cand || (flush && seen)))
		mxfs_probe_ratelimited(
			"mxfs: P43-OWNERSCAN ino=%llu flush=%d seen=%d cand=%d wrote=%d durable=%d fmt=%u\n",
			(unsigned long long)ip->i_ino, flush, seen, cand,
			wrote, durable, ip->i_df.if_format);
	return durable;
}

/* FIX-16 (PROVEN BY INSTRUMENT, run89 r6): the noino BAST release
 * (inode evicted — dominant source is our OWN verify-phase drop_caches on a
 * LIVE dir) unlocked with a committed-but-NEVER-WRITTEN dir data block
 * (daddr=94197064 lseq=168 wseq=0, dirty=0 pin=0 in_ail=0 delwri=0): this
 * block class is mxfs-seq-tracked and never enters the AIL, so the FIX-12
 * whole-AIL LSN fence is structurally blind to it.  The peer's PR grant then
 * FUA-read the pre-add platter (test1 readdir=758/800); our OWN next acquire
 * re-landed it 200ms later (P3R-RELAND) — too late.  This scan is the
 * map-independent (no inode needed) landing pass: walk every AG's buffer
 * cache for dir3 blocks OWNED by the releasing ino that are UNDESTAGED
 * (lseq!=wseq or pinned) and synchronously bwrite them before the unlock,
 * validating content (magic+owner) before re-marking a !DONE image (the
 * extent-walk reland's P3R logic).  For file inos the owner match finds
 * nothing and the walk is a cheap comparison pass.  Returns # written.
 *
 * (D-0491): land=false is the CHECK mode — count the owned undestaged
 * blocks without taking holds or writing, so a drain's caller can prove the
 * drain left nothing behind before it lets the on-disk grant go.  Returns the
 * count found. */
int
mxfs_dir_noino_land_scan(struct xfs_mount *mp, uint64_t ino, bool land)
{
	xfs_agnumber_t		agno;
	struct xfs_buf		*held[MXFS_OWNER_SCAN_MAX];
	int			nheld = 0, i, wrote = 0, found = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (!mxfs_dir_buf_is_owned_dir3(bp, ino))
				continue;
			if (!mxfs_dir_buf_is_undestaged(bp))
				continue;
			if (bp->b_flags & XBF_STALE)
				continue;
			found++;
			if (!land)
				continue;
			if (nheld >= MXFS_OWNER_SCAN_MAX)
				continue;
			/* non-sleeping hold under the walk's RCU section */
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				held[nheld++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}

	for (i = 0; i < nheld; i++) {
		struct xfs_buf	*bp = held[i];
		bool		content_ok;

		xfs_buf_lock(bp);
		if (!mxfs_dir_buf_is_undestaged(bp) ||
		    (bp->b_flags & XBF_STALE) ||
		    !mxfs_dir_buf_is_owned_dir3(bp, ino)) {
			xfs_buf_relse(bp);
			continue;
		}
		/* P3R logic: writing needs XBF_DONE ("content valid").  A
		 * !DONE undestaged image is still ours iff the header parses
		 * (magic already implied by the b_ops owner match above);
		 * garbage means log-only content — shout and skip rather
		 * than feed the write verifier a shutdown. */
		content_ok = (bp->b_flags & XBF_DONE) ||
			     (bp->b_addr && !bp->b_error);
		if (!content_ok) {
			pr_err("mxfs: P-NOINO-LAND-LOST ino=%llu daddr=%lld lseq=%llu wseq=%llu err=%d — undestaged dir block unrecoverable in core at noino release\n",
				(unsigned long long)ino,
				(long long)bp->b_maps[0].bm_bn,
				(unsigned long long)bp->b_mxfs_logged_seq,
				(unsigned long long)bp->b_mxfs_written_seq,
				bp->b_error);
			xfs_buf_relse(bp);
			continue;
		}
		mxfs_probe_ratelimited("mxfs: P-NOINO-LAND ino=%llu daddr=%lld lseq=%llu wseq=%llu done=%d — landing undestaged dir block at noino release\n",
			(unsigned long long)ino,
			(long long)bp->b_maps[0].bm_bn,
			(unsigned long long)bp->b_mxfs_logged_seq,
			(unsigned long long)bp->b_mxfs_written_seq,
			(bp->b_flags & XBF_DONE) ? 1 : 0);
		bp->b_flags |= XBF_DONE;
		bp->b_flags &= ~_XBF_DELWRI_Q;
		/* drive the unpin (we hold bp locked; the async log worker
		 * tick would otherwise stall us — owner-scan idiom) */
		if (xfs_buf_ispinned(bp))
			xfs_log_force(mp, 0);
		if (xfs_bwrite(bp))
			pr_err("mxfs: P-NOINO-LAND-ERR ino=%llu daddr=%lld write failed\n",
				(unsigned long long)ino,
				(long long)bp->b_maps[0].bm_bn);
		else
			wrote++;
		xfs_buf_relse(bp);
	}
	return land ? wrote : found;
}

/* OWNER-SCAN acquire-side EVICT — the READ-side
 * complement of mxfs_dir_data_owner_scan.  The acquire-side evict
 * (mxfs_dir_drain_evict_data_blocks) is ALSO extent-map-bound: a clean cached
 * dir DATA/leaf/free block owned by this inode that is no longer in the current
 * in-core map is NOT evicted, so a fresh-EX-grant RMW reads it STALE (missing a
 * peer's durable dirent) and rewrites it, durably reverting the peer's add (the
 * readdir=799 loss — PROVEN this session to PERSIST even after the release-side
 * owner-scan made every owned block durable, so the surviving mechanism is a
 * stale-base RMW on the acquirer, not a release-durability gap).  Walk every
 * AG's buffer cache for dir3 blocks owned by this inode and force-evict (clear
 * XBF_DONE + zero dir_gen so the next read FUA-cold-fetches the peer's durable
 * image) every CLEAN one — independent of the extent map.  CLEAN ONLY: a block
 * carrying genuine pending local work (dirty | pinned | delwri |
 * undestaged lseq!=wseq —: enforced in the loop guard, the
 * b57r5 -117 root was this loop running mid-tenure and destroying undestaged
 * committed mods) is OUR own un-checkpointed content and is LEFT (clearing its
 * DONE would lose it = resurrection); a DESTAGED in-AIL BLI is retired
 * (zombie — content already durable), and only a clean DONE base is a
 * prior-tenure stale image safe to drop (Inv 1 drained our work at our prior
 * release before the peer's intervening tenure).  Gated by the caller on a
 * real cross-node handoff (grant_gen changed) — but the fast-path caller
 * re-runs while dir_gen != loaded_gen, which a local-mod self-echo keeps true
 * mid-tenure, so the loop guard must stand alone.  Returns # evicted. */
int
mxfs_dir_evict_owned_data_blocks(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
	struct xfs_buf		*held[MXFS_OWNER_SCAN_MAX];
	int			nheld = 0, i, nevict = 0, seen = 0;

	if (!mxfs_dir_owner_scan)
		return 0;
	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return 0;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (!mxfs_dir_buf_is_owned_dir3(bp, ip->i_ino))
				continue;
			seen++;
			if (nheld >= MXFS_OWNER_SCAN_MAX)
				continue;
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				held[nheld++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}

	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = held[i];
		struct xfs_buf_log_item	*bip;

		xfs_buf_lock(bp);
		bip = bp->b_log_item;
		/* This is meant to run at a CONFIRMED cross-node handoff, where
		 * EVERY cached owned dir block is a PRIOR-TENURE base: a peer
		 * held EX since our last grant, and Inv 1 drained our prior work
		 * durable BEFORE that peer's tenure, so the peer's on-disk image
		 * is authoritative.  So:
		 *  - skip genuine in-flight bytes (pinned / open-txn dirty /
		 *    delwri) — clearing DONE on a pinned buf corrupts;
		 *    caught on a later pass;
		 *  - a lingering DESTAGED in-AIL BLI is a durable-or-superseded
		 *    ZOMBIE — RETIRE it (xfs_buf_item_done) so no later xfsaild
		 *    push reflushes our stale image over the peer's add (the
		 *    P34-NEWTENURE-RETIRE justification, map-independently);
		 *  - then clear XBF_DONE so the next read FUA-cold-fetches the
		 *    peer's durable block.
		 *
		 * (b57r5 -117 ROOT, PROVEN BY INSTRUMENT): the caller
		 * gates do NOT guarantee tenure-start.  The fast-path caller
		 * (~22170) re-runs the refresh on EVERY acquire while
		 * dir_gen != loaded_gen — and a local modify's self-echo gen
		 * bump keeps that true MID-TENURE, so this loop ran repeatedly
		 * DURING one continuous EX hold (P43-OWNEREVICT evicted=2 ×3 in
		 * 20ms) and its retire+DONE-clear DESTROYED the only copy of
		 * this tenure's committed-unwritten dir mods (lseq>wseq).  The
		 * next cold-read re-fetched the pre-mod platter image for the
		 * DATA block while the LEAF kept the modified image (P5 salvage)
		 * → bestsp[db] != bf[0].length → -117 dirty-cancel → shutdown.
		 * Guard: an UNDESTAGED (lseq!=wseq) block is THIS node's
		 * committed-unwritten content — never a prior-tenure base
		 * (prior-tenure work was drained at our release, Inv 1, so it
		 * carries lseq==wseq) — LEAVE it, exactly as this function's
		 * header always promised.  P48 names any skip for forensics. */
		if (!(bp->b_flags & XBF_DONE) ||
		    (bp->b_flags & XBF_STALE) ||
		    xfs_buf_ispinned(bp) ||
		    (bp->b_flags & _XBF_DELWRI_Q) ||
		    (bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) ||
		    mxfs_dir_buf_is_undestaged(bp)) {
			/* (instrumented): a CONFIRMED-handoff owned dir block that
			 * is still dirty/pinned/delwri/!DONE is a STALE-BASE SURVIVOR
			 * — our prior tenure's work that the release drain did NOT
			 * force-complete (Inv 1 gap).  It is skipped here, so the
			 * imminent RMW serves it as a stale base (the residual .md5
			 * single-dirent lost-update).  Log it to prove the gap. */
			if (ip->i_ino <= 256)
				mxfs_probe_ratelimited(
					"mxfs: P48-OWNEREVICT-DIRTYSKIP ino=%llu daddr=%lld dirty=%d pin=%d delwri=%d done=%d inail=%d undest=%d lseq=%llu wseq=%llu — kept (in-flight or undestaged this-tenure work)\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn,
					(int)(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)),
					xfs_buf_ispinned(bp),
					!!(bp->b_flags & _XBF_DELWRI_Q),
					!!(bp->b_flags & XBF_DONE),
					(int)(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)),
					(int)mxfs_dir_buf_is_undestaged(bp),
					(unsigned long long)bp->b_mxfs_logged_seq,
					(unsigned long long)bp->b_mxfs_written_seq);
			xfs_buf_relse(bp);
			continue;
		}
		if (bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) {
			bp->b_mxfs_done_site = MXFS_SITE;
			xfs_buf_item_done(bp, XFS_BLI_NO_IODONE);	/* ail_delete + relse BLI */
			bip = NULL;
		}
		bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
		bp->b_mxfs_dir_gen = 0;
		nevict++;
		xfs_buf_relse(bp);
	}

	if (ip->i_ino <= 256 && (seen || nevict))
		mxfs_probe_ratelimited(
			"mxfs: P43-OWNEREVICT ino=%llu seen=%d evicted=%d fmt=%u\n",
			(unsigned long long)ip->i_ino, seen, nevict,
			ip->i_df.if_format);
	return nevict;
}

/*
 * WRITER-SIDE ORDERING FIX (instrumented, PROVEN root in
 * `docs/history/zsl-root-di-ahead-of-bmbt-leaf-ordering.md` /
 * `docs/history/zsl-bmbt-leaf-write-essentially-never-submitted.md`):
 *
 * zero_silent_loss's 1600-silent cascade is a single early FS shutdown: a
 * reloading peer reads an on-disk dinode whose di_nextents=N while the matching
 * on-disk bmbt leaf still holds only N-1 records (ir.loaded != if_nextents at
 * xfs_bmap.c:1286 -> EFSCORRUPTED -> shutdown -> whole 16-node storm cascades).
 *
 * The skew is NOT a stale clobber and NOT a missing release-path flush — it is
 * an ORDERING leak through BACKGROUND writeback: xfsaild's xfs_inode_item_push
 * -> xfs_iflush_cluster -> xfs_iflush publishes the inode CLUSTER (di_nextents=N)
 * to the coherent SCST store while the dir's bmbt LEAF (record N) is still only
 * dirty/in-AIL in this node and has NOT reached disk.  The grower may be killed
 * by the cascade before it ever RELEASES (run d: di=16 flushed, no node ever
 * wrote leaf=16), so the release-path mxfs_dir_bmbt_scan never gets to land it.
 *
 * Fix: couple the two at the flush boundary.  This is called from xfs_iflush,
 * UNDER the inode ILOCK (so in-core di_nextents cannot advance) and BEFORE
 * xfs_iflush_fork copies the fork into the on-disk dinode.  At that point the
 * inode is committed/unpinned (xfs_inode_item_push gates on ipincount), so its
 * bmbt leaves are committed too — we just destage them synchronously
 * (xfs_bwrite via mxfs_dir_bmbt_scan flush mode) so every leaf record N is
 * DURABLE before the cluster buffer carrying di_nextents=N is even queued.
 * Reader-side FUA cannot help here (fua_disable=1 => coherent SCST cache); only
 * leaf-before-dinode write ordering removes the skew.  BTREE-format dir/file
 * data forks only (mxfs_dir_bmbt_scan no-ops other formats); multi-node only.
 */
atomic_t mxfs_iflush_bmbt_durable_calls = ATOMIC_INIT(0);

/* D-0973: clean cached bmbt blocks an inode flush declined to destage
 * because the fork was unread (adopted, unchanged since), and blocks it
 * destaged anyway because they carried local modifications (detector).
 * Registered as parameters beside iomap_iread_pr. */
atomic_t mxfs_iflush_unread_clean_skip = ATOMIC_INIT(0);
atomic_t mxfs_iflush_unread_local = ATOMIC_INIT(0);
/* Owned bmbt blocks the reload's eviction walk saw but could not hold. */
atomic_t mxfs_bmbt_evict_capped = ATOMIC_INIT(0);
/* D-0974 detectors: owned bmbt blocks an inode flush's destage walk dropped
 * at its hold cap, and blocks it skipped for !XBF_DONE that carried local
 * work (dirty, in the AIL, pinned, or logged since last written). */
atomic_t mxfs_iflush_bmbt_capped = ATOMIC_INIT(0);
atomic_t mxfs_iflush_bmbt_notdone_needs = ATOMIC_INIT(0);

void
mxfs_iflush_force_bmbt_durable(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
#define MXFS_BMBT_FORCE_MAX	64
	struct xfs_buf		*held[MXFS_BMBT_FORCE_MAX];
	int			nheld = 0, i, wrote = 0, leafsum = 0;
	int			ncapped = 0, nnotdone = 0, nnotdone_needs = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		MXFS_SOLE_SKIP_NOTE(mp->m_mxfs_dlm, "iflush_force_bmbt_durable");
		return;
	}
	if (ip->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return;

	atomic_inc(&mxfs_iflush_bmbt_durable_calls);

	/*
	 * the leaf-vs-dinode ordering bug is NOT a missing flush of a
	 * DIRTY leaf — at this point P61-BMBTSCAN shows the in-core leaf is
	 * already CLEAN (XBF_DONE, BLI not dirty/in-AIL) with N records, yet the
	 * on-disk leaf still holds N-1 (the bio that should have landed N never
	 * did / was superseded).  So mxfs_dir_bmbt_scan(true), which only writes
	 * dirty/in-AIL/pinned leaves, skips it (cand=0) and di_nextents=N is then
	 * published ahead of the stale on-disk leaf.  We hold the ILOCK here, so
	 * the in-core extent map (iext + bmbt leaves) is frozen and authoritative.
	 * UNCONDITIONALLY destage every cached bmbt block owned by this inode —
	 * even a "clean" one — so the leaf image about to be referenced by the
	 * di_nextents we are serializing is guaranteed durable on the shared SCST
	 * store first.  Bounded (a dir has a handful of bmbt blocks); skip a
	 * buffer that has no in-core image (!XBF_DONE = invalidated, nothing of
	 * ours to land).
	 */
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr)
				continue;
			if (be64_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_u.l.bb_owner) != ip->i_ino)
				continue;
			if (!(bp->b_flags & XBF_DONE)) {
				/* D-0974 detector: a block never read or
				 * written has no XBF_DONE yet may carry
				 * committed content the LUN lacks (racy flag
				 * reads under RCU: a count, not a decision). */
				struct xfs_buf_log_item	*nbip = bp->b_log_item;

				nnotdone++;
				if (xfs_buf_ispinned(bp) ||
				    (nbip && (test_bit(XFS_LI_DIRTY,
						       &nbip->bli_item.li_flags) ||
					      test_bit(XFS_LI_IN_AIL,
						       &nbip->bli_item.li_flags))) ||
				    (!(bp->b_flags & XBF_STALE) &&
				     mxfs_dir_buf_is_undestaged(bp)))
					nnotdone_needs++;
				continue;
			}
			if (nheld >= MXFS_BMBT_FORCE_MAX) {
				ncapped++;	/* D-0974 detector */
				continue;
			}
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				held[nheld++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}
	if (ncapped || nnotdone_needs) {
		atomic_add(ncapped, &mxfs_iflush_bmbt_capped);
		atomic_add(nnotdone_needs, &mxfs_iflush_bmbt_notdone_needs);
		mxfs_probe_ratelimited("mxfs: P974-DESTAGE-GAP ino=%llu if_nextents=%llu held=%d capped=%d notdone=%d notdone_needs=%d need_iread=%d broot_lvl=%d comm=%s — owned bmbt blocks this flush will not destage\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)ip->i_df.if_nextents,
			nheld, ncapped, nnotdone, nnotdone_needs,
			xfs_need_iread_extents(&ip->i_df) ? 1 : 0,
			ip->i_df.if_broot ?
				be16_to_cpu(ip->i_df.if_broot->bb_level) : -1,
			current->comm);
	}

	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = held[i];
		struct xfs_btree_block	*lblk;
		int			werr;

		xfs_buf_lock(bp);
		if (!(bp->b_flags & XBF_DONE)) {	/* invalidated under us */
			xfs_buf_relse(bp);
			continue;
		}
		/*
		 * D-0973: "the in-core map is authoritative" holds only once
		 * the fork has been loaded.  With the extents unread the fork
		 * was adopted from disk at a reload and nothing here has
		 * changed it since, so a clean cached block is at best the
		 * image already on disk and at worst this node's pre-reload
		 * image of a leaf a peer has since rewritten — which this loop
		 * wrote over the peer's leaf while the flush published the
		 * peer's di_nextents (measured: 1818 torn flushes when the
		 * reload did not evict a regular file's leaves).  Destage only
		 * what carries local modifications; count any such block, since
		 * an unread fork holding local bmbt work means the reload did
		 * not retire this node's previous tenure.
		 */
		if (xfs_need_iread_extents(&ip->i_df)) {
			struct xfs_buf_log_item	*ubip = bp->b_log_item;
			bool			local = xfs_buf_ispinned(bp) ||
				mxfs_dir_buf_is_undestaged(bp) ||
				(ubip && (test_bit(XFS_LI_DIRTY,
						   &ubip->bli_item.li_flags) ||
					  test_bit(XFS_LI_IN_AIL,
						   &ubip->bli_item.li_flags)));

			if (!local) {
				atomic_inc(&mxfs_iflush_unread_clean_skip);
				xfs_buf_relse(bp);
				continue;
			}
			atomic_inc(&mxfs_iflush_unread_local);
			mxfs_probe_ratelimited("mxfs: P973-UNREAD-LOCAL ino=%llu daddr=%lld pin=%d undestaged=%d comm=%s — unread fork holds local bmbt work\n",
				(unsigned long long)ip->i_ino,
				(long long)bp->b_maps[0].bm_bn,
				xfs_buf_ispinned(bp),
				mxfs_dir_buf_is_undestaged(bp), current->comm);
		}
		lblk = (struct xfs_btree_block *)bp->b_addr;
		/*
		 * WRITER-SIDE ROOT FIX (zero_silent_loss): the in-core
		 * bmbt LEAF buffer can lag the authoritative in-core iext tree
		 * (P63-TORN-FLUSH: leafsum=N-1 while if_nextents=N) — either a
		 * stale plain-bio read DMA'd the OLDER on-disk leaf over a
		 * checkpointed-clean buffer, or xfs_btree_insert grew iext but not
		 * this cached leaf (P63-INSERT-DESYNC).  Destaging the lagged leaf
		 * and then publishing di_nextents=N (the caller copies it
		 * immediately after we return) tears the on-disk dinode<->bmbt
		 * pair, which a reloading peer reads as ir.loaded(N-1) !=
		 * if_nextents(N) -> EFSCORRUPTED -> the 16-node storm's silent
		 * loss.  We hold the ILOCK, so the iext tree is frozen and
		 * authoritative.  For a SINGLE-LEAF tree (broot_nrecs==1, every
		 * extent lives in this one leaf), re-serialize the leaf's records
		 * straight from the iext list so the durable leaf matches exactly
		 * the di_nextents about to be written.  Mirrors the leaf-fill in
		 * xfs_bmap_extents_to_btree.  Bounded by the single-leaf capacity
		 * (m_bmap_dmxr[0]); skip if extents are not in-core (need_iread =
		 * nothing of ours to reconcile) or the tree is multi-leaf.
		 */
		if (be16_to_cpu(lblk->bb_level) == 0 &&
		    ip->i_df.if_broot &&
		    be16_to_cpu(ip->i_df.if_broot->bb_numrecs) == 1 &&
		    !xfs_need_iread_extents(&ip->i_df) &&
		    (unsigned long long)be16_to_cpu(lblk->bb_numrecs) !=
			ip->i_df.if_nextents &&
		    ip->i_df.if_nextents <= (xfs_extnum_t)mp->m_bmap_dmxr[0]) {
			struct xfs_iext_cursor	icur;
			struct xfs_bmbt_irec	rec;
			struct xfs_bmbt_rec	*arp;
			uint16_t		old_nr =
				be16_to_cpu(lblk->bb_numrecs);
			int			cnt = 0;

			for_each_xfs_iext(&ip->i_df, &icur, &rec) {
				if (isnullstartblock(rec.br_startblock))
					continue;
				arp = xfs_bmbt_rec_addr(mp, lblk, 1 + cnt);
				xfs_bmbt_disk_set_all(arp, &rec);
				cnt++;
			}
			if ((xfs_extnum_t)cnt == ip->i_df.if_nextents) {
				lblk->bb_numrecs = cpu_to_be16(cnt);
				mxfs_probe("mxfs: P64-LEAF-REBUILD ino=%llu daddr=%lld old_numrecs=%u new_numrecs=%d if_nextents=%llu comm=%s\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn,
					old_nr, cnt,
					(unsigned long long)ip->i_df.if_nextents,
					current->comm);
			}
		}
		if (be16_to_cpu(lblk->bb_level) == 0)
			leafsum += be16_to_cpu(lblk->bb_numrecs);
		if (xfs_buf_ispinned(bp))
			xfs_log_force(mp, 0);
		bp->b_flags &= ~_XBF_DELWRI_Q;
		werr = xfs_bwrite(bp);		/* returns with bp locked */
		wrote++;
		if (werr)
			mxfs_probe_ratelimited(
				"mxfs: P62-IFLUSH-FORCE-ERR ino=%llu daddr=%lld rc=%d\n",
				(unsigned long long)ip->i_ino,
				(long long)bp->b_maps[0].bm_bn, werr);
		xfs_buf_relse(bp);
	}

	/*
	 * (zero_silent_loss — Face-A nheld=0 hole + Face-B root, design-consult
	 * design review fabrication recipe).  The destage loop above only covers bmbt
	 * leaves that are CACHED (XBF_DONE) on THIS node.  Proven residual
	 * (P63-TORN-FLUSH ... leafsum=0 nheld=0): the single leaf is NOT in our
	 * buffer cache at iflush — it was reclaimed/unhashed mid-tenure — so the
	 * loop finds nothing and di_nextents=N is then published over whatever the
	 * on-disk leaf last held (N-1 / stale).  A peer that reloads trips
	 * ir.loaded != if_nextents (Face A); and the next acquirer's lazy
	 * xfs_iread_extents cold-reads (cache-miss) that same stale leaf, so its
	 * leaf=N-1 vs iext=N and the LEFT_CONTIG merge in the next mkdir shuts the
	 * FS down (Face B).  We hold ILOCK (iext frozen + authoritative) and own
	 * the inode EX (no peer can read the intermediate), and this is a
	 * SINGLE-LEAF tree (if_broot level 1, one child), so reconstruct the whole
	 * leaf straight from the authoritative iext list and destage it BEFORE the
	 * caller publishes di_nextents.  Instantiate via xfs_buf_get (NOT read — we
	 * must never DMA the stale on-disk image; xfs_bmbt_init_block + the iext
	 * fill rewrite the entire block).  Same no-log force-write idiom as the
	 * cached rebuild above (xfs_iflush already advances on-disk state without
	 * logging).  Fires only on the bug (leafsum != if_nextents).
	 */
	if ((int)leafsum != (int)ip->i_df.if_nextents &&
	    ip->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    ip->i_df.if_broot &&
	    be16_to_cpu(ip->i_df.if_broot->bb_level) == 1 &&
	    be16_to_cpu(ip->i_df.if_broot->bb_numrecs) == 1 &&
	    !xfs_need_iread_extents(&ip->i_df) &&
	    ip->i_df.if_nextents <= (xfs_extnum_t)mp->m_bmap_dmxr[0]) {
		__be64		*pp = xfs_bmap_broot_ptr_addr(mp,
					ip->i_df.if_broot, 1,
					ip->i_df.if_broot_bytes);
		xfs_fsblock_t	fsbno = be64_to_cpu(*pp);

		if (xfs_verify_fsbno(mp, fsbno)) {
			struct xfs_buf	*lbp = NULL;
			xfs_daddr_t	d = XFS_FSB_TO_DADDR(mp, fsbno);

			if (xfs_buf_get(mp->m_ddev_targp, d, mp->m_bsize,
					&lbp) == 0 && lbp) {
				struct xfs_buf_log_item *lbip = lbp->b_log_item;
				bool		dirty = lbip &&
					test_bit(XFS_LI_DIRTY,
						 &lbip->bli_item.li_flags);
				bool		in_ail = lbip &&
					test_bit(XFS_LI_IN_AIL,
						 &lbip->bli_item.li_flags);

				/*
				 * If the leaf is genuinely live on this node
				 * (dirty / in-AIL / pinned) the cached loop
				 * above owns it — don't fabricate over our own
				 * un-landed log state.
				 */
				if (dirty || in_ail || xfs_buf_ispinned(lbp) ||
				    (lbp->b_flags & _XBF_DELWRI_Q)) {
					mxfs_probe_ratelimited(
					    "mxfs: P65-LEAF-FAB-SKIP ino=%llu daddr=%lld dirty=%d in_ail=%d pin=%d\n",
					    (unsigned long long)ip->i_ino,
					    (long long)d, dirty, in_ail,
					    xfs_buf_ispinned(lbp));
					xfs_buf_relse(lbp);
				} else {
					struct xfs_btree_block	*lblk =
						(struct xfs_btree_block *)
						lbp->b_addr;
					uint16_t	had =
						(lbp->b_flags & XBF_DONE) ?
						be16_to_cpu(lblk->bb_numrecs) :
						0xffff;
					struct xfs_iext_cursor	icur;
					struct xfs_bmbt_irec	rec;
					struct xfs_bmbt_rec	*arp;
					int		cnt = 0, werr;

					lbp->b_ops = &xfs_bmbt_buf_ops;
					xfs_bmbt_init_block(ip, lblk, lbp, 0, 0);
					for_each_xfs_iext(&ip->i_df, &icur,
							  &rec) {
						if (isnullstartblock(
						    rec.br_startblock))
							continue;
						arp = xfs_bmbt_rec_addr(mp,
							lblk, 1 + cnt);
						xfs_bmbt_disk_set_all(arp,
							&rec);
						cnt++;
					}
					if ((xfs_extnum_t)cnt ==
					    ip->i_df.if_nextents) {
						lblk->bb_numrecs =
							cpu_to_be16(cnt);
						lbp->b_flags &= ~_XBF_DELWRI_Q;
						/* the
						 * FUA-path tenure gate now runs
						 * for every bmbt write; stamp
						 * this reconstructed image as
						 * THIS-tenure-authoritative
						 * (built under ILOCK+EX from
						 * the live iext) so the gate
						 * passes it. */
						lbp->b_tenure_id =
							ip->i_mxfs_ex_grant_seq;
						werr = xfs_bwrite(lbp);
						if (!werr) {
							leafsum = cnt;
							wrote++;
						}
						mxfs_probe("mxfs: P65-LEAF-FABRICATE ino=%llu daddr=%lld had=%u new=%d if_nextents=%llu rc=%d comm=%s\n",
							(unsigned long long)ip->i_ino,
							(long long)d, had, cnt,
							(unsigned long long)ip->i_df.if_nextents,
							werr, current->comm);
					}
					xfs_buf_relse(lbp);
				}
			}
		}
	}

	/*
	 * DECISIVE WRITER-SIDE REGRESSION DETECTOR
	 * (instrumented, the path handed off): PROVED the on-disk
	 * (dinode di_nextents, bmbt-leaf records) pair is genuinely inconsistent
	 * ON DISK even after P70 FUA-rereads the dinode — so a writer durably
	 * wrote a di_nextents LOWER than a peer's committed grow, reverting it.
	 * We are inside xfs_iflush holding the ILOCK, about to let the caller
	 * copy if_nextents into the on-disk dinode (xfs_inode_to_disk, right
	 * after we return).  Plain-read THIS inode's on-disk cluster (fua_disable=1
	 * => plain bio hits the coherent SCST cache = the cluster coherence point)
	 * and compare the CURRENT on-disk di_nextents to the if_nextents we are
	 * about to publish.  If on-disk > if_nextents we are about to REGRESS the
	 * extent count = durably revert a peer's grow = the torn pair a reloading
	 * peer reads as EFSCORRUPTED (over-count) -> zero_silent_loss.  Always-on,
	 * rate-limited, fires ONLY on the regression (a normal grow has on-disk <=
	 * if_nextents).  DIR BTREE inodes, multi-node only.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
		uint32_t	clen = BBTOB(ip->i_imap.im_len);
		void		*dbuf = ((clen & 511) == 0 && clen) ?
					kmalloc(clen, GFP_NOFS) : NULL;

		if (dbuf) {
			extern int mxfs_pal_bdev_read_plain_bdev(
				struct block_device *, uint64_t, void *,
				uint32_t);
			uint64_t	lba = (uint64_t)ip->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset;

			if (mxfs_pal_bdev_read_plain_bdev(
				    mp->m_ddev_targp->bt_bdev, lba, dbuf,
				    clen) == 0) {
				struct xfs_dinode *odip =
					dbuf + ip->i_imap.im_boffset;
				unsigned long long disk_nx =
					be32_to_cpu(odip->di_nextents);

				if (be16_to_cpu(odip->di_magic) ==
					MXFS_DINODE_MAGIC &&
				    odip->di_format == XFS_DINODE_FMT_BTREE &&
				    disk_nx > ip->i_df.if_nextents)
					mxfs_probe_ratelimited(
						"mxfs: P74-DINEXT-REGRESS ino=%llu about_to_write_nx=%llu disk_nx=%llu leafsum=%d disk_size=%lld incore_size=%lld comm=%s — WRITER reverting peer grow (torn pair)\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)ip->i_df.if_nextents,
						disk_nx, leafsum,
						(long long)be64_to_cpu(odip->di_size),
						(long long)ip->i_disk_size,
						current->comm);
			}
			kfree(dbuf);
		}
	}

	/*
	 * (zero_silent_loss): NON-ratelimited torn-flush detector.  This
	 * is the EXACT bug condition: we are inside xfs_iflush, about to copy
	 * di_nextents (= if_nextents) into the on-disk dinode, but the durable
	 * leaf record sum (leafsum, across every cached level-0 bmbt leaf we just
	 * destaged) is LESS than if_nextents -> a reloading peer reads di=N over a
	 * leaf=N-1 -> SIG1 ir.loaded != if_nextents -> shutdown.  Because P62
	 * above is pr_warn_ratelimited, the decisive di=17/leaf=16 flush was being
	 * SUPPRESSED.  Single-leaf dirs only (broot_nrecs==1), so leafsum must
	 * equal if_nextents on a consistent map; fires only on the tear.
	 *
	 * D-0973: not on an unread fork.  Its count was adopted from disk with
	 * the leaves a peer wrote, and the loop above no longer destages clean
	 * cached leaves then, so leafsum is 0 by construction and says nothing
	 * about what is on disk.
	 */
	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    !xfs_need_iread_extents(&ip->i_df) &&
	    ip->i_df.if_broot &&
	    /* one leaf only when the in-inode root is level 1: a level-2 root
	     * with one pointer names an interior node over many leaves, of
	     * which leafsum counts only the cached ones (measured: 42 false
	     * tears on a two-level regular-file tree, if_nextents 2719..3819) */
	    be16_to_cpu(ip->i_df.if_broot->bb_level) == 1 &&
	    be16_to_cpu(ip->i_df.if_broot->bb_numrecs) == 1 &&
	    (unsigned long long)leafsum != ip->i_df.if_nextents)
		mxfs_probe("mxfs: P63-TORN-FLUSH ino=%llu if_nextents=%llu leafsum=%d nheld=%d wrote=%d broot_nrecs=%u comm=%s\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)ip->i_df.if_nextents, leafsum,
			nheld, wrote,
			be16_to_cpu(ip->i_df.if_broot->bb_numrecs),
			current->comm);

	if (mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		mxfs_probe_ratelimited(
			"mxfs: P62-IFLUSH-FORCE ino=%llu if_nextents=%llu nheld=%d wrote=%d leafsum=%d broot_lvl=%u broot_nrecs=%u comm=%s\n",
			(unsigned long long)ip->i_ino,
			(unsigned long long)ip->i_df.if_nextents,
			nheld, wrote, leafsum,
			ip->i_df.if_broot ?
				be16_to_cpu(ip->i_df.if_broot->bb_level) : 0xffff,
			ip->i_df.if_broot ?
				be16_to_cpu(ip->i_df.if_broot->bb_numrecs) : 0,
			current->comm);
}

/*
 * ROOT FIX (instrumented, PROVEN by the post-reload EFSCORRUPTED shutdown:
 * "corrupt dinode 131 (btree extents)" at xfs_iread_bmbt_block, caller
 * xfs_create, on a BTREE-format shared storm dir).  When a dir's extent map
 * is BTREE-format, the map lives in separate bmbt (extent-map btree) blocks
 * in the AGs, NOT in the dinode literal area.  mxfs_dlm_reload_inode
 * invalidates the inode CLUSTER buffer (the dinode = bmbt ROOT in if_broot)
 * but leaves the cached bmbt CHILD blocks untouched, and
 * mxfs_dir_drain_evict_data_blocks only evicts DATA-fork blocks (and bails
 * outright for a just-reloaded BTREE fork whose extents are not yet read).
 * So after a reload adopts a peer's fresh bmbt root, the next
 * xfs_iread_extents walks that root into a STALE cached child block whose
 * tree shape (level / numrecs / keys) does not match -> xfs_iread_bmbt_block
 * flags it corrupt -> xfs_trans_cancel -> FS shutdown.  The on-disk child is
 * coherent (the releaser flushed it via mxfs_dir_bmbt_scan); only OUR cache
 * is stale.  Evict (clear XBF_DONE) every clean cached bmbt block owned by
 * this inode so the lazy extent read cold-fetches the peer's coherent
 * children.  Same evict idiom as the data-block path: never xfs_buf_stale
 * (drops the rhashtable entry the AIL still refs); never clear DONE on a
 * pinned buffer (corruption); leave undestaged-in-AIL blocks (our own
 * un-landed work) for the next pass.
 */
void
mxfs_dir_evict_bmbt_blocks(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
#define MXFS_BMBT_EVICT_MAX	64
	struct xfs_buf		*held[MXFS_BMBT_EVICT_MAX];
	int			nheld = 0, i;
	/*
	 * walk-level counters to settle the
	 * OPEN question — when the stale leaf survives, is it a rhashtable-walk
	 * MISS (case a) or a found-but-skipped transient pin/dirty (case b)?
	 * nseen_bmbt = bmbt-format bufs the walk saw (any owner); nthisino =
	 * those owned by THIS inode; ncapped = those dropped by the 64-entry
	 * held[] cap.  If the storm's stale leaf daddr never appears in a
	 * P67-EVICT-SKIP/P59-EVICT line AND nthisino is short of the expected
	 * leaf count, the walk never held it (case a, b_ops/owner-invisible);
	 * if nheld < nthisino with ncapped>0 the 64-cap dropped it (raise cap).
	 */
	int			nseen_bmbt = 0, nthisino = 0, ncapped = 0;
	/*
	 * D-0973: the hold array is a batch size, never a limit.  A regular
	 * file's tree can have far more cached blocks than 64: with ~20k
	 * extents the walk left 21773-26941 owned blocks cached per lap, and
	 * the next extent load read those stale leaves (579 mismatches, every
	 * write on that node failed).  When the walk sees more than it can
	 * hold, it drops its holds, sizes the array to what it saw and walks
	 * again; bmbt_evict_capped counts only what is still left after that.
	 */
	struct xfs_buf		**hold = held;
	int			hcap = MXFS_BMBT_EVICT_MAX, attempt;

	if (ip->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return;

	for (attempt = 0; ; attempt++) {
	nheld = nseen_bmbt = nthisino = ncapped = 0;
	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		struct xfs_perag	*pag = xfs_perag_get(mp, agno);
		struct rhashtable_iter	iter;
		struct xfs_buf		*bp;

		if (!pag)
			continue;
		rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
		rhashtable_walk_start(&iter);
		while ((bp = rhashtable_walk_next(&iter))) {
			if (IS_ERR(bp)) {
				if (PTR_ERR(bp) == -EAGAIN)
					continue;
				break;
			}
			if (bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr)
				continue;
			nseen_bmbt++;
			if (be64_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_u.l.bb_owner) !=
			    ip->i_ino)
				continue;
			nthisino++;
			if (nheld >= hcap) {
				ncapped++;
				continue;
			}
			/* non-sleeping hold under the walk's RCU section */
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				hold[nheld++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
	}
	if (!ncapped || attempt >= 2)
		break;
	{
		struct xfs_buf	**bigger;
		int		ncap = nthisino + 64;

		bigger = kmalloc_array(ncap, sizeof(*bigger),
				       GFP_NOFS | __GFP_NOWARN);
		if (!bigger)
			break;		/* evict what is held; count the rest */
		for (i = 0; i < nheld; i++)
			xfs_buf_rele(hold[i]);
		if (hold != held)
			kfree(hold);
		hold = bigger;
		hcap = ncap;
	}
	}

	/*
	 * drain a pin-ONLY stale bmbt leaf before
	 * evicting it — the proven /acquire-side fix, previously
	 * applied ONLY to dir DATA blocks (mxfs_dir_drain_evict_data_blocks).
	 * This function runs at an EX reload (need_iread=1 — the only caller,
	 * mxfs_dir_drain_evict_data_blocks), where a peer's grow has already
	 * made the dir's bmbt durable on the platter, so OUR cached leaf is
	 * stale.  But it is often pin-ONLY (pinned && !dirty && !in_ail && DONE)
	 * — this node's own already-committed prior-tenure work whose async CIL
	 * unpin tail just hasn't fired.  The old code SKIPPED it (clearing
	 * XBF_DONE on a pinned buffer corrupts —), so xfs_iread_extents
	 * cold-read the STALE cached leaf (record count N-1) against the freshly
	 * reloaded dinode (di_nextents=N) -> P59-IREAD-MISMATCH loaded=N-1
	 * if_nextents=N -> EFSCORRUPTED shutdown (PROVEN test11/test12, 16-node
	 * dpn=100 storm; P133-BMBT-STALE-SKIP dirty=0 in_ail=0 pin=1).  Drive
	 * the commit with one sync log force, bounded-wait the unpin, then evict
	 * so the read cold-fetches the peer's coherent leaf.  Pin-ONLY ONLY: a
	 * dirty/in-AIL leaf carries un-written local content and is left to the
	 * release-side durability machinery (clearing its DONE would clobber the
	 * peer).  No i_lock held here (the caller evicts before its snapshot)
	 * and we run off the CAW poll thread (process ctx), so blocking is safe.
	 */
	/* ALWAYS-ON capped — run 075216Z had ZERO evictions
	 * and ZERO skips across a full failing run, so either reloads never
	 * find cached children (walk-miss, case a) or children are
	 * never cached at reload.  These counters settle it. */
	/* D-0973 detector, uncapped: owned bmbt blocks this walk saw but did
	 * not hold (the held[] cap), each one left cached with XBF_DONE. */
	if (ncapped)
		atomic_add(ncapped, &mxfs_bmbt_evict_capped);
	{
		static atomic_t p67e = ATOMIC_INIT(0);
		if (atomic_inc_return(&p67e) <= 1000)
			mxfs_probe("mxfs: P67-BMBT-EVICT-ENTER ino=%llu nheld=%d nseen_bmbt=%d nthisino=%d ncapped=%d need_iread=%d\n",
				(unsigned long long)ip->i_ino, nheld,
				nseen_bmbt, nthisino, ncapped,
				xfs_need_iread_extents(&ip->i_df) ? 1 : 0);
	}

	{
		bool	any_pin_only = false;

		for (i = 0; i < nheld; i++) {
			struct xfs_buf		*bp = hold[i];
			struct xfs_buf_log_item	*bip = bp->b_log_item;

			if (xfs_buf_ispinned(bp) &&
			    !(bip && test_bit(XFS_LI_DIRTY,
					      &bip->bli_item.li_flags)) &&
			    !(bip && test_bit(XFS_LI_IN_AIL,
					      &bip->bli_item.li_flags)) &&
			    (bp->b_flags & XBF_DONE)) {
				any_pin_only = true;
				break;
			}
		}
		if (any_pin_only)
			xfs_log_force(mp, XFS_LOG_SYNC);
	}

	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = hold[i];
		struct xfs_buf_log_item	*bip;
		bool			dirty, in_ail, pinned;
		int			w;

		xfs_buf_lock(bp);
		bip = bp->b_log_item;
		dirty = bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
		in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
		pinned = xfs_buf_ispinned(bp);
		/*
		 * bounded drain of the pin-ONLY unpin tail (idiom:
		 * 50 iters ~100ms; the pre-loop sync force drives the common
		 * case).  Drop the buf lock across the sleep so the unpin workqueue
		 * can run.  held[] carries an extra b_hold so bp stays valid.
		 */
		for (w = 0; w < 50 && pinned && !dirty && !in_ail &&
			     (bp->b_flags & XBF_DONE) &&
			     !xfs_is_shutdown(mp) && !xfs_is_unmounting(mp); w++) {
			xfs_buf_unlock(bp);
			msleep(2);
			xfs_buf_lock(bp);
			bip = bp->b_log_item;
			dirty = bip && test_bit(XFS_LI_DIRTY,
						&bip->bli_item.li_flags);
			in_ail = bip && test_bit(XFS_LI_IN_AIL,
						 &bip->bli_item.li_flags);
			pinned = xfs_buf_ispinned(bp);
		}
		/* FIX-14: undestaged check UNCONDITIONAL — the
		 * in_ail gate let CIL-window buffers (committed, in_ail=0,
		 * nothing dirty/pinned, lseq>wseq) be evicted; the re-read
		 * DMA'd the platter over the committed delta (run87 r2 chain,
		 * P-DE-BLK sibling).  Same idiom FIX-10 killed in P28C. */
		if ((bp->b_flags & XBF_DONE) && !pinned && !dirty &&
		    !(bp->b_flags & _XBF_DELWRI_Q) &&
		    !mxfs_dir_buf_is_undestaged(bp)) {
			bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			bp->b_mxfs_dir_gen = 0;
			{
				static atomic_t p59e = ATOMIC_INIT(0);
				if (atomic_inc_return(&p59e) <= 1000)
					mxfs_probe("mxfs: P59-BMBT-EVICT ino=%llu daddr=%lld in_ail=%d\n",
						(unsigned long long)ip->i_ino,
						(long long)bp->b_maps[0].bm_bn,
						in_ail);
			}
		} else if (dirty || in_ail || pinned ||
			   (bp->b_flags & _XBF_DELWRI_Q) ||
			   ((bp->b_flags & XBF_DONE) &&
			    mxfs_dir_buf_is_undestaged(bp))) {
			/* always-on capped — a skipped (kept)
			 * bmbt child at reload is the STALE-BASE the P67-STALE-
			 * BASE-RMW laundering detector then catches at the next
			 * modify; this names the manufacture site. */
			static atomic_t p67s = ATOMIC_INIT(0);
			if (atomic_inc_return(&p67s) <= 500)
				mxfs_probe("mxfs: P67-BMBT-EVICT-SKIP ino=%llu daddr=%lld DONE=%d pin=%d dirty=%d in_ail=%d delwri=%d undestaged=%d flags=0x%x\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn,
					!!(bp->b_flags & XBF_DONE), pinned, dirty, in_ail,
					!!(bp->b_flags & _XBF_DELWRI_Q),
					in_ail ? mxfs_dir_buf_is_undestaged(bp) : -1,
					bp->b_flags);
		}
		/*
		 * ROOT FIX — P-SEMA-OVERUP poisoning source.
		 * xfs_buf_relse() IS unlock+rele (xfs_buf.h:375); the explicit
		 * xfs_buf_unlock() that used to precede it here double-upped
		 * b_sema by +1 on EVERY held buffer at EVERY EX reload evict,
		 * leaving the shared dir's bmbt buffers permanently
		 * multi-ownable (kcore b_sema.count=83; run65 probes: count
		 * climbing 2..19 in one second from exactly this stack).  A
		 * multi-ownable buffer lets xfsaild's delwri trylock succeed
		 * DURING another thread's hold → concurrent double submits
		 * (P-WRCNT-RESUBMIT ×54 in validate2) → racing completions →
		 * double xfs_buf_item_done → spurious not-in-AIL
		 * SHUTDOWN_CORRUPT_INCORE + xfsaild NULL-relse oops (test1
		 * r17), and stale-image write-write reordering on the wire
		 * (single-dirent-loss vector).  Exactly one unlock: relse.
		 */
		xfs_buf_relse(bp);
	}
	if (hold != held)
		kfree(hold);
}

/*
 * D-0975: the end of this node's tenure on an inode ends the life of every
 * reusable cached image of the inode's extent-tree blocks.
 *
 * Every bmbt block this node caches was read under a grant on the owning
 * inode, and a block of that tree can be freed only under an EX grant, which
 * needs this node's grant released first.  So a cached bmbt image can become
 * the stale image of a reused address only after the tenure that read it has
 * ended — and the reload's owner-keyed eviction at the next acquire cannot
 * find it once the address belongs to another inode's tree.  Measured on the
 * 2-node TCP rig: 107 cached bmbt buffers of a peer-deleted file, none owned
 * by the new inode whose tree reused two of their addresses; both lookups
 * were refused at the btree owner check (P975-BMBT-LOOKUP-BAD cached_owner=
 * the deleted inode, disk_owner= the new one), and the same image under a
 * matching owner would have been served as the extent map.
 *
 * So drop them here, before the wire unlock, for every tenure that ends (EX
 * or PR, file or directory): clear XBF_DONE on every clean cached bmbt
 * buffer whose payload owner is this inode — data and attr fork alike, both
 * carry the inode as bb_owner — so the next read goes to disk and re-verifies.
 * Never xfs_buf_stale (the AIL may still reference the buffer).
 *
 * This is a fail-closed barrier, not a best effort.  A buffer whose lock
 * cannot be taken within the budget (an in-flight read holds its lock until
 * completion; XBF_READ marks those and they are collected before their
 * header carries an owner), or that still carries local work (dirty, pinned,
 * in the AIL, delayed-write queued, or logged since last written — nothing a
 * release's durable block may leave behind, and a PR tenure logs nothing) is
 * counted and reported, and the caller does not unlock.  Ops, owner and
 * state are re-checked under the buffer lock, since a buffer selected in
 * the walk may have changed identity by the time it is locked.
 */
int mxfs_tenure_end_evict = 1;
atomic_t mxfs_bmbt_rel_evicted = ATOMIC_INIT(0);
atomic_t mxfs_bmbt_rel_busy = ATOMIC_INIT(0);
atomic_t mxfs_bmbt_rel_localwork = ATOMIC_INIT(0);

int
mxfs_bmbt_tenure_end_evict(struct xfs_inode *ip, const char *why)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
	struct xfs_buf		**hold = NULL;
	int			hcap = 0, nheld = 0, nseen = 0, nsel = 0;
	int			nevict = 0, nlocal = 0, nbusy = 0, nover = 0;
	int			attempt, i;
	bool			forced = false;
	u64			deadline;

	if (!mxfs_tenure_end_evict || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;

	/*
	 * Collect under the walk's RCU section with a non-sleeping hold.  The
	 * first pass only counts (hcap == 0); the array is then sized from
	 * what that pass saw, and the walk repeats while more appear.
	 */
	for (attempt = 0; attempt < 4; attempt++) {
		nheld = nseen = nsel = nover = 0;
		for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
			struct xfs_perag	*pag = xfs_perag_get(mp, agno);
			struct rhashtable_iter	iter;
			struct xfs_buf		*bp;

			if (!pag)
				continue;
			rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
			rhashtable_walk_start(&iter);
			while ((bp = rhashtable_walk_next(&iter))) {
				if (IS_ERR(bp)) {
					if (PTR_ERR(bp) == -EAGAIN)
						continue;
					break;
				}
				if (bp->b_ops != &xfs_bmbt_buf_ops || !bp->b_addr)
					continue;
				nseen++;
				if (!(bp->b_flags & XBF_READ) &&
				    be64_to_cpu(((struct xfs_btree_block *)
						 bp->b_addr)->bb_u.l.bb_owner) !=
				    ip->i_ino)
					continue;
				nsel++;
				if (nheld >= hcap) {
					nover++;
					continue;
				}
				spin_lock(&bp->b_lock);
				if (bp->b_hold > 0) {
					bp->b_hold++;
					hold[nheld++] = bp;
				}
				spin_unlock(&bp->b_lock);
			}
			rhashtable_walk_stop(&iter);
			rhashtable_walk_exit(&iter);
			xfs_perag_put(pag);
		}
		if (!nover)
			break;
		for (i = 0; i < nheld; i++)
			xfs_buf_rele(hold[i]);
		nheld = 0;
		kfree(hold);
		hcap = nsel + 64;
		hold = kmalloc_array(hcap, sizeof(*hold),
				     GFP_NOFS | __GFP_NOWARN);
		if (!hold) {
			hcap = 0;
			nbusy = nsel;	/* nothing collected: not safe */
			goto out;
		}
	}
	if (nover)
		nbusy += nover;	/* still growing after 4 walks: not safe */

	deadline = ktime_get_ns() + 30ULL * NSEC_PER_SEC;
	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = hold[i];
		struct xfs_btree_block	*blk;
		struct xfs_buf_log_item	*bip;
		bool			dirty, in_ail, pinned;

again:
		while (!xfs_buf_trylock(bp)) {
			if (ktime_get_ns() > deadline ||
			    xfs_is_shutdown(mp)) {
				nbusy++;
				goto rele;
			}
			msleep(1);
		}
		blk = bp->b_addr;
		if (bp->b_ops != &xfs_bmbt_buf_ops || !blk ||
		    !(bp->b_flags & XBF_DONE) ||
		    be64_to_cpu(blk->bb_u.l.bb_owner) != ip->i_ino) {
			/* not this inode's, or nothing reusable here: already
			 * evicted, or a read that did not complete */
			xfs_buf_unlock(bp);
			goto rele;
		}
		bip = bp->b_log_item;
		dirty = bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
		in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
		pinned = xfs_buf_ispinned(bp);
		if (pinned && !dirty && !in_ail) {
			/* pin-only: a committed image whose CIL unpin has not
			 * fired yet.  One sync force retires it; then wait. */
			xfs_buf_unlock(bp);
			if (!forced) {
				forced = true;
				xfs_log_force(mp, XFS_LOG_SYNC);
			}
			if (ktime_get_ns() > deadline || xfs_is_shutdown(mp)) {
				nbusy++;
				goto rele;
			}
			msleep(2);
			goto again;
		}
		if (dirty || in_ail || pinned ||
		    (bp->b_flags & _XBF_DELWRI_Q) ||
		    mxfs_dir_buf_is_undestaged(bp)) {
			static atomic_t p975l = ATOMIC_INIT(0);

			nlocal++;
			if (atomic_inc_return(&p975l) <= 200)
				pr_err("mxfs: P975-REL-LOCALWORK ino=%llu daddr=%lld why=%s dirty=%d in_ail=%d pin=%d delwri=%d undestaged=%d flags=0x%x mode=%u — cached extent-tree block still carries local work at the end of the tenure\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn, why,
					dirty, in_ail, pinned,
					!!(bp->b_flags & _XBF_DELWRI_Q),
					mxfs_dir_buf_is_undestaged(bp),
					bp->b_flags, ip->i_dlm_mode);
			xfs_buf_unlock(bp);
			goto rele;
		}
		bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
		bp->b_mxfs_dir_gen = 0;
		nevict++;
		xfs_buf_unlock(bp);
rele:
		xfs_buf_rele(bp);
	}
out:
	kfree(hold);
	if (nevict)
		atomic_add(nevict, &mxfs_bmbt_rel_evicted);
	if (nbusy)
		atomic_add(nbusy, &mxfs_bmbt_rel_busy);
	if (nlocal)
		atomic_add(nlocal, &mxfs_bmbt_rel_localwork);
	{
		static atomic_t p975e = ATOMIC_INIT(0);

		if (nlocal || nbusy || atomic_inc_return(&p975e) <= 200)
			mxfs_probe("mxfs: P975-TENURE-END-EVICT ino=%llu why=%s seen=%d selected=%d held=%d evicted=%d local=%d busy=%d mode=%u comm=%s\n",
				(unsigned long long)ip->i_ino, why, nseen, nsel,
				nheld, nevict, nlocal, nbusy, ip->i_dlm_mode,
				current->comm);
	}
	if (nlocal)
		return -EIO;
	if (nbusy)
		return -EBUSY;
	return 0;
}

/*
 * The replay of a dead peer's journal slice writes the peer's logged images
 * through this node's buffer cache (xlog_recover_buf_commit_pass2 reads each
 * block through mp->m_ddev_targp, applies the image and queues the write),
 * and they stay cached, XBF_DONE, although no inode tenure on this node read
 * them.  The tenure-end eviction above retires only images read under a
 * grant, so after the peer returns, frees those blocks and reuses the
 * addresses in another structure, this node's first access can be served a
 * recovery image with no read — the D-0975 shape from a producer outside the
 * grant discipline, and with the inode number reused as well the image
 * carries the right owner and a valid CRC, so the owner check cannot refuse
 * it.
 *
 * So the recovery retires them itself: after the replayed images are home
 * (the P226-FR-HOMEFLUSH device flush) and before the slice is published
 * (IMAGES_REPLAYED, after which the dead holds are purged and normal access
 * resumes), clear XBF_DONE on every clean buffer the replay tagged whose
 * image can be reused at another address — extent-allocated metadata: bmbt,
 * directory / da / attr / symlink blocks, the AG btrees — or that carries no
 * verifier at all.  Inode clusters, AG headers and the superblock live at
 * fixed addresses and are refreshed by their own acquire-time reloads; they
 * are counted, not evicted.  Same idiom as the tenure-end evict: never
 * xfs_buf_stale, re-check under the buffer lock, and fail closed — a tagged
 * buffer that cannot be locked in the budget or still carries local work
 * makes the recovery return a retryable error, so nothing is published and
 * the next election replays and evicts again.  recov_evict=0 keeps the
 * census and skips the eviction (control).
 */
int mxfs_recov_evict = 1;
atomic_t mxfs_recov_tagged = ATOMIC_INIT(0);
atomic_t mxfs_recov_queued = ATOMIC_INIT(0);
atomic_t mxfs_recov_cache_hit = ATOMIC_INIT(0);
atomic_t mxfs_recov_hit_in_recovery = ATOMIC_INIT(0);
atomic_t mxfs_recov_bmbt_cached = ATOMIC_INIT(0);
atomic_t mxfs_recov_dir_cached = ATOMIC_INIT(0);
atomic_t mxfs_recov_agbt_cached = ATOMIC_INIT(0);
atomic_t mxfs_recov_other_cached = ATOMIC_INIT(0);
atomic_t mxfs_recov_evicted = ATOMIC_INIT(0);
atomic_t mxfs_recov_busy = ATOMIC_INIT(0);
atomic_t mxfs_recov_localwork = ATOMIC_INIT(0);

/*
 * Which recovery-populated images the retirement clears, by class:
 *   1 bmbt; 2 directory / da / attr / symlink; 3 AG btrees — extent-allocated
 *   metadata, whose block can be freed and reallocated to another structure
 *   while the image stays cached: retired.
 *   4 anything else — no verifier, or an ops this list does not know:
 *   retired, fail closed.
 *   0 the explicit exemptions only: inode clusters, AGF/AGI/AGFL, the
 *   superblock and dquot blocks live at fixed addresses, and a stale image
 *   of one is what a previous tenure of this node leaves behind every day —
 *   refreshed by their own acquire-time reloads (the inode reload re-reads
 *   the dinode, iget of a miss reloads the cluster, AG meta carries a
 *   generation stamp checked at the AG acquire); clearing XBF_DONE would not
 *   refresh their in-core derivatives either.  Counted, not evicted.
 */
static int
mxfs_recov_image_class(const struct xfs_buf *bp)
{
	const struct xfs_buf_ops *ops = bp->b_ops;

	if (ops == &xfs_bmbt_buf_ops)
		return 1;
	if (ops == &xfs_dir3_block_buf_ops || ops == &xfs_dir3_data_buf_ops ||
	    ops == &xfs_dir3_leaf1_buf_ops || ops == &xfs_dir3_leafn_buf_ops ||
	    ops == &xfs_dir3_free_buf_ops || ops == &xfs_da3_node_buf_ops ||
	    ops == &xfs_attr3_leaf_buf_ops || ops == &xfs_attr3_rmt_buf_ops ||
	    ops == &xfs_symlink_buf_ops)
		return 2;
	if (ops == &xfs_bnobt_buf_ops || ops == &xfs_cntbt_buf_ops ||
	    ops == &xfs_inobt_buf_ops || ops == &xfs_finobt_buf_ops ||
	    ops == &xfs_rmapbt_buf_ops || ops == &xfs_refcountbt_buf_ops)
		return 3;
	if (ops == &xfs_inode_buf_ops || ops == &xfs_inode_buf_ra_ops ||
	    ops == &xfs_agf_buf_ops || ops == &xfs_agi_buf_ops ||
	    ops == &xfs_agfl_buf_ops || ops == &xfs_sb_buf_ops ||
	    ops == &xfs_sb_quiet_buf_ops || ops == &xfs_dquot_buf_ops ||
	    ops == &xfs_dquot_buf_ra_ops)
		return 0;
	return 4;
}

/* Retirement failure injection for the retry arm: after this many images
 * have been retired in one recovery, that recovery returns busy (nothing
 * published, the next election replays and retires again); self-clears. */
int mxfs_dbg_recov_evict_fail_after;
module_param_named(dbg_recov_evict_fail_after, mxfs_dbg_recov_evict_fail_after, int, 0644);
MODULE_PARM_DESC(dbg_recov_evict_fail_after,
		 "test: fail the recovery image retirement after N retirements, once (0=off)");

int
mxfs_recov_image_evict(struct xfs_mount *mp, uint32_t dead_slot)
{
	xfs_agnumber_t		agno;
	struct xfs_buf		**hold = NULL;
	int			hcap = 0, nheld = 0, nseen = 0, nsel = 0;
	int			nevict = 0, nlocal = 0, nbusy = 0, nover = 0;
	int			ncls[5] = { 0, 0, 0, 0, 0 };
	int			attempt, i;
	bool			forced = false;
	u64			deadline;

	for (attempt = 0; attempt < 4; attempt++) {
		nheld = nseen = nsel = nover = 0;
		memset(ncls, 0, sizeof(ncls));
		for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
			struct xfs_perag	*pag = xfs_perag_get(mp, agno);
			struct rhashtable_iter	iter;
			struct xfs_buf		*bp;

			if (!pag)
				continue;
			rhashtable_walk_enter(&pag->pag_bcache.bc_hash, &iter);
			rhashtable_walk_start(&iter);
			while ((bp = rhashtable_walk_next(&iter))) {
				int	cls;

				if (IS_ERR(bp)) {
					if (PTR_ERR(bp) == -EAGAIN)
						continue;
					break;
				}
				if (!bp->b_mxfs_recov_image)
					continue;
				nseen++;
				cls = mxfs_recov_image_class(bp);
				ncls[cls]++;
				if (!cls)
					continue;
				nsel++;
				if (nheld >= hcap) {
					nover++;
					continue;
				}
				spin_lock(&bp->b_lock);
				if (bp->b_hold > 0) {
					bp->b_hold++;
					hold[nheld++] = bp;
				}
				spin_unlock(&bp->b_lock);
			}
			rhashtable_walk_stop(&iter);
			rhashtable_walk_exit(&iter);
			xfs_perag_put(pag);
		}
		if (!nover)
			break;
		for (i = 0; i < nheld; i++)
			xfs_buf_rele(hold[i]);
		nheld = 0;
		kfree(hold);
		hcap = nsel + 64;
		hold = kmalloc_array(hcap, sizeof(*hold),
				     GFP_NOFS | __GFP_NOWARN);
		if (!hold) {
			hcap = 0;
			nbusy = nsel;
			goto out;
		}
	}
	if (nover)
		nbusy += nover;
	atomic_add(ncls[1], &mxfs_recov_bmbt_cached);
	atomic_add(ncls[2] + ncls[4], &mxfs_recov_dir_cached);
	atomic_add(ncls[3], &mxfs_recov_agbt_cached);
	atomic_add(ncls[0], &mxfs_recov_other_cached);
	if (!mxfs_recov_evict) {
		for (i = 0; i < nheld; i++)
			xfs_buf_rele(hold[i]);
		nheld = 0;
		goto out;
	}

	deadline = ktime_get_ns() + 30ULL * NSEC_PER_SEC;
	for (i = 0; i < nheld; i++) {
		struct xfs_buf		*bp = hold[i];
		struct xfs_buf_log_item	*bip;
		bool			dirty, in_ail, pinned;

again:
		while (!xfs_buf_trylock(bp)) {
			if (ktime_get_ns() > deadline || xfs_is_shutdown(mp)) {
				nbusy++;
				goto rele;
			}
			msleep(1);
		}
		if (!bp->b_mxfs_recov_image || !(bp->b_flags & XBF_DONE) ||
		    !mxfs_recov_image_class(bp)) {
			/* refreshed by a read, already evicted, or a read in
			 * flight: nothing of the replay's left to reuse */
			xfs_buf_unlock(bp);
			goto rele;
		}
		bip = bp->b_log_item;
		dirty = bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
		in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
		pinned = xfs_buf_ispinned(bp);
		if (pinned && !dirty && !in_ail) {
			xfs_buf_unlock(bp);
			if (!forced) {
				forced = true;
				xfs_log_force(mp, XFS_LOG_SYNC);
			}
			if (ktime_get_ns() > deadline || xfs_is_shutdown(mp)) {
				nbusy++;
				goto rele;
			}
			msleep(2);
			goto again;
		}
		if (dirty || in_ail || pinned ||
		    (bp->b_flags & _XBF_DELWRI_Q) ||
		    mxfs_dir_buf_is_undestaged(bp)) {
			static atomic_t prl = ATOMIC_INIT(0);

			nlocal++;
			if (atomic_inc_return(&prl) <= 200)
				pr_err("mxfs: P-RECOV-EVICT-LOCALWORK slot=%u daddr=%lld ops=%s dirty=%d in_ail=%d pin=%d delwri=%d undestaged=%d flags=0x%x — a recovery-written image still carries local work at the end of the recovery\n",
					dead_slot, (long long)bp->b_maps[0].bm_bn,
					bp->b_ops && bp->b_ops->name ?
						bp->b_ops->name : "?",
					dirty, in_ail, pinned,
					!!(bp->b_flags & _XBF_DELWRI_Q),
					mxfs_dir_buf_is_undestaged(bp),
					bp->b_flags);
			xfs_buf_unlock(bp);
			goto rele;
		}
		bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
		bp->b_mxfs_dir_gen = 0;
		bp->b_mxfs_recov_image = false;
		nevict++;
		xfs_buf_unlock(bp);
		if (unlikely(mxfs_dbg_recov_evict_fail_after > 0 &&
			     nevict >= mxfs_dbg_recov_evict_fail_after)) {
			mxfs_dbg_recov_evict_fail_after = 0;
			pr_warn("mxfs: P-RECOV-EVICT-INJECT slot=%u after=%d — injected retirement failure; the recovery must retry and retire the rest\n",
				dead_slot, nevict);
			xfs_buf_rele(bp);
			for (i++; i < nheld; i++)
				xfs_buf_rele(hold[i]);
			nbusy++;
			break;
		}
rele:
		xfs_buf_rele(bp);
	}
out:
	kfree(hold);
	if (nevict)
		atomic_add(nevict, &mxfs_recov_evicted);
	if (nbusy)
		atomic_add(nbusy, &mxfs_recov_busy);
	if (nlocal)
		atomic_add(nlocal, &mxfs_recov_localwork);
	mxfs_xfs_probe(mp,
		"MXFS: P-RECOV-IMAGE-EVICT slot %u tagged_cached=%d bmbt=%d dir=%d agbt=%d noverifier=%d fixed=%d selected=%d evicted=%d local=%d busy=%d evict=%d — %s",
		dead_slot, nseen, ncls[1], ncls[2], ncls[3], ncls[4], ncls[0],
		nsel, nevict, nlocal, nbusy, mxfs_recov_evict,
		(nlocal || nbusy) ? "NOT all retired; slice NOT published, will retry" :
		mxfs_recov_evict ? "recovery-written images retired before publication" :
		"eviction off (control); images left cached");
	if (nlocal)
		return -EIO;
	if (nbusy)
		return -EBUSY;
	return 0;
}

/*
 * — ROOT-POINTER-driven bmbt child evict, the
 * walk-miss-proof companion to mxfs_dir_evict_bmbt_blocks.  Runs 072239Z/
 * 075216Z showed the reader-side mix (fresh adopted bmbt ROOT walked into a
 * stale CACHED child -> map missing blocks the leaf references -> P14) with
 * the owner-scan evict firing ZERO times — if the rhashtable walk misses the
 * child buffer (case a), the stale child survives with XBF_DONE and
 * xfs_iread_extents serves it.  The freshly ADOPTED in-core root names its
 * children directly; evict them by exact daddr lookup so no walk can miss.
 * Same evict idiom (never stale, never touch pinned/dirty/in-AIL/delwri/
 * undestaged).  Level-1 roots only (a storm dir has one level); deeper trees
 * fall back to the owner-scan (already run by the caller).
 */
/* < a864 > Coherent block read for diagnostics.  On the SCST CAW-
 * multipath target (mxfs_fua_disable=1) the CLUSTER-COHERENT image is the write
 * cache reached by a plain bio; a SCSI READ-FUA pierces PAST it to the platter,
 * which LAGS until destage.  So sample the SAME coherence point the
 * dir-metadata read path uses: plain bio when fua_disable=1, FUA otherwise. */
int
mxfs_dbg_coherent_read(struct xfs_mount *mp, uint64_t lba_512, void *buf,
		       uint32_t len)
{
	extern int mxfs_fua_disable;
	extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
						 uint64_t, void *, uint32_t);
	extern int mxfs_pal_scsi_read_fua_bdev(struct block_device *,
					       uint64_t, void *, uint32_t);

	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return -ENODEV;
	if (mxfs_fua_disable)
		return mxfs_pal_bdev_read_plain_bdev(
			mp->m_ddev_targp->bt_bdev, lba_512, buf, len);
	return mxfs_pal_scsi_read_fua_bdev(
		mp->m_ddev_targp->bt_bdev, lba_512, buf, len);
}

/*
 * D-0975 detector, called from xfs_btree_lookup_get_block's refusal path
 * for an inode-rooted btree on a clustered mount: the refused image (the
 * buffer the lookup got, from the cache or from disk) against the same
 * address read at the coherence point.  cached_owner != want with
 * disk_owner == want is a stale cached image of another tree at a reused
 * address; both equal to something else is a bad block on disk.
 */
atomic_t mxfs_bmbt_lookup_bad = ATOMIC_INIT(0);

void
mxfs_bmbt_lookup_bad_probe(struct xfs_mount *mp, struct xfs_buf *bp,
			   xfs_ino_t want, int want_level)
{
	struct xfs_btree_block	*cb = bp ? bp->b_addr : NULL;
	struct xfs_btree_block	*db;
	uint32_t		len = mp->m_sb.sb_blocksize;
	void			*dbuf;
	int			drc = -ENOMEM;

	atomic_inc(&mxfs_bmbt_lookup_bad);
	if (!bp || !cb)
		return;
	dbuf = kmalloc(len, GFP_NOFS);
	if (dbuf)
		drc = mxfs_dbg_coherent_read(mp, (uint64_t)xfs_buf_daddr(bp) +
				mp->m_ddev_targp->bt_sector_offset, dbuf, len);
	db = dbuf;
	mxfs_probe_ratelimited("mxfs: P975-BMBT-LOOKUP-BAD daddr=%lld want_ino=%llu want_level=%d cached_owner=%llu cached_level=%u cached_nrecs=%u cached_magic=0x%08x flags=0x%x ops=%s disk_rc=%d disk_owner=%llu disk_level=%u disk_magic=0x%08x same_image=%d comm=%s\n",
		(long long)xfs_buf_daddr(bp), (unsigned long long)want,
		want_level,
		(unsigned long long)be64_to_cpu(cb->bb_u.l.bb_owner),
		be16_to_cpu(cb->bb_level), be16_to_cpu(cb->bb_numrecs),
		be32_to_cpu(cb->bb_magic), bp->b_flags,
		bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?", drc,
		(!drc && db) ? (unsigned long long)be64_to_cpu(db->bb_u.l.bb_owner) : 0ULL,
		(!drc && db) ? be16_to_cpu(db->bb_level) : 0,
		(!drc && db) ? be32_to_cpu(db->bb_magic) : 0,
		(!drc && db) ? !memcmp(dbuf, cb, len) : -1,
		current->comm);
	kfree(dbuf);
}

void
mxfs_dir_evict_bmbt_by_root(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_ifork	*ifp = &ip->i_df;
	int			i, nrecs;

	if (ifp->if_format != XFS_DINODE_FMT_BTREE || !ifp->if_broot)
		return;
	if (be16_to_cpu(ifp->if_broot->bb_level) != 1)
		return;
	nrecs = be16_to_cpu(ifp->if_broot->bb_numrecs);
	if (nrecs <= 0 || nrecs > 16)
		return;
	for (i = 1; i <= nrecs; i++) {
		xfs_fsblock_t	cfsb = be64_to_cpu(*xfs_bmap_broot_ptr_addr(
					mp, ifp->if_broot, i,
					ifp->if_broot_bytes));
		struct xfs_buf	*bp = NULL;
		struct xfs_buf_log_item *bip;
		bool		dirty, in_ail, pinned;

		if (!xfs_verify_fsbno(mp, cfsb))
			continue;
		/*
		 * < a864 > DECISIVE R-a/R-b DISCRIMINATOR (instrumented) for
		 * the 32/caw dir_reuse "xfs_bmbt block reads back XDD3 -> CRC err 74
		 * -> shutdown" failure.  The adopted in-core if_broot names this
		 * child daddr as a bmbt block; FUA-read it off the coherent platter
		 * and check its magic.  A non-BMA3 magic (e.g. XDD3 dir-data) proves
		 * the ADOPTED root points at a block the cluster has REPURPOSED.
		 * Then FUA-read the raw inode cluster and parse ITS on-disk bmdr
		 * root: if the fresh platter dinode does NOT name this child daddr,
		 * THIS node adopted a STALE inode-cluster dinode (R-b, reader-side —
		 * missing handoff FUA on the inode cluster); if it DOES name it, the
		 * platter dinode is itself inconsistent (R-a, writer-side release
		 * ordering).  Diagnostic only (no behaviour change); capped. */
		{
			xfs_daddr_t	cd = XFS_FSB_TO_DADDR(mp, cfsb);
			static atomic_t	pbrc = ATOMIC_INIT(0);
			uint32_t	blen = mp->m_sb.sb_blocksize;
			void		*fbuf;

			if (atomic_inc_return(&pbrc) <= 200 &&
			    (fbuf = kmalloc(blen, GFP_NOFS)) != NULL) {
				int frc = mxfs_dbg_coherent_read(mp,
					(uint64_t)cd +
					mp->m_ddev_targp->bt_sector_offset,
					fbuf, blen);
				uint32_t cmagic = (frc == 0) ?
					be32_to_cpu(*(__be32 *)fbuf) : 0;

				if (frc == 0 && cmagic != MXFS_BMAP_CRC_MAGIC &&
				    cmagic != MXFS_BMAP_MAGIC) {
					uint32_t clen = (uint32_t)
						ip->i_imap.im_len << BBSHIFT;
					void	*cbuf = clen ?
						kmalloc(clen, GFP_NOFS) : NULL;
					int	names = -1;
					uint32_t rnx = 0;

					if (cbuf && mxfs_dbg_coherent_read(mp,
					    (uint64_t)ip->i_imap.im_blkno +
					    mp->m_ddev_targp->bt_sector_offset,
					    cbuf, clen) == 0) {
						struct xfs_dinode *rd =
						  (struct xfs_dinode *)((char *)
						  cbuf + ip->i_imap.im_boffset);

						rnx = be32_to_cpu(
							rd->di_nextents);
						if (rd->di_format ==
						    XFS_DINODE_FMT_BTREE) {
						  struct xfs_bmdr_block *rb =
						    (struct xfs_bmdr_block *)
						    ((char *)rd +
						     xfs_dinode_size(
							rd->di_version));
						  int dmxr = xfs_bmdr_maxrecs(
						    XFS_DFORK_DSIZE(rd, mp),
						    false);
						  int rn = be16_to_cpu(
							rb->bb_numrecs);
						  int k;

						  names = 0;
						  for (k = 1; k <= rn &&
						       k <= dmxr; k++) {
						    xfs_fsblock_t rf =
						      be64_to_cpu(
							*xfs_bmdr_ptr_addr(
							  rb, k, dmxr));
						    if (XFS_FSB_TO_DADDR(mp,
							rf) == cd) {
						      names = 1;
						      break;
						    }
						  }
						}
					}
					kfree(cbuf);
					mxfs_probe("mxfs: P-BROOT-REPURPOSE ino=%llu child_daddr=%lld fua_magic=0x%08x incore_nx=%llu raw_nx=%u raw_names_child=%d verdict=%s\n",
						(unsigned long long)ip->i_ino,
						(long long)cd, cmagic,
						(unsigned long long)
						ifp->if_nextents,
						rnx, names,
						names == 0 ?
						"STALE-INCORE-DINODE(R-b)" :
						names == 1 ?
						"PLATTER-DINODE-INCONSISTENT(R-a)" :
						"RAW-READ-FAILED");
				}
				kfree(fbuf);
			}
		}
		if (xfs_buf_incore(mp->m_ddev_targp,
				   XFS_FSB_TO_DADDR(mp, cfsb),
				   XFS_FSB_TO_BB(mp, 1), XBF_TRYLOCK,
				   &bp) != 0 || !bp)
			continue;
		bip = bp->b_log_item;
		dirty = bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags);
		in_ail = bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags);
		pinned = xfs_buf_ispinned(bp);
		if ((bp->b_flags & XBF_DONE) && !pinned && !dirty &&
		    !(bp->b_flags & _XBF_DELWRI_Q) &&
		    !mxfs_dir_buf_is_undestaged(bp)) {
			bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			bp->b_mxfs_dir_gen = 0;
			{
				static atomic_t p59r = ATOMIC_INIT(0);
				if (atomic_inc_return(&p59r) <= 1000)
					mxfs_probe("mxfs: P59-BMBT-ROOT-EVICT ino=%llu daddr=%lld in_ail=%d\n",
						(unsigned long long)ip->i_ino,
						(long long)XFS_FSB_TO_DADDR(mp, cfsb),
						in_ail);
			}
		} else {
			static atomic_t p59rs = ATOMIC_INIT(0);
			if (atomic_inc_return(&p59rs) <= 500)
				mxfs_probe("mxfs: P59-BMBT-ROOT-KEEP ino=%llu daddr=%lld DONE=%d pin=%d dirty=%d in_ail=%d delwri=%d\n",
					(unsigned long long)ip->i_ino,
					(long long)XFS_FSB_TO_DADDR(mp, cfsb),
					!!(bp->b_flags & XBF_DONE), pinned,
					dirty, in_ail,
					!!(bp->b_flags & _XBF_DELWRI_Q));
		}
		/*
		 * ROOT FIX — P-SEMA-OVERUP poisoning source.
		 * xfs_buf_relse() IS unlock+rele (xfs_buf.h:375); the explicit
		 * xfs_buf_unlock() that used to precede it here double-upped
		 * b_sema by +1 on EVERY held buffer at EVERY EX reload evict,
		 * leaving the shared dir's bmbt buffers permanently
		 * multi-ownable (kcore b_sema.count=83; run65 probes: count
		 * climbing 2..19 in one second from exactly this stack).  A
		 * multi-ownable buffer lets xfsaild's delwri trylock succeed
		 * DURING another thread's hold → concurrent double submits
		 * (P-WRCNT-RESUBMIT ×54 in validate2) → racing completions →
		 * double xfs_buf_item_done → spurious not-in-AIL
		 * SHUTDOWN_CORRUPT_INCORE + xfsaild NULL-relse oops (test1
		 * r17), and stale-image write-write reordering on the wire
		 * (single-dirent-loss vector).  Exactly one unlock: relse.
		 */
		xfs_buf_relse(bp);
	}
}
module_param_named(tenure_end_evict, mxfs_tenure_end_evict, int, 0644);
MODULE_PARM_DESC(tenure_end_evict,
		 "drop this node's clean cached extent-tree blocks of an inode when its grant leaves (release or reclaim); 0 restores the behaviour before 0.87.6 for A/B");
/* Recovery-written image retirement (mxfs_recov_image_evict): the switch,
 * the replay's tag count, the census at the recovery's end by class, what it
 * retired or could not, and the detector for an image served from the cache. */
module_param_named(recov_evict, mxfs_recov_evict, int, 0644);
MODULE_PARM_DESC(recov_evict,
		 "retire the cached images a dead peer's slice replay wrote before publishing the recovery; 0=off (control: images stay cached), 1=on (default)");
