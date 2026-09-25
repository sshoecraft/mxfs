// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- read coherency: getattr, peer flush and directory durability signals
 */
#define MXFS_TU_ID 27	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*  (dir_reuse 16/caw ROOT): mxfs_dlm_dir_durable_signal
 * runs xfs_log_force(SYNC) + a full dir-block flush on EVERY create/remove/rename
 * of a contended dir (gate i_dlm_dir_gen>0), while holding the dir ILOCK_EXCL.
 * Under dir_reuse@16 (rank1 rm-rf's 1600 shared-dir entries, each a separate
 * unlink) that's 1600 synchronous log-forces + dir flushes on the critical path
 * -> the rm hangs (xfs_buf_iowait in mxfs_dir_bmbt_scan, hung-task 90s+) and the
 * whole test blows its budget.  It was re-introduced because the async
 * release-drain MISSED a node's final deletes (peer cold-read stale = durable-loss).
 * MODES: 1=always flush per-modify when gen>0 (behavior, DEFAULT/safe);
 * 0=never per-modify flush (A/B: proves cost + exposes any release-drain gap);
 * 2=flush per-modify ONLY when a peer wants EX on this dir (i_dlm_dir_want_ex) —
 * i.e. defer the flush unless a peer is actually waiting to read, so the common
 * uncontended-tenure rm/create storm pays nothing and the flush still happens
 * before any handoff.  Instrumented A/B lever for the dir_reuse speed fix. */
int mxfs_dir_persig_flush = 1;
module_param_named(dir_persig_flush, mxfs_dir_persig_flush, int, 0644);
MODULE_PARM_DESC(dir_persig_flush,
	"per-modify dir durable-signal flush: 1=always(gen>0), 0=never, 2=only when peer-wants-EX (default 1)");

/*
 * FIX: getattr inode-DLM refresh.  xfs_vn_getattr reads the cached
 * in-core inode attributes (di_size etc.) with no coordination.  In multi-
 * node a peer can update an inode we hold no DLM grant on (readdir/readahead
 * instantiates a peer's inode without a grant, so a peer's write never BASTs
 * us and i_dlm_stale stays false) — our cached di_size goes stale and stat()
 * returns it (the cross_write_read di_size=0 failure).  Taking ILOCK_SHARED
 * routes through mxfs_dlm_ilock_begin(PR): a fresh (non-cached) PR acquire
 * BASTs the EX holder, forcing its flush to the backing store, and reloads
 * the inode from disk — so getattr reports the current size.  Returns true if
 * it locked (caller must mxfs_getattr_dlm_unlock); false single-node / no DLM
 * (caller skips, preserving native single-node getattr cost).
 */
/*
 * 0.84.2: returns 1 with ILOCK_SHARED held, 0 when there was nothing to
 * take (single node / no DLM), or a negative errno with nothing held when
 * the cluster acquire was abandoned — the master never acknowledged the
 * request past the budget, or this task was killed.  stat is a fallible
 * boundary: nothing is dirty, no transaction is open, and the syscall can
 * fail cleanly; an unbounded wait here was measured (s581c) as a stat
 * through a held fd blocked past 495 s behind a live master.
 */
int
mxfs_getattr_dlm_lock(struct xfs_inode *ip)
{
	int ret;

	if (!ip || !ip->i_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
		return 0;
	/*
	 * NOTE: a getattr-time di_size==0 detect+reload fix was TRIED
	 * (builds 40B34C7C/C55F41B3) and REVERTED — P103 diagnostic proved it
	 * NEVER fired for the failing reads: the reading inode has di_size!=0
	 * at getattr yet `cat` returns EMPTY → the staleness is in the DATA
	 * PAGES / extent map (stale cached data block from a prior lifecycle of
	 * the reused inode/block), NOT di_size.  Taking EXCL on size==0 files
	 * also added cross_visibility flakiness.  The fix belongs on the data
	 * read-coherency path (invalidate stale data pages / extent map on a
	 * cross-node content read of a reused inode), not here.
	 */
	ret = mxfs_ilock_fallible(ip, XFS_ILOCK_SHARED);
	if (ret) {
		pr_warn_ratelimited(
		    "mxfs: P958-GETATTR-REFUSED ino=%llu rc=%d comm=%s — stat refused: the cluster acquire was abandoned; failing the syscall instead of waiting on it\n",
			(unsigned long long)ip->i_ino, ret, current->comm);
		return ret;
	}
	return 1;
}

void
mxfs_getattr_dlm_unlock(struct xfs_inode *ip)
{
	xfs_iunlock(ip, XFS_ILOCK_SHARED);
}

/*
 * STICKY-PR read coherency envelope (Gemini-confirmed architecture; see
 * coherency-sticky-pr-fix.md).  Call at the TOP of xfs_file_read_iter, BEFORE any
 * VFS lock (IOLOCK/ILOCK), so a grant-less (NL) or stale cached regular-file
 * inode is brought coherent before the read touches i_size/pages:
 *   - ilock_begin(PR) on an NL inode takes a fresh CAW PR grant (slow path) which
 *     sets i_dlm_stale + reloads the dinode (di_size+extents) AND drops the
 *     regular-file page cache (invalidate_inode_pages2 in reload) → the
 *     subsequent read sees the owner's committed content, not stale di_size=0/0-pages.
 *   - It registers this node as a PR grant HOLDER in the inode's CAW slot, so a
 *     future writer's EX acquire BASTs us (the missing event that let grant-less
 *     caches go stale forever).
 *   - STICKY: ilock_begin/end leaves i_dlm_mode==PR cached after holders hit 0, so
 *     repeat reads hit the fast path with ZERO CAW I/O (no per-read perf wall).
 * Called WITHOUT holding any VFS lock → mxfs_dlm_reload_inode's down_write(i_lock)
 * is safe (the deadlock in reverted in-VFS-lock attempts is avoided).
 * Gated multi-node + regular file; single-node / dirs are a no-op.
 */
/*
 * 0.84.2: returns 0, or a negative errno when the cluster acquire was
 * abandoned (the master never acknowledged the request past the budget, or
 * this task was killed).  The read is a fallible boundary — it is called
 * before any VFS lock, nothing is dirty, no transaction is open — and the
 * caller fails the read.  Only the PR the envelope itself asks for may give
 * up; ilock_begin/end are balanced either way.
 */
int
mxfs_read_coherency_envelope(struct xfs_inode *ip)
{
	struct mxfs_acqfallible	acqfall;
	int			ret = 0;

	if (!ip || !ip->i_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
		return 0;
	if (!S_ISREG(VFS_I(ip)->i_mode))
		return 0;
	mxfs_acqfall_enter(&acqfall, ip->i_ino);
	mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
	if (mxfs_acqfall_taken(&acqfall, &ret))
		ret = fatal_signal_pending(current) ? -EINTR : ret;
	mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
	mxfs_acqfall_exit(&acqfall);
	if (ret)
		pr_warn_ratelimited(
		    "mxfs: P958-READ-REFUSED ino=%llu rc=%d comm=%s — read refused: the cluster acquire was abandoned; failing the read instead of waiting on it\n",
			(unsigned long long)ip->i_ino, ret, current->comm);
	return ret;
}

/*
 * FORCE a peer holder of this inode number to flush its current
 * on-disk incarnation NOW, instead of waiting (up to a 120s barrier
 * timeout) for the peer's lazy iflush/AIL destage.
 *
 * Used by the xfs_lookup reused-inode eviction path: when a peer freed an
 * inode number and reallocated it for a NEW incarnation of a DIFFERENT type
 * (the churned barrier/test dirs), the dirent already carries the new ftype
 * but the new dinode is not yet on the medium — so the eviction's gen-gated
 * recycle re-read keeps seeing the stale OLD incarnation and the lookup
 * returns the wrong type (ENOTDIR/EISDIR) until the peer eventually destages.
 *
 * The creator acquired the inode DLM EX during xfs_create (xfs_ilock ->
 * mxfs_dlm_ilock_begin(EX)) and leaves it STICKY-cached after commit.  A PR
 * acquire from this node BASTs that EX holder -> its bast_work_fn drains +
 * iflushes the new dinode + blkdev_flush BEFORE downconverting -> the new
 * incarnation is durable when we get the PR grant.  We then release; the
 * caller evicts the stale in-core inode and re-igets, and the gen-gated
 * recycle re-read now sees the fresh incarnation.
 *
 * Type-agnostic (the reused incarnation may be a dir OR a file), unlike
 * mxfs_read_coherency_envelope (regular-file only).  i_dlm_stale MUST be
 * clear on entry so ilock_begin does NOT do an in-place reload of this
 * wrong-type stale inode (that deadlocks/races —); the caller relies
 * solely on the BAST side effect, then evicts + re-instantiates cleanly.
 *
 * Called WITHOUT holding any VFS lock (the xfs_lookup eviction point holds
 * no parent lock), so the PR acquire is deadlock-safe.
 */
void
mxfs_dlm_force_peer_flush(struct xfs_inode *ip)
{
	if (!ip || !ip->i_mount->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(ip->i_mount->m_mxfs_dlm))
		return;
	mxfs_dlm_ilock_begin(ip, MXFS_LOCK_PR);
	mxfs_dlm_ilock_end(ip, MXFS_LOCK_PR);
}

/*
 * is this inode owned by a PEER node under the node-affine inode
 * allocation policy?  Regular files are allocated from the creating node's
 * affine AG (node_slot %% maxagi); an inode in a DIFFERENT AG than this
 * node's affine AG therefore belongs to a peer.  A node must not write a
 * peer's inode (e.g. an atime update on read), because xfs_iflush copies the
 * WHOLE in-core inode — including a possibly-stale di_size — into the shared
 * cluster buffer, clobbering the peer's authoritative size (P97).  Returns
 * true only in multi-node for a regular-file inode outside our affine AG.
 */
bool
mxfs_inode_is_peer_ag(struct xfs_inode *ip)
{
	struct xfs_mount	*mp;

	if (!ip)
		return false;
	mp = ip->i_mount;
	if (!mp || !mp->m_mxfs_dlm || mp->m_maxagi == 0 ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return false;
	if (!S_ISREG(VFS_I(ip)->i_mode))
		return false;
	return XFS_INO_TO_AGNO(mp, ip->i_ino) !=
		(mp->m_mxfs_node_slot % mp->m_maxagi);
}

/*
 * producer bridge for the inode-eviction ring.  Called from xfs_ifree
 * when this node frees an inode.  Stages {ino, gen} into the disklock heartbeat
 * ring (see dlm/disklock.c) so passively NL-caching peers can invalidate any
 * stale cached copy of the number before it is reused as a different
 * type/incarnation (the cross_visibility "Is a directory" / invisible-file
 * failures).  `gen` is the freed image's generation, already bumped once by
 * xfs_ifree; a peer invalidates only a cached copy of THAT incarnation (its
 * i_generation is gen - 1, or gen for a copy of the free image).  Generations
 * are random per allocation, so no order relation identifies an incarnation
 * (mxfs_dlm_evict_inode_cb).  No-op in single-node or when the DLM/disklock
 * isn't active.
 */
void
mxfs_dlm_note_inode_freed(struct xfs_mount *mp, uint64_t ino, uint32_t gen)
{
	if (!mp || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		MXFS_SOLE_SKIP_NOTE(mp->m_mxfs_dlm, "note_inode_freed");
		return;
	}

	mxfs_v5_dlm_note_inode_freed(mp->m_mxfs_dlm, ino, gen);
}

/*
 * producer for a DIR_MODIFY eviction-ring entry.  Called from the
 * canonical dir-modify chokepoints (xfs_dir_createname / removename / replace)
 * after this node commits a dirent add/remove to directory `dir_ino`.  Peers
 * that passively cache `dir_ino` at NL (no DLM grant — e.g. a node doing
 * readdir on a SHARED directory) never get BAST'd, so without this they serve
 * a STALE cached dir DATA/LEAF block (missing our just-added names, or still
 * listing our just-removed ones) — and a peer that then MODIFIES the same dir
 * RMWs off that stale block and clobbers our committed dirents (the rename/
 * unlink "can't stat my own file" lost-update).  The peer consumer bumps the
 * dir's i_dlm_dir_gen so its next readdir FUA-re-reads the committed blocks.
 * No-op single-node / DLM inactive.  Non-blocking (stages to the HB ring).
 */
void
mxfs_dlm_note_dir_modified(struct xfs_mount *mp, uint64_t dir_ino)
{
	if (!mp || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;

	mxfs_v5_dlm_note_dir_modified(mp->m_mxfs_dlm, dir_ino);
}

/*
 * DURABILITY-ORDERED dir-modify signal for the unlink/rename commit
 * path.  The plain producer above stages the DIR_MODIFY signal at the moment
 * the dirent op COMMITS in-core (inside the still-open transaction) — but the
 * dir DATA block carrying the change is then only in the journal + AIL, not yet
 * at its final on-disk location.  A passively-caching peer that receives the
 * signal and FUA-re-reads the dir block can therefore read the STALE pre-change
 * platter image, re-stamp its cache gen to match, and — because no further
 * signal follows for that dir — serve that stale block PERMANENTLY (the
 * "node1 still sees node3_file26 after node3 deleted it" residual + the harness
 * polling to a ~120s barrier timeout).
 *
 * Fix the ordering: AFTER xfs_trans_commit, with the dir ILOCK_EXCL still held
 * (extent list stable), push the dir's data AGs to disk SYNCHRONOUSLY (the same
 * per-AG primitive the BAST-release drain uses), then stage a FRESH DIR_MODIFY
 * signal.  Now the signal a peer observes is guaranteed to post-date the
 * block's durability, so its FUA-re-read sees the committed change.  Process
 * context only (never the HB thread — a sync AIL push there would stall
 * heartbeats and trip false peer dead-detection).  No-op single-node.
 *
 * Caller MUST hold dp->i_lock (ILOCK_EXCL or shared) so the extent list is
 * stable across the push.
 */
void
mxfs_dlm_dir_durable_signal(struct xfs_inode *dp)
{
	struct xfs_mount	*mp;

	if (!dp)
		return;
	mp = dp->i_mount;
	if (!mp || !mp->m_mxfs_dlm)
		return;
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		MXFS_SOLE_SKIP_NOTE(mp->m_mxfs_dlm, "dir_durable_signal");
		return;
	}
	/* per-op barrier is CAW-only (see mxfs_dirop_durable_tcp) */
	if (!mxfs_dirop_durable_needed(mp))
		return;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return;

	/*
	 * v0.5.1: PUBLISH-ONLY.  The old body ran xfs_log_force(SYNC) + a
	 * targeted dir-block bwrite right here, per modify (~7 ms) — an
	 * 8.7k-file rsync spent ~60 s of its wall inside this function
	 * ( stack sampling), and an async/coalesced variant
	 * of the flush raced the lockless FUA readers into dir3 verifier
	 * shutdowns.  The flush is not needed for coherency:
	 *   - A peer that READS the dir coordinates through the DLM; its
	 *     PR acquire forces our BAST release drain (invariant #1),
	 *     which makes these same blocks durable before the peer can
	 *     read them.
	 *   - The eviction-ring consumers only EVICT caches; their
	 *     subsequent re-read coordinates as above.  A lockless FUA
	 *     oracle reading a platter that lags in-core sees the OLD
	 *     state ("no change yet"), which is benign — the oracles are
	 *     gated on holding NO grant (v0.5.1 d_revalidate gates), and
	 *     a grant-less node never has newer in-core state than disk.
	 *   - fsync-acked durability is the log's job (and foreign-slice
	 *     replay after death), not the in-place dir block's.
	 */

	/*
	 * — RE-INTRODUCE publish-before-notify for
	 * CONTENDED dirs.  v0.5.1 gutted this to publish-only (no disk I/O),
	 * relying on the BAST-release drain for durability.  PROVEN GAP (this
	 * session, raw-disk parse + P-WRACT cross-node write trace on 2/tcp uv):
	 * a node's committed FINAL dir deletes are NOT always destaged at its
	 * EX->PR downgrade / release — node2 deleted node2_file21..30 (in-core
	 * block active=2) yet the shared LUN block stalled at active=12 (the last
	 * 10 deletes were never written; no NL-skip, xfsaild simply never pushed
	 * the post-downgrade state), so the peer (node1) cold-read the stale disk
	 * and listed the deleted files = uv "none remain got=10".
	 *
	 * We are called post-commit with dp ILOCK_EXCL held (xfs_remove/create/
	 * rename), i.e. i_dlm_mode==EX, so the dirskip chokepoint's NL guard does
	 * NOT fire and this block is authoritative (no peer can have raced it).
	 * Synchronously land the dir's modified DATA blocks to the LUN here, BEFORE
	 * note_dir_modified bumps any peer's gen, so a peer's evict + cold-read
	 * observes the durable image (PROVED the transport is coherent).
	 *
	 * GATED on i_dlm_dir_gen>0 (a peer has modified this dir => it is shared/
	 * contended): a solo rsync into its own subtree keeps gen=0 and pays
	 * nothing, avoiding the v0.5.1 60s-per-8.7k-file regression that caused
	 * the removal.  Synchronous xfs_bwrite only (NOT the reverted async/
	 * coalesced variant that raced lockless FUA readers into dir3 verifier
	 * shutdowns).  Bounded by dir size; EX held so no cross-node wait.
	 */
	{
		extern int mxfs_dirwr_enabled, mxfs_instr_enabled;
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)) {
			static atomic_t pdsig = ATOMIC_INIT(0);
			if (atomic_inc_return(&pdsig) <= 3000)
				mxfs_probe("mxfs: P-DSIG ino=%llu gen=%llu fmt=%d selfc=%d flush=%d comm=%s\n",
					(unsigned long long)dp->i_ino,
					(unsigned long long)dp->i_dlm_dir_gen,
					dp->i_df.if_format,
					dp->i_mxfs_self_created ? 1 : 0,
					(dp->i_dlm_dir_gen > 0 &&
					 (dp->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
					  dp->i_df.if_format == XFS_DINODE_FMT_BTREE)) ? 1 : 0,
					current->comm);
		}
	}
	/*
	 * candidate-B tried loosening this gate to publish on
	 * every create for peer-reachable dirs at gen==0 — REVERTED: a
	 * synchronous log_force(SYNC)+bwrite per create while holding the dir
	 * ILOCK_EXCL kept the lock long enough that peers' EX acquires timed
	 * out (rc=-110) -> mass shutdown (xfs_mxfs_dlm.c:15570).  Durability
	 * must be enforced at EX-RELEASE (handoff), not per-create.  Gate
	 * restored to gen>0. */
	/*  instrumented A/B gate on the per-modify sync flush.
	 * mode 1=always (default/), 0=never, 2=only when a peer wants EX. */
	{
	extern int mxfs_dir_persig_flush;
	bool persig_do = (mxfs_dir_persig_flush == 1) ||
			 (mxfs_dir_persig_flush == 2 && dp->i_dlm_dir_want_ex);
	if (persig_do && dp->i_dlm_dir_gen > 0 &&
	    (dp->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     dp->i_df.if_format == XFS_DINODE_FMT_BTREE)) {
		/*
		 * The caller (xfs_create/xfs_remove/xfs_rename) holds dp
		 * ILOCK_EXCL *and* dp->i_lock WRITE across this call, so the
		 * data fork is already stable and a reload cannot race us.  Do
		 * NOT take dp->i_lock here: mxfs_drain_ilock_read does a
		 * down_read_trylock, which can NEVER succeed against the
		 * caller's own held write lock (rwsems are not recursive) ->
		 * a 150s P132-ILOCK-STUCK self-deadlock (PROVEN D-state
		 * bash in xfs_create -> durable_signal -> mxfs_drain_ilock_read).
		 * Call the flush directly; ILOCK_EXCL is the fork-stability
		 * guarantee the bare mxfs_dir_flush_data_blocks needs.
		 */
		/* P11-POSTADD: dump the dir's in-core data-block
		 * names at durable_signal ENTRY (BEFORE log_force) for the storm
		 * dir.  Compared to the per-block P-RELFLUSH/P11-CLEANSKIP dump
		 * INSIDE mxfs_dir_flush_data_blocks (AFTER log_force), this
		 * bisects the durable-loss revert: a just-committed dirent
		 * PRESENT here but ABSENT in the flush dump => log_force/flush
		 * window reverts it; ABSENT here too => the revert is earlier
		 * (commit / addname-split). */
		if (unlikely((mxfs_dirwr_enabled || mxfs_instr_enabled) &&
			     dp->i_ino <= 256)) {
			extern void mxfs_dir_dump_block_names(struct xfs_inode *,
							      const char *);
			mxfs_dir_dump_block_names(dp, "PRELOGF");
		}
		xfs_log_force(mp, XFS_LOG_SYNC);
		mxfs_dir_flush_data_blocks(dp);
	}
	}

	mxfs_v5_dlm_note_dir_modified(mp->m_mxfs_dlm, dp->i_ino);
}
EXPORT_SYMBOL(mxfs_dlm_dir_durable_signal);

/*
 * /consumer side of the eviction ring (design review design Part 1+2).
 *
 * Invoked from the disklock heartbeat MONITOR THREAD (dlm/disklock.c) once per
 * entry a PEER published.  `type` selects the action:
 *
 *  INODE_FREE: a peer freed `ino` (now at di_gen `gen`).  If we hold a
 *    passively-cached (NL) in-core copy whose incarnation (i_generation) is at
 *    or behind the freed gen, it is stale (the number may be reused for a
 *    different type/contents and nothing BAST'd us).  Flag XFS_ISTALE_CAW +
 *    i_dlm_stale so the next path-walk lookup evicts + re-reads the dinode.
 *
 *  DIR_MODIFY: a peer modified directory `ino`.  If we hold a live
 *    in-core copy of that directory, bump its i_dlm_dir_gen so the next
 *    readdir's xfs_da_read_buf invalidates + FUA-re-reads its stale-but-CLEAN
 *    cached dir DATA/LEAF blocks.  (Only CLEAN blocks are invalidated by that
 *    hook; our own dirty/in_ail dir blocks are preserved — so this is safe even
 *    if we are concurrently modifying the same dir.)
 *
 * Runs OUTSIDE any xfs_iget / ILOCK / transaction context.  MUST NOT block, do
 * I/O, sleep, or take inode/AG DLM locks.  Takes only pag_ici_lock +
 * i_flags_lock (spinlocks).  data == struct xfs_mount *.
 */
void
mxfs_dlm_evict_inode_cb(void *data, uint64_t ino, uint32_t gen, uint32_t type)
{
	struct xfs_mount	*mp = data;
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	xfs_agino_t		agino;

	if (!mp || ino == 0)
		return;

	agno = XFS_INO_TO_AGNO(mp, ino);
	if (agno >= mp->m_sb.sb_agcount)
		return;
	agino = XFS_INO_TO_AGINO(mp, ino);

	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return;

	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, agino);
	if (ip && ip->i_ino == ino) {
		spin_lock(&ip->i_flags_lock);

		if (type == MXFS_EVICT_TYPE_DIR_MODIFY) {
			/*
			 * Peer modified this directory.  Bump i_dlm_dir_gen on
			 * a live, fully-instantiated cached directory so the
			 * next readdir re-reads the committed dir blocks.  Only
			 * meaningful once the dir-block invalidation gen is
			 * armed (i_dlm_dir_gen != 0, set on the first multi-node
			 * dir read); a 0 means nothing is cached to go stale.
			 *
			 * the gen bump covers ONLY
			 * block/leaf dirs (consumed via xfs_da_read_buf).  A
			 * SHORTFORM dir's readdir reads the inline fork and
			 * never reaches that hook, so a peer's added entry
			 * stayed invisible (the 16-node posix barrier-dir
			 * staleness).  Arm MXFS_IF_DIR_RELOAD instead;
			 * xfs_readdir consumes it with an event-driven
			 * mxfs_dlm_reload_inode before sf getdents.  We hold
			 * only spinlocks here — flag is all we may do.  The
			 * i_dlm_dir_gen != 0 guard does not apply: shortform
			 * staleness needs no armed dir-block gen.
			 *
			 * FIX — arm MXFS_IF_DIR_RELOAD
			 * for EVERY dir format, not just LOCAL.  The original
			 * "LOCAL only" gate assumed block/leaf dirs need only
			 * their DATA blocks refreshed (i_dlm_dir_gen, consumed
			 * in xfs_da_read_buf / mxfs_dir_evict_data_blocks).  But
			 * that only re-reads blocks at daddrs the cached EXTENT
			 * MAP already knows.  When a peer GROWS a dir (shortform
			 * ->block->leaf) or shrinks+regrows it onto DIFFERENT
			 * blocks (block->shortform->block at a new daddr), the
			 * data-fork extent map itself changes.  A peer holding a
			 * stale extent map then maps a dir offset to a freed/
			 * reused block -> xfs_bmapi_read returns a HOLE
			 * (XFS_DABUF_MAP_HOLE_OK internal error, xfs_da_btree.c
			 * line 2814) or reads the wrong daddr -> xfs_dir3_block_
			 * verify fails -> Metadata I/O Error -> FS shutdown ->
			 * every posix_semantics barrier hangs 120s -> >600s
			 * timeout.  Forcing MXFS_IF_DIR_RELOAD makes the
			 * consumer (lookup/readdir) do a full mxfs_dlm_reload_
			 * inode, which xfs_idestroy_fork+xfs_inode_from_disk the
			 * data fork = the extent map is rebuilt coherently.
			 */
			if (!(ip->i_flags & (XFS_IRECLAIM | XFS_IRECLAIMABLE |
					     XFS_INEW | XFS_ISTALE)) &&
			    S_ISDIR(VFS_I(ip)->i_mode)) {
				if (ip->i_dlm_dir_gen != 0)
					ip->i_dlm_dir_gen++;
				ip->i_flags |= MXFS_IF_DIR_RELOAD;
				mxfs_probe_ratelimited(
					"mxfs: EVICT-RING-DIRMOD ino=%llu gen->%llu fmt=%u reload=%d\n",
					(unsigned long long)ino,
					(unsigned long long)ip->i_dlm_dir_gen,
					ip->i_df.if_format,
					!!(ip->i_flags & MXFS_IF_DIR_RELOAD));
			}
		} else {
			/*
			 * INODE_FREE.  Only flag a fully-instantiated, live
			 * cached inode that IS the freed incarnation.
			 *
			 * `gen` is the freed image's generation: xfs_ifree bumps
			 * i_generation once before it publishes, so a peer's
			 * cached copy of the freed incarnation carries gen - 1
			 * and the freeing node's own shell (or a copy reloaded
			 * from the free image) carries gen.  Nothing else is
			 * that incarnation.  XFS draws every new incarnation's
			 * generation at random (xfs_init_new_inode:
			 * get_random_u32), so the "at or behind" order this
			 * gate applied before 0.89.76 (i_generation <= gen)
			 * was a coin flip on a reused number.  Measured 2/tcp
			 * (tests/d0977_open_unlink_tcp.sh s170f): B closed
			 * incarnation A of number 2127; the peer freed it and
			 * created a successor on the same number; B opened the
			 * successor, recycling its cached shell in place; then
			 * A's free entry (gen A+1) reached B from the ring.
			 * The successor's random generation was below A+1 for
			 * two of five successors, and each time the entry
			 * poisoned B's live, open shell — the held descriptor
			 * read -ESTALE and the harness graded it lost data.
			 * A shell of some other incarnation is left alone
			 * here: this ring is a hint, and the grant-time reloads
			 * are what keep such a shell from being used.
			 */
			uint32_t	igen = (uint32_t)VFS_I(ip)->i_generation;
			bool		live = !(ip->i_flags &
					(XFS_IRECLAIM | XFS_IRECLAIMABLE |
					 XFS_INEW | XFS_ISTALE)) &&
					VFS_I(ip)->i_mode != 0;

			if (live && igen != gen && igen + 1 != gen) {
				mxfs_probe_ratelimited(
					"mxfs: EVICT-RING-OTHER-INCARN ino=%llu incore_gen=%u freed_gen=%u opens=%d mapped=%d — the cached shell is another incarnation of the number, not the freed one; left alone\n",
					(unsigned long long)ino, igen, gen,
					atomic_read(&ip->i_mxfs_open_n),
					mapping_mapped(VFS_I(ip)->i_mapping) ? 1 : 0);
			} else if (live) {
				/* 0.89.1 (D-0979): usable descriptors only; an
				 * open still in its protecting acquire meets the
				 * freed image in the reload under that acquire */
				bool prot = mxfs_inode_exposed(ip);

				ip->i_flags |= XFS_ISTALE_CAW;
				ip->i_dlm_stale = true; ip->i_dlm_stale_src = 12;
				/*
				 * 0.89.0 (D-0977): a peer FREED an incarnation
				 * this node still has open or mapped.  The
				 * open-holder mark should have deferred that
				 * free; whatever let it through, the blocks
				 * are gone and may already carry another
				 * file's bytes, so the descriptor must never
				 * read or write through this shell again:
				 * poison it (every file op refuses -ESTALE,
				 * every fault SIGBUS).  Flag only — this runs
				 * on the heartbeat monitor under spinlocks;
				 * the gates contain the shell without the
				 * revocation worker.
				 */
				if (prot)
					ip->i_flags |= MXFS_IF_INCARN_STALE;
				mxfs_probe_ratelimited(
					"mxfs: EVICT-RING-FLAG ino=%llu incore_gen=%u freed_gen=%u opens=%d mapped=%d poisoned=%d\n",
					(unsigned long long)ino,
					VFS_I(ip)->i_generation, gen,
					atomic_read(&ip->i_mxfs_open_n),
					mapping_mapped(VFS_I(ip)->i_mapping) ? 1 : 0,
					prot ? 1 : 0);
			}
		}
		spin_unlock(&ip->i_flags_lock);
	}
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
}

void
mxfs_p98_getattr_check(struct xfs_inode *ip)
{
	struct xfs_mount	*mp;
	uint16_t		dmode = 0;
	uint64_t		dsz;

	if (likely(!mxfs_instr_enabled) || !ip)
		return;
	mp = ip->i_mount;
	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISREG(VFS_I(ip)->i_mode) || XFS_ISIZE(ip) != 0)
		return;

	dsz = mxfs_inode_disk_di_size(ip, &dmode, NULL);
	mxfs_probe_ratelimited("mxfs: P98-GETATTR ino=%llu incore_size=0 disk_di_size=%lld disk_mode=0%o dlm_mode=%u dlm_stale=%d (disk!=0 => READ-STALE in-core; disk==0 => writer not durable)\n",
		(unsigned long long)ip->i_ino, (long long)dsz,
		(unsigned)dmode, ip->i_dlm_mode, ip->i_dlm_stale);
}

/*
 * P71 diagnostic: FUA-read the AGI block from disk and return the
 * on-disk agi_unlinked[bucket] head agino, so P71 can compare it against the
 * in-core head.  If in-core==NULLAGINO but disk!=NULLAGINO → in-core STALE
 * (read-coherency: FUA re-read missed the peer's committed unlink-list head).
 * If disk ALSO==NULLAGINO → the in-core view matches disk; the "garbage" is a
 * genuine logic error (double-remove / inode never on the list), not staleness.
 * Returns the on-disk head agino, or 0xfffffffe on read error (distinct from
 * NULLAGINO 0xffffffff).  Caller holds the buffer locked.
 */
uint32_t
mxfs_agi_disk_bucket_head(struct xfs_buf *agibp, int bucket)
{
	uint32_t	len;
	uint64_t	lba;
	void		*tmp;
	uint32_t	head;
	int		rc;
	struct xfs_agi	*dagi;

	if (!agibp || !agibp->b_target || !agibp->b_target->bt_bdev)
		return 0xfffffffeU;
	len = BBTOB(agibp->b_length);
	if (len == 0 || (len & 511))
		return 0xfffffffeU;
	lba = (uint64_t)agibp->b_maps[0].bm_bn + agibp->b_target->bt_sector_offset;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return 0xfffffffeU;
	rc = mxfs_pal_scsi_read_fua_bdev(agibp->b_target->bt_bdev, lba, tmp, len);
	if (rc) {
		kfree(tmp);
		return 0xfffffffeU;
	}
	dagi = (struct xfs_agi *)tmp;
	head = be32_to_cpu(dagi->agi_unlinked[bucket]);
	kfree(tmp);
	return head;
}

/*
 * P71 diagnostic: FUA-read this inode's on-disk dinode and return its
 * di_mode.  0 ⇒ the inode is FREE on disk (a peer already inactivated/freed it
 * → this node is about to DOUBLE-FREE / double-remove-from-unlinked-list =
 * cross-node double-inactivation).  nonzero ⇒ still allocated.  Returns <0 on
 * error.  Caller holds the inode; runs only on the rare corruption path.
 */
int
mxfs_inode_disk_mode(struct xfs_inode *ip, uint32_t *nlink_out)
{
	struct xfs_mount	*mp = ip->i_mount;
	uint32_t		len;
	uint64_t		lba;
	void			*tmp;
	int			rc;
	uint16_t		mode;

	if (nlink_out)
		*nlink_out = 0xffffffffU;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return -EINVAL;
	len = BBTOB(ip->i_imap.im_len);
	if (len == 0 || (len & 511))
		return -EINVAL;
	lba = (uint64_t)ip->i_imap.im_blkno + mp->m_ddev_targp->bt_sector_offset;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	rc = mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev, lba, tmp, len);
	if (rc) {
		kfree(tmp);
		return rc < 0 ? rc : -EIO;
	}
	{
		struct xfs_dinode *dip =
			(struct xfs_dinode *)((char *)tmp + ip->i_imap.im_boffset);
		mode = be16_to_cpu(dip->di_mode);
		if (nlink_out)
			*nlink_out = be32_to_cpu(dip->di_nlink);
	}
	kfree(tmp);
	return (int)mode;
}

/*
 * (D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN instrument): raw FUA
 * read of ip's dinode returning the ON-DISK unlinked-list state.  The
 * hypothesis under test: a peer's mid-bucket remove rewires OUR cached
 * unlinked inode's di_next_unlinked on disk while the in-core
 * ip->i_next_unlinked (set at iget) is never refreshed across AG-DLM
 * handoffs — the later local remove then stitches the shared bucket with
 * the stale value.  disk_next != in-core next at remove time is the
 * direct discriminator.
 */
int
mxfs_inode_disk_unlinked(struct xfs_inode *ip, uint32_t *nlink_out,
			 uint32_t *next_out)
{
	struct xfs_mount	*mp = ip->i_mount;
	uint32_t		len;
	uint64_t		lba;
	void			*tmp;
	int			rc;
	uint16_t		mode;

	if (nlink_out)
		*nlink_out = 0xffffffffU;
	if (next_out)
		*next_out = 0xffffffffU;
	if (!mp->m_ddev_targp || !mp->m_ddev_targp->bt_bdev)
		return -EINVAL;
	len = BBTOB(ip->i_imap.im_len);
	if (len == 0 || (len & 511))
		return -EINVAL;
	lba = (uint64_t)ip->i_imap.im_blkno + mp->m_ddev_targp->bt_sector_offset;
	tmp = kmalloc(len, GFP_NOFS);
	if (!tmp)
		return -ENOMEM;
	rc = mxfs_pal_scsi_read_fua_bdev(mp->m_ddev_targp->bt_bdev, lba, tmp, len);
	if (rc) {
		kfree(tmp);
		return rc < 0 ? rc : -EIO;
	}
	{
		struct xfs_dinode *dip =
			(struct xfs_dinode *)((char *)tmp + ip->i_imap.im_boffset);
		mode = be16_to_cpu(dip->di_mode);
		if (nlink_out)
			*nlink_out = be32_to_cpu(dip->di_nlink);
		if (next_out)
			*next_out = be32_to_cpu(dip->di_next_unlinked);
	}
	kfree(tmp);
	return (int)mode;
}
