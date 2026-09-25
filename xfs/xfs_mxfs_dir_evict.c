// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- directory block ownership, eviction and consumer refresh
 */
#define MXFS_TU_ID 12	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

static bool
mxfs_dir_buf_owned_by(struct xfs_buf *bp, uint64_t ino)
{
	const struct xfs_buf_ops *ops = bp->b_ops;

	if (!bp->b_addr || !(bp->b_flags & XBF_DONE))
		return false;
	if (ops == &xfs_bmbt_buf_ops)
		return be64_to_cpu(((struct xfs_btree_block *)
			bp->b_addr)->bb_u.l.bb_owner) == ino;
	if (ops == &xfs_dir3_data_buf_ops ||
	    ops == &xfs_dir3_block_buf_ops ||
	    ops == &xfs_dir3_free_buf_ops)
		return be64_to_cpu(((struct xfs_dir3_blk_hdr *)
			bp->b_addr)->owner) == ino;
	if (ops == &xfs_dir3_leaf1_buf_ops ||
	    ops == &xfs_dir3_leafn_buf_ops ||
	    ops == &xfs_da3_node_buf_ops)
		return be64_to_cpu(((struct xfs_da3_blkinfo *)
			bp->b_addr)->owner) == ino;
	return false;
}
static int
mxfs_dir_collect_owned_bufs(struct xfs_inode *ip, struct xfs_buf **out,
			    int max, bool *overflow)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_agnumber_t		agno;
	int			n = 0;

	*overflow = false;
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
			if (!mxfs_dir_buf_owned_by(bp, ip->i_ino))
				continue;
			if (n >= max) {
				*overflow = true;
				break;
			}
			/* non-sleeping hold under the walk's RCU section */
			spin_lock(&bp->b_lock);
			if (bp->b_hold > 0) {
				bp->b_hold++;
				out[n++] = bp;
			}
			spin_unlock(&bp->b_lock);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
		xfs_perag_put(pag);
		if (*overflow)
			break;
	}
	return n;
}

/*
 * (instrumented): OWNER-based eviction of every cached dir
 * metadata block (data/block/leaf/free/node + bmbt) owned by ip, regardless of
 * the CURRENT in-core extent map.
 *
 * The per-extent-map evict (mxfs_dir_evict_data_blocks, and the reload's
 * data-block walk) only reaches daddrs the current map names.  When a reload
 * SHRINKS the map (P33-FROMDISK-DIRSHRINK: 3 data blocks -> 1, e.g. adopting a
 * freshly rm-rf+recreated incarnation) the PRIOR incarnation's leaf/data blocks
 * — at daddrs no longer in the map — survive cached and STALE.  A later lookup
 * walks the stale (owner==ino, same reused inode#) leaf, hash-resolves a name
 * to a data-block offset the shrunk map now treats as a hole, and ENOENTs:
 * the leaf-vs-data tear (drc leaf-hash lookup_fail).  Drop the durable/clean
 * owned buffers so the next read cold-FUA-fetches the coherent image; leave
 * dirty/pinned/in-AIL/un-DONE buffers (own un-checkpointed work) alone.
 *
 * O(whole buffer cache).  Call ONLY on the rare shrink/incarnation-change
 * reload — the owner-walk on every modify starved the dir-EX handoff.
 */
void
mxfs_dir_evict_owned_dir_blocks(struct xfs_inode *ip, bool leaf_only)
{
	struct xfs_buf	*owned[MXFS_DIR_OWNED_MAX];
	bool		overflow;
	int		n, i, evicted = 0;

	n = mxfs_dir_collect_owned_bufs(ip, owned, MXFS_DIR_OWNED_MAX, &overflow);
	for (i = 0; i < n; i++) {
		struct xfs_buf		*bp = owned[i];
		struct xfs_buf_log_item	*bip;
		bool			undurable;

		if (!xfs_buf_trylock(bp)) {
			xfs_buf_rele(bp);	/* in-flight: next read re-fetches */
			continue;
		}
		/*
		 * < > leaf_only: on a genuine cross-node EX handoff we
		 * must refresh only the derived LEAF/NODE/free INDEX (the stale-flush
		 * source of the DISK-TORN tear) — NOT the DATA blocks that hold the
		 * dirents.  Cold-re-reading clean DATA blocks on every handoff churns
		 * a node's dir view to empty when dir-data durability lags (test6
		 * readdir=0).  The leaf is a pure index, safe to drop+rebuild.
		 */
		if (leaf_only &&
		    (bp->b_ops == &xfs_dir3_data_buf_ops ||
		     bp->b_ops == &xfs_dir3_block_buf_ops)) {
			xfs_buf_relse(bp);
			continue;
		}
		bip = bp->b_log_item;
		undurable = (bip && (test_bit(XFS_LI_DIRTY,
					     &bip->bli_item.li_flags) ||
				     test_bit(XFS_LI_IN_AIL,
					     &bip->bli_item.li_flags))) ||
			    xfs_buf_ispinned(bp) ||
			    (bp->b_flags & _XBF_DELWRI_Q) ||
			    !(bp->b_flags & XBF_DONE);
		/* per-block decision + image fingerprint + CIL
		 * residency for the ledger replay (see P4R-RELSTALE). */
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled) &&
		    (bp->b_ops == &xfs_dir3_data_buf_ops ||
		     bp->b_ops == &xfs_dir3_block_buf_ops)) {
			static atomic_t p4o_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p4o_n) <= 100000) {
				uint32_t fs = 0, fx = 0, fc = 0;

				if (bp->b_addr)
					fc = mxfs_dir3_data_fingerprint(
						ip->i_mount, bp->b_addr,
						BBTOB(bp->b_length),
						((struct xfs_dir3_blk_hdr *)
						 bp->b_addr)->magic ==
						cpu_to_be32(XFS_DIR3_BLOCK_MAGIC),
						&fs, &fx);
				mxfs_probe("mxfs: P4O-OWNEVICT ino=%llu daddr=%lld evict=%d dirty=%d in_ail=%d pin=%d delwri=%d done=%d in_cil=%d fcnt=%u fsum=0x%x fxor=0x%x comm=%s realns=%llu\n",
					(unsigned long long)ip->i_ino,
					(long long)bp->b_maps[0].bm_bn,
					undurable ? 0 : 1,
					(bip && test_bit(XFS_LI_DIRTY,
						&bip->bli_item.li_flags)) ? 1 : 0,
					(bip && test_bit(XFS_LI_IN_AIL,
						&bip->bli_item.li_flags)) ? 1 : 0,
					xfs_buf_ispinned(bp) ? 1 : 0,
					(bp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
					(bp->b_flags & XBF_DONE) ? 1 : 0,
					(bip && !list_empty_careful(
						&bip->bli_item.li_cil)) ? 1 : 0,
					fc, fs, fx, current->comm,
					(unsigned long long)ktime_get_real_ns());
			}
		}
		if (!undurable) {
			bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			bp->b_mxfs_dir_gen = 0;
			evicted++;
		}
		xfs_buf_relse(bp);
	}
	mxfs_probe_ratelimited(
		"mxfs: P68-OWNEVICT ino=%llu collected=%d evicted=%d overflow=%d\n",
		(unsigned long long)ip->i_ino, n, evicted,
		overflow ? 1 : 0);
}

int mxfs_dir_force_evict = 1;
module_param_named(dir_force_evict, mxfs_dir_force_evict, int, 0644);
MODULE_PARM_DESC(dir_force_evict,
	"force cross-node dir clean-block evict on every modify (not local-gen-gated); 1=on");

/*
 * 0.75.39 (2/tcp, tests/hot_inode_peer_unlink_2node.sh) — a REGULAR
 * FILE's cached-mode fast path yields to a peer's pending request.
 *
 * MEASURED: A writes one file in a tight loop (open O_TRUNC, write, close,
 * ~0.8 ms per round); B's `rm` of that file waited 2534 / 3030 / 2763 ms and
 * returned 110 / 94 / 82 ms AFTER A's loop ended, with P-LKTIMEOUT-* firing
 * on B every time.  A's trace on the inode: P7B-BASTNOTIFY, then P70-BP
 * ENTRY with ex=0 pr=0 pin=0, then P2D-DRAINWHY in_ail=1 flushing=1 — the
 * drain waiting for the inode to come clean — while 7864 local holds were
 * admitted in state DEMOTING (mode still EX) and kept re-dirtying it; the
 * release completed 2.47 s later, the moment the loop stopped.
 *
 * Directories have gated this fast path on state==CACHED since v0.3.13.
 * Files kept a mode-only check because bast_process's filemap_write_and_wait
 * dispatches xfs-conv kworkers that must re-enter under the still-held grant
 * (v0.3.5 /).  Those are kernel threads; a user task starting NEW work
 * is not what that exemption was for.  So: a user task with nothing pinned
 * asking for a file whose grant a peer has requested (state BAST) or is
 * being drained away (state DEMOTING, foreign demoter) falls through to the
 * demote-wait and re-acquires after the hand-off.  Kernel threads, the
 * demoter itself, pinned chains and the nested-hold breaker (a task
 * that already holds the inode) are untouched.  The release-flush admission
 *  is narrowed to kernel threads on the same reasoning.
 *
 * Knob, default ON, for the A/B the measurement is quoted against.
 */
int mxfs_file_yield_on_demote = 1;
module_param_named(file_yield_on_demote, mxfs_file_yield_on_demote, int, 0644);
MODULE_PARM_DESC(file_yield_on_demote,
	"a regular file's cached-grant fast path yields to a peer's pending request (state BAST/DEMOTING) for user tasks with nothing pinned; 1=on (default)");

bool
mxfs_file_yield_gate(const struct xfs_inode *ip, int mode)
{
	if (!READ_ONCE(mxfs_file_yield_on_demote) ||
	    S_ISDIR(VFS_I((struct xfs_inode *)ip)->i_mode) ||
	    ip->i_dlm_pin_count != 0 ||
	    /*
	     * 0.75.40: only when NO local holder is counted.  The drain
	     * cannot start while one is (bast_process enters at ex=0 pr=0
	     * or aborts, P15-REL-ABORT), so parking a new requester behind
	     * a local holder serves no peer — and when the holder is this
	     * very task taking its nested ILOCK under a counted IOLOCK it is
	     * a self-deadlock the demote-wait only breaks with its 3 s
	     * rescue polls.  MEASURED (board s522o, 0.75.39):
	     * dir_reuse_coherency BARRIER_TIMEOUT 116 s with test2 printing
	     * P-FILE-YIELD ino=8927045 req=5 ex=1 every ~3 s.  The sess4
	     * nested-hold breaker admits this case at state BAST; the mode
	     * fast path keeps admitting it at DEMOTING as before 0.75.39.
	     */
	    ip->i_dlm_ex_holders != 0 || ip->i_dlm_pr_holders != 0 ||
	    (current->flags & PF_KTHREAD) ||
	    mxfs_is_demoter(ip))
		return false;
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_DEMOTING)
		return mxfs_foreign_demoter(ip);
	return ip->i_dlm_state == MXFS_DLM_ISTATE_BAST;
}

/*
 * — D-UNMOUNT-BUSY-INODES.  Registry of live xfs_inodes so the object
 * that survives the last unmount (and blocks kmem_cache_destroy at rmmod) can
 * be named with full state instead of being an anonymous slab object.  The
 * list itself lives in xfs_icache.c; the knob is here with the other mxfs
 * params.  Default on: one spin_lock/list op per inode alloc and free.
 */
module_param_named(live_inode_track, mxfs_live_inode_track, int, 0644);
MODULE_PARM_DESC(live_inode_track,
	"track every live xfs_inode so a leak surviving unmount is named at module unload (P202); 1=on (default)");

/*
 * NEW-TENURE in-AIL evict.  dir_force_evict already evicts CLEAN
 * dir blocks on every modify, but its keep-guard retains an in-AIL block whose
 * last mods are merely undestaged-in-AIL (mxfs_dir_buf_is_undestaged) — assumed
 * to be this node's own un-checkpointed work.  PROVEN HOLE: after a
 * peer cross-node EX handoff, that in-AIL block is DURABLE (Inv 1 drained it at
 * our release) but STALE (the peer added a dirent to the same data block after
 * we released); keeping it makes the first RMW of our next tenure pick a free
 * slot the peer already used (EQUAL-count / DIFFERENT-fingerprint clobber) and
 * destage it over the peer's entry — the dir_reuse_coherency readdir=799 loss.
 *
 * Fix: detect a NEW TENURE = the master dir epoch advanced past i_dlm_dir_evict_mep
 * (a peer held EX since our last evict).  On the FIRST modify of a new tenure,
 * DROP the in-AIL-undestaged keep clause so those durable-but-stale blocks are
 * evicted and the RMW cold-reads the peer's image.  SAFE because (a) at modify-
 * START this tenure's own new work does not exist yet (the create runs after the
 * evict), and (b) anything in-AIL is from before the handoff = drained durable.
 * The dirty / pinned / delwri / !DONE hard-guards stay (genuine in-flight bytes).
 * Unlike dir_tenure_evict (which syncs valid_epoch mid-tenure and mis-evicts this
 * tenure's OWN earlier blocks -> readdir=0), the compare is per-evict-call, so a
 * second modify in the same tenure sees the same epoch and keeps live work.
 */
int mxfs_dir_newtenure_evict = 1;	/* DEFAULT 1 — at the first modify of a new cross-node tenure (master dir epoch advanced) force-evict the durable-but-stale prior-tenure base so the RMW cold-reads the peer's image (fixes dir_reuse readdir=799).  set this 0 because clearing XBF_DONE on an in-AIL-UNDESTAGED block left a ZOMBIE BLI that reflushed the stale image -> readdir=0/800.  FIXED that by RETIRING the BLI at the new-tenure evict (P34-NEWTENURE-RETIRE, mxfs_dir_evict_data_blocks !undurable branch): at new_tenure the block is durable (Inv 1 drained our work at our prior release, before the peer's tenure) so the undestaged flag is a false positive and retiring is loss-safe.  Inert for shortform dirs (return-true early) and single-node, so 1/tcp + tcp_dlm_scaling unaffected. */
module_param_named(dir_newtenure_evict, mxfs_dir_newtenure_evict, int, 0644);

/*
 * — design review grant-generation evict (/23/61
 * design, finally wired into the MODIFY-EVICT keep-guard).  ROOT (proven this
 * run, drain writes a stale-base block; bmap not stale; 
 * P67 read-path backstop fired 0× because a cache-HIT read RE-STAMPS the stale
 * block fresh — all of bufgen/grant_gen/epoch read "current" at RMW time).  The
 * keep-guard wrongly keys KEEP on the in-AIL undestaged FLAG (AIL bookkeeping is
 * NOT a durability/ownership oracle — design review's exact identified bug).  At the
 * EVICT (which runs BEFORE the stale read re-stamps), a prior-tenure block still
 * carries its OLD b_mxfs_grant_gen != the inode's current i_dlm_cached_grant_gen
 * (the acked-TCP per-grant token, which advances ONLY via a slow-path re-grant =
 * we RELEASED EX = Invariant 1 drained our work to the LUN before the peer's
 * tenure).  So a grant-stale in-AIL clean block is a durable-but-stale base whose
 * undestaged "keep" is a false positive: force-evict it so the RMW cold-reads
 * the peer's superset image.  Stamped-nonzero gate (b_grant_gen!=0 && cached!=0)
 * avoids dropping an ambiguous never-stamped block (no resurrection).
 * dirty/pin/delwri/!DONE stay hard-guarded (current-tenure in-flight work carries
 * b_grant_gen==cached so it is never flagged; grant_gen cannot change while we
 * hold EX continuously).  Default 1.
 */
int mxfs_dir_grant_evict = 1;	/* DEFAULT 1 (combo, see dir_owner_scan). DEFAULT 0 — the grant-gen evict is the correct /61 design and is SAFE (no shutdowns, fires on the right daddrs) but INSUFFICIENT: it refreshes the RMW base yet the durable single-dirent loss persists (PROVEN fresh base + still-lost node2_f49 => the loss is a stale WRITE, not a stale base).  Kept as an A/B lever; default off so the build stays keeper-equivalent. */
module_param_named(dir_grant_evict, mxfs_dir_grant_evict, int, 0644);
MODULE_PARM_DESC(dir_grant_evict,
	"force-evict a clean in-AIL dir block whose b_mxfs_grant_gen lags the "
	"inode's cached grant gen (prior-tenure stale base); 1=on default");

int mxfs_dir_gen_evict;	/*  DEFAULT 0 (A/B lever pending validation). Force-evict a clean in-AIL dir DATA/BLOCK block whose b_mxfs_dir_gen (stamped ONLY at cold read time) lags the inode's current i_dlm_dir_gen -- the exact dc_stale predicate the write-side clobber guards (dir_ex_write_guard/dataclobber/dir_reintro_probe) already trust, but which incarn_aba/new_tenure/prior_tenure/grant_stale_base (keyed on other fields) do not cover. Targets cache_coherency@32 "uv gone" (Case B dangling dirent): P-REINTRO proved a bgen<dirgen block reaches destage with stale content because eviction never forced its re-read before the RMW captured it. See the P-GENEVICT site comment for the sess5-relepoch-regression safety analysis (why this field, unlike relepoch, cannot false-fire against in-flight same-tenure work). */
module_param_named(dir_gen_evict, mxfs_dir_gen_evict, int, 0644);
MODULE_PARM_DESC(dir_gen_evict,
	"force-evict a clean in-AIL dir DATA/BLOCK block whose b_mxfs_dir_gen "
	"lags the inode's current dir_gen (dc_stale prior-tenure base, "
	"uncovered by epoch/grant/incarn discriminators); 0=off (default)");

int mxfs_dir_subset_guard;	/* ROOT-FIX candidate: DEFAULT 0.  Write-chokepoint dirent SUBSET guard: suppress a CLEAN (bdirty=0) in-AIL xfsaild push of a multinode dir DATA block when the on-disk block holds a dirent (inumber) the in-core image LACKS (would durably drop a peer's just-added entry = readdir=799 clobber).  same-incarnation gated; legit removes are dirty (never suppressed), legit adds are in-core supersets (extra==0). */
module_param_named(dir_subset_guard, mxfs_dir_subset_guard, int, 0644);
MODULE_PARM_DESC(dir_subset_guard,
	"suppress a clean in-AIL xfsaild dir-DATA write whose in-core image is missing an inumber present on disk (would drop a peer dirent); 1=on");

int mxfs_dir_reintro_probe;	/* DEFAULT 0.  P-REINTRO diagnostic — at the dir-write chokepoint, for a dc_stale (prior-tenure) dir DATA/BLOCK image, read current disk and log any in-core-extra dirent (inum absent on disk) whose on-disk inode is FREE (a dangling-dirent REINTRODUCE) vs LIVE (a legit un-landed add).  Names the reintroducing write (comm/mode/in_ail/undest/gen).  Heavy (per-extra-inum FUA read) — gated on dc_stale so the common path is untouched; diagnostic runs only. */
module_param_named(dir_reintro_probe, mxfs_dir_reintro_probe, int, 0644);
MODULE_PARM_DESC(dir_reintro_probe,
	"log dir-write chokepoint reintroduce candidates (stale in-core-extra dirent to a freed inode); 1=on");

int mxfs_dir_reintro_skip;	/* DEFAULT 0.  P-REINTRO-SKIP fix — drop the xfsaild write of a CLEAN superseded zombie dir DATA/BLOCK buffer (in-AIL, !dirty, !pinned, !undestaged, same-incarnation, dc_stale) whose in-core-extra dirents are PURELY free reintroduces (live_extra==0), and mark it for re-read.  Never drops a live add (live_extra>0 => write proceeds).  Lightweight: the disk read + per-inum FUA only run on the rare dc_stale+incore-extra path, so no per-handoff latency (budget).  Targets the 16-node durable dangling-dirent (CASE B). */
module_param_named(dir_reintro_skip, mxfs_dir_reintro_skip, int, 0644);
MODULE_PARM_DESC(dir_reintro_skip,
	"drop a clean stale-zombie dir write that would reintroduce a removed dirent pointing at a freed inode; 1=on");

int mxfs_dir_reintro_trim;	/*  DEFAULT 0.  cache_coherency@32 "uv gone" ROOT PROVEN (P68-EVDECIDE trace): these blocks are NEVER in-AIL between operations (evicted+refetched every modify call, exactly as designed) -- so dir_reintro_skip's in-AIL/!undestaged gate is structurally inert here (confirmed empirically: 0 fires across 2 full 32-node runs despite 13+ dir_reintro_probe fires). The real mechanism is a genuine sub-millisecond TOCTOU -- our own coherent read of a dir DATA/BLOCK block races a peer's own durable remove landing on the SAME block microseconds later; our own (unrelated) destage moments after carries the peer's already-removed dirent forward. Mirror of the ADD-direction TOCTOU mxfs_dir3_data_writemerge already fixes by GRAFTING (not dropping) -- this is the REMOVE-direction fix: SURGICALLY converts each in-core-extra entry whose target inode is PROVEN FREE (mxfs_dir3_reintro_free_count's existing discriminator -- a dirent can never legitimately point to a freed inode) to a free/unused descriptor in place, then freescans to rebuild bestfree. Every other byte of the write, including this operation's own genuine edit, is untouched -- unlike dir_reintro_skip's whole-write drop (unsafe per the revert: a dirty/undestaged write here typically also carries genuine not-yet-durable local content). Safe regardless of live_extra (live entries are never touched). */
module_param_named(dir_reintro_trim, mxfs_dir_reintro_trim, int, 0644);
MODULE_PARM_DESC(dir_reintro_trim,
	"surgically remove (not drop the whole write) in-core dir DATA/BLOCK "
	"dirents proven to point at a freed inode before the write proceeds; "
	"0=off (default)");

/* DIAGNOSTIC (default 0): at every multinode dir-DATA-block write, FUA-read
 * disk and report disk_extra (inumbers on disk the in-core write LACKS = peer adds
 * we'd revert) AND incore_extra (inumbers in-core that disk LACKS = our new adds).
 * Distinguishes the fix direction: incore_extra>0 && disk_extra>0 = MERGE-needed
 * (both writers have unique entries; suppression drops ours, writing drops theirs);
 * incore_extra==0 && disk_extra>0 = pure stale rewrite (safe to suppress). */
int mxfs_dir_writeprobe;
module_param_named(dir_writeprobe, mxfs_dir_writeprobe, int, 0644);

/* WRITE-SIDE 3-WAY MERGE.  DEFAULT 0.  At the dir DATA-block bio
 * chokepoint, when the in-core image we are about to destage and the current
 * on-disk image have DIVERGED IN BOTH DIRECTIONS (we hold an add the disk lacks
 * AND the disk holds an add we lack = MERGE-NEEDED), graft the disk's unique
 * dirents into our in-core block before the write so the destage cannot revert a
 * peer's durable add.  Gated on bidirectional divergence so it NEVER touches a
 * pure-stale write (a legit remove looks pure-stale -> would resurrect).  Proven
 * root: smoking gun (P-WMERGE held_mode=EX in_ail=1 MERGE-NEEDED) — a
 * peer add lands durably AFTER our last refresh but BEFORE this async xfsaild
 * destage (a write-side TOCTOU the read-side refresh cannot close). */
int mxfs_dir_write_merge;
module_param_named(dir_write_merge, mxfs_dir_write_merge, int, 0644);
MODULE_PARM_DESC(dir_write_merge,
	"graft a peer's disk-only dirents into a MERGE-NEEDED dir DATA block at bio submit so the destage cannot revert a peer add; 1=on");

int mxfs_dir_fua_refresh_destaged;	/* ROOT-FIX candidate: DEFAULT 0.  In mxfs_buf_read_fua, allow the FUA pierce on a multi-node dir DATA/LEAF buffer that has a LINGERING attached BLI but is DESTAGED (pin==0 && logged_seq==written_seq) — refreshing the stale prior-tenure RMW base the P91 skip otherwise keeps, AND the stale b_addr xfsaild would destage.  pin/undestaged still hard-skip (un-checkpointed work protected). */
module_param_named(dir_fua_refresh_destaged, mxfs_dir_fua_refresh_destaged, int, 0644);
MODULE_PARM_DESC(dir_fua_refresh_destaged,
	"FUA-refresh a destaged (lingering-BLI) multinode dir DATA/LEAF buffer in mxfs_buf_read_fua instead of keeping the stale in-core image; 1=on");
MODULE_PARM_DESC(dir_newtenure_evict,
	"on the first dir modify after a cross-node EX handoff (master epoch advanced), "
	"force-evict even in-AIL-undestaged (durable-but-stale) dir blocks so the RMW "
	"cold-reads the peer's image; 1=on");

/*
 * refresh-in-place the residual xfsaild zombie reflush.
 * After the membership split-brain fix (deferred-TCP-death + EX-grant settle-gate
 * in dlm/), the only remaining 8/tcp dir_reuse loss is a CLEAN in-AIL dir DATA
 * block (block 0) that this node holds EX for but whose cached image is 1 dirent
 * behind durable disk (a peer's add the acquire-side drain_evict SKIPPED, left>0).
 * xfsaild background-reflushes that stale image over the peer's durable block.
 *
 * The refuted write-side fixes all DROPPED/SKIPPED the write (left the stale image
 * in-core -> readdir=0 cascade) or RETIRED the BLI (over-lost / cemented stale).
 * This is different: at the bio-submit chokepoint, when the disk is a strict
 * SUPERSET of the in-core buffer (disk has dirents we lack AND we have NONE the
 * disk lacks = a pure stale-subset, no un-landed work) AND we currently hold the
 * dir EX (so NO peer can be writing this block right now -> the plain disk read is
 * STABLE, not torn), COPY the disk image into the buffer and complete the write as
 * a no-op (content already == disk).  This makes the in-core image CORRECT (no
 * loss: we had no entries disk lacked) and avoids writing the stale image.  Gated
 * default-off; the keeper build is the clean membership-fix build.
 */
int mxfs_dir_refresh_inplace = 0;	/* REFUTED (default 0, inert): both
				 * variants of the dir-write-chokepoint intervention corrupt.
				 * v1 (memcpy disk->buf) tripped xfs_dir3_block_verify (block
				 * 0x78). v2 (EX-gated pure-subset DROP via P12/P26 ioend+gen=0)
				 * was validated on 8/tcp dir_reuse → CATASTROPHIC 0/8:
				 * xfs_dir2_leaf_removename metadata corruption (leaf1 0xbfa438)
				 * + bnobt double-free (ltbno+ltlen>bno, xfs_free_ag_extent) +
				 * readdir=0/800. Dropping the in-AIL dir write desyncs the
				 * buffer's log/CRC/verifier state from disk. ALL buffer-layer
				 * interventions now refuted; the residual zombie needs the
				 * ARCHITECTURAL fix (write-authority token / flush-quiesce at
				 * handoff-acquire). Kept as kill-switchable param only. */
module_param_named(dir_refresh_inplace, mxfs_dir_refresh_inplace, int, 0644);
MODULE_PARM_DESC(dir_refresh_inplace,
                 "At xfsaild dir-block flush, if disk is a strict superset of a "
                 "clean in-AIL buffer we hold EX for, refresh the buffer from disk "
                 "and skip the stale write (1=on default, 0=off)");

/* (design review Policy-A gap-close): when set, a read-path tenure_stale
 * buffer (b_mxfs_dir_epoch < MASTER dir epoch) bypasses the in-AIL-undestaged
 * keep-guard (xfs_da_btree.c) and is invalidated + re-read.  Closes the
 * residual ~1/3 readdir=799 that dir_tenure_evict alone leaves (the stale base
 * was in_ail-undestaged so the keep-guard preserved it).  Loss-safe: tenure_stale
 * is true ONLY for genuine prior-tenure blocks (Inv 1 drained our work at the
 * prior release).  Use WITH dir_tenure_evict=1.  Default 0 until A/B-proven. */
int mxfs_dir_tenure_stale_bypass;
module_param_named(dir_tenure_stale_bypass, mxfs_dir_tenure_stale_bypass, int, 0644);

/* EXPERIMENTAL — coherency safety UNTESTED (default 0).  When 1,
 * mxfs_dir_release_invalidate_data_blocks skips the invalidation unless a peer
 * BAST requested EX (i_dlm_dir_want_ex).  Intent: keep cached dir blocks for
 * private/PR-shared dirs (the 32-node dlm_scaling cold-reread storm: ~2.7GB
 * reads/run, ~18 cold dir re-reads/op that are 0 solo; global eviction-off lifts
 * dlm_scaling 0/32->29/32).  Gives +15-18% at 32/caw (marginal).  CAUTION: the
 * i_dlm_dir_want_ex flag (set in bast_notify, cleared on grant) is potentially
 * RACY vs the release path, so a stale-false flag could skip a needed invalidate
 * and serve a stale dir cross-node.  An attempted 4/caw coherency A/B was
 * INCONCLUSIVE (the substrate was PR-fenced = reservation-conflict, all reads
 * empty, so param-on AND param-off both "failed" — NOT a valid coherency signal).
 * The robust fix is design review's LOCK-protected caching (hold >=PR across lookups,
 * invalidate only on a real EX BAST — the lock, not a flag, is the guarantee);
 * see docs/history/caw-32node-dlm-scaling-fix-progress-and-fable-design.md.  Default 0
 * (keeper-equivalent; the flag plumbing is inert when off). */
int mxfs_dir_release_skip_nonex;
module_param_named(dir_release_skip_nonex, mxfs_dir_release_skip_nonex, int, 0644);
MODULE_PARM_DESC(dir_release_skip_nonex,
	"skip release-time dir-buffer invalidation unless a peer BAST requested EX (keeps cache for private/PR-shared dirs; default 0)");

/* (design review Hole B): disable dir-block readahead on multinode shared dirs —
 * a readahead from a prior tenure can complete late and re-populate the buffer
 * cache with a stale XBF_DONE image past the acquire-evict, feeding a stale dir
 * base into the next modify (leaf hash/address divergence). 1=disable (default). */
/* default 1 (ON for multinode shared dirs). PROVEN (instrumented, build
 * 5E54558B): a dir-block READAHEAD bypasses the xfs_da_read_buf coherency
 * gen-stamp, so a speculative read submitted before a peer's write and
 * completing after re-acquire repopulates the cache with a STALE image
 * (b_mxfs_dir_gen=0) marked XBF_DONE that the acquire-side evict already ran
 * past -> the next modify RMWs a stale dir base -> durable dirent/leaf-hash
 * loss (P-LEAFWRITECLOBBER buf_cnt=119 over disk_cnt=202 bufgen=0).  With
 * reada disabled, crash_consistency PASSES 3/3 (was reliably 1/2).  The gate
 * (xfs_da_reada_buf) is scoped to multinode shared dirs only, so SINGLE-NODE
 * keeps readahead = no perf regression there.  Speculative dir readahead on a
 * concurrently-modified shared LUN is a coherency hazard, not a perf win (the
 * GFS2/OCFS2 conservative-readahead rationale).  The "1/2 regression"
 * was contaminated cluster state (re-validated 3/3 clean here). */
int mxfs_dir_no_reada = 1;
module_param_named(dir_no_reada, mxfs_dir_no_reada, int, 0644);
MODULE_PARM_DESC(dir_no_reada,
	"disable dir-block readahead on multinode shared dirs (coherency); 1=on (default), 0=off");
EXPORT_SYMBOL(mxfs_dir_no_reada);

bool
mxfs_dir_evict_data_blocks(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	unsigned int		dir_blk_bb;
	bool			all_evicted = true;	/* false if any undurable block skipped */
	uint32_t		cur_mep = 0;		/* master dir epoch this call */
	bool			new_tenure = false;	/* peer held EX since our last evict */

	/* (instrumented): always-on capped entry probe — multinode dirs only.
	 * P68-EVDECIDE fires only INSIDE the per-block loop after a cached block
	 * is found; it was 0, so this tells us which early-return / empty-loop
	 * path is taken (fmt + extent state) at evict time. */
	/*
	 * BTREE-format dirs used to `return true`
	 * here — a LIE that advanced i_dlm_dir_evicted_gen with everything
	 * still cached stale (P106-MR-SKIP then fast-pathed every modify onto
	 * the stale base = the zsl quiet dirent loss + bmbt/dinode tear).
	 * The iext walk below works for a BTREE fork too once its extents are
	 * in-core (always true by modify/lookup time — the dir was just read);
	 * the real gate is extents-loaded, not fork format.  An unenumerable
	 * dir (BTREE, extents not yet read) returns false so the gen does NOT
	 * advance and the lazy read hooks stay armed.  (A first owner-based
	 * buffer-cache-walk version of this fix was correct but O(whole cache)
	 * per modify — it starved the dir-EX handoff cluster-wide.)
	 */
	if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE) {
		if (xfs_need_iread_extents(&ip->i_df))
			return false;
	} else if (ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS)
		return true;		/* shortform: no data blocks */

	/*
	 * NEW-TENURE detection (see mxfs_dir_newtenure_evict).
	 * Compute the master dir epoch ONCE; if it advanced past our last evict,
	 * a peer held EX in between (a real handoff) so this is the first modify
	 * of a fresh tenure and our in-AIL-undestaged blocks are durable-but-stale.
	 */
	if (mxfs_dir_newtenure_evict && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		cur_mep = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm, ip->i_ino);
		new_tenure = (cur_mep != 0 && cur_mep != ip->i_dlm_dir_evict_mep);
		/*
		 * on the FIRST evict of a new tenure ONLY, sync
		 * valid_epoch UP to the master epoch BEFORE any modify this
		 * tenure stamps a block.  Then every block we touch this tenure
		 * carries b_mxfs_dir_epoch == cur_mep, so the per-block prior-
		 * tenure test below (b_epoch < cur_mep) flags ONLY genuinely
		 * stale prior-tenure bases and NEVER this tenure's own work (the
		 * readdir=0 trap = syncing valid_epoch MID-tenure after
		 * earlier blocks were stamped low; doing it once at tenure start,
		 * before any modify, avoids that).  cur_mep cannot advance while
		 * we hold EX continuously, so valid_epoch stays == cur_mep all
		 * tenure.
		 */
		/* braces — the incarn stamp was OUTSIDE the if (indentation
		 * lied), so every multinode dir modify stamped valid_incarn = live
		 * generation even when the epoch was NOT synced, converting "no
		 * baseline" (which mxfs_dir_epoch_superseded handles) into "live
		 * baseline of 0" (permanently stale — the P195 raw-compare feed). */
		if (new_tenure && cur_mep > ip->i_dlm_dir_valid_epoch) {
			ip->i_dlm_dir_valid_epoch = cur_mep;
			ip->i_dlm_dir_valid_incarn = VFS_I(ip)->i_generation;	/* the baseline belongs to THIS incarnation */
		}
	}

	/*
	 * (design review §6): SYNC i_dlm_dir_valid_epoch UP TO the master
	 * authoritative dir epoch before the per-block prior-tenure compare.
	 * i_dlm_dir_valid_epoch LAGS (it is set only at the end of the acquire
	 * reload, after keep-guards that often short-circuit — xfs_da_btree.c
	 * comment), so b_mxfs_dir_epoch (stamped from valid_epoch) can EQUAL a
	 * lagging valid_epoch even after a real peer handoff -> the P23 prior-
	 * tenure override UNDER-FIRES (the residual single-entry loss).  The master
	 * epoch (mxfs_v5_dlm_inode_dir_epoch) advances reliably on every cross-node
	 * EX handoff.  Monotonic max: it only advances, and the master epoch cannot
	 * advance while we hold EX continuously (no peer EX) -> a current-tenure
	 * block read THIS tenure was stamped at this same (now-synced) epoch and is
	 * NOT flagged stale (no resurrection); only genuinely prior-tenure blocks
	 * (b_epoch < synced valid_epoch) are evicted.  Gated on dir_tenure_evict.
	 */
	if (mxfs_dir_tenure_evict && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm)) {
		uint32_t mep = mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
							   ip->i_ino);
		/* braces — same unconditional-incarn-stamp bug as the
		 * new_tenure sync above; see that comment. */
		if (mep > ip->i_dlm_dir_valid_epoch) {
			ip->i_dlm_dir_valid_epoch = mep;
			ip->i_dlm_dir_valid_incarn = VFS_I(ip)->i_generation;	/* the baseline belongs to THIS incarnation */
		}
	}

	dir_blk_bb = XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

	/*
	 * instrumented DECISIVE: is THIS node's in-core dir bmap STALE vs the
	 * coherent on-disk inode at the START of a modify (we are about to evict
	 * + RMW)?  This evict walks ip->i_df extents; if the bmap is BEHIND disk
	 * (a peer grew the dir and we never reloaded the fork), we evict too-few
	 * blocks and RMW a stale base -> durable clobber of the peer's entries
	 * (node1_f1..N block-0 loss / leaf-hash loss; both nodes agree).
	 * Coherent plain-read the on-disk inode, compare di_nextents/size; fire
	 * only when disk is GROWN past in-core for the SAME incarnation.  Capped
	 * total reads so the perturbation stays bounded.
	 */
	/* (instrumented): RE-GATED to instr after CONFIRMING the round-1 stale-
	 * fork hypothesis is REFUTED — P37-STALEBMAP-MODIFY fired 0× on ALL 8
	 * nodes (probe ran 44-75×/node), so the incoming EX holder's in-core dir
	 * bmap is NEVER behind the durable on-disk inode for the same gen.  The
	 * round-1 loss is NOT a too-few-extents evict.  Re-gated so the criteria
	 * run pays no per-modify plain-read cost (budget). */
	if (unlikely(mxfs_instr_enabled || mxfs_dir_relverify) &&
	    mp->m_mxfs_dlm && !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
		extern int mxfs_pal_bdev_read_plain_bdev(struct block_device *,
							 uint64_t, void *,
							 uint32_t);
		static atomic_t	p37n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p37n) <= 5000) {
			uint32_t	icl = BBTOB(ip->i_imap.im_len);
			void		*ict = ((icl & 511) == 0 && icl) ?
						kmalloc(icl, GFP_NOFS) : NULL;

			if (ict && mxfs_pal_bdev_read_plain_bdev(
			    mp->m_ddev_targp->bt_bdev,
			    (uint64_t)ip->i_imap.im_blkno +
				mp->m_ddev_targp->bt_sector_offset,
			    ict, icl) == 0) {
				struct xfs_dinode *idd =
					ict + ip->i_imap.im_boffset;
				uint32_t disk_nx = be32_to_cpu(idd->di_nextents);
				uint64_t disk_sz = be64_to_cpu(idd->di_size);
				uint32_t disk_gen = be32_to_cpu(idd->di_gen);

				if (disk_gen == VFS_I(ip)->i_generation &&
				    (disk_nx > ip->i_df.if_nextents ||
				     disk_sz > (uint64_t)ip->i_disk_size))
					mxfs_probe("mxfs: P37-STALEBMAP-MODIFY ino=%llu incore_nx=%llu disk_nx=%u incore_fmt=%d disk_fmt=%d incore_size=%lld disk_size=%llu gen=%u comm=%s — modify on a STALE bmap (disk grown past in-core)\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)ip->i_df.if_nextents,
						disk_nx, ip->i_df.if_format,
						idd->di_format,
						(long long)ip->i_disk_size,
						disk_sz, disk_gen,
						current->comm);
			}
			kfree(ict);
		}
	}

	for_each_xfs_iext(&ip->i_df, &icur, &got) {
		xfs_daddr_t	d_start, d_end, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		d_start = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		d_end = d_start + XFS_FSB_TO_BB(mp, got.br_blockcount);

		for (d = d_start; d + dir_blk_bb <= d_end; d += dir_blk_bb) {
			struct xfs_buf		*dbp = NULL;
			struct xfs_buf_log_item	*bip;
			bool			undurable;
			int			ierr;

			/* XBF_TRYLOCK: a block we can't grab cleanly is being
			 * used by I/O completion or a peer drain; skip it and
			 * let the lazy read-path hook catch it. */
			ierr = xfs_buf_incore(mp->m_ddev_targp, d, dir_blk_bb,
					      XBF_TRYLOCK, &dbp);
			if (ierr == -EAGAIN) {
				/*
				 * Cached but LOCKED (in-flight I/O completion, or
				 * a peer drain).  This MODIFY-path evict is the
				 * ONLY place that drops the stale base BEFORE the
				 * create/rename RMW (the xfs_da_read_buf read hook
				 * is gated off under ILOCK_EXCL).  The OLD code
				 * skipped immediately (P36-EVICT-LOCKED) and "let
				 * the lazy read hook catch it" — but that hook ALSO
				 * XBF_TRYLOCK-skips under the same contention
				 * (P34-TRYLOCK-STALE).  So an ABA-stale block-0 at
				 * a reused daddr slips BOTH nets and the create
				 * RMWs a STALE base → the first-wave dirents
				 * (PROVEN: node1_f1..f12) are durably clobbered =
				 * the dir_reuse 2/tcp readdir shortfall.
				 *
				 * FIX: bounded TRYLOCK retry.  The
				 * holder already released the DLM grant for us to
				 * reach here, so the lock is almost always a
				 * transient in-flight I/O completion that clears in
				 * a few ms.  Do NOT take a BLOCKING lock — the read
				 * hook proved that deadlocks (a peer drain can hold
				 * this buffer while waiting on the inode-DLM grant
				 * we hold); TRYLOCK+msleep releases nothing while
				 * waiting, so a peer drain still makes progress.
				 * Bounded so a genuinely-wedged buffer can't stall
				 * the create indefinitely (falls back to the old
				 * skip — no worse than before).
				 */
				int w;
				for (w = 0; w < 25 && ierr == -EAGAIN &&
					    !xfs_is_shutdown(mp); w++) {
					msleep(2);
					dbp = NULL;
					ierr = xfs_buf_incore(mp->m_ddev_targp,
							      d, dir_blk_bb,
							      XBF_TRYLOCK, &dbp);
				}
				if (ierr == -EAGAIN) {
					all_evicted = false;
					pr_warn_ratelimited("mxfs: P36-EVICT-LOCKED ino=%llu daddr=%llu (stale base KEPT after %d-retry — clobber risk)\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d, w);
					continue;
				}
				if (w > 0)
					mxfs_probe_ratelimited("mxfs: P36-EVICT-RECOVERED ino=%llu daddr=%llu after %d retries (stale base dropped pre-RMW)\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d, w);
			}
			if (ierr != 0 || !dbp)
				continue;	/* not cached => next read fetches */

			bip = dbp->b_log_item;
			{
				bool in_ail = (bip && test_bit(XFS_LI_IN_AIL,
						     &bip->bli_item.li_flags));
				bool dirty  = (bip && test_bit(XFS_LI_DIRTY,
						     &bip->bli_item.li_flags));
				/*
				 * SAME-inode-number ABA — this buffer was
				 * stamped with a DIFFERENT (non-zero) i_generation, so
				 * its committed-unwritten (in-AIL undestaged) content
				 * belongs to a FREED PRIOR incarnation of this reused
				 * inode number, NOT to us.  This evict runs on the
				 * MODIFY (create/rename/remove) path where dp holds
				 * ILOCK_EXCL and the read-hook's invalidation is gated
				 * off (!owned_ex), so it is the ONLY place that can drop
				 * the stale base before the RMW.  Remove the
				 * in-AIL-undestaged keep-guard for an ABA buffer (the
				 * dirty/pin/delwri/!DONE guards stay — never clear
				 * XBF_DONE on a buffer with un-logged work). */
				bool incarn_aba =
					(dbp->b_mxfs_dir_incarn != 0 &&
					 dbp->b_mxfs_dir_incarn !=
						VFS_I(ip)->i_generation);
				/*
				 * sess-tcp ROOT FIX (crash_consistency dir-entry
				 * visibility lag): the OLD coarse check treated ANY
				 * in-AIL block as undurable and SKIPPED it — but a
				 * dir block whose last local mods are already
				 * write-submitted (destaged) merely LINGERS in the
				 * AIL until the log tail advances.  Skipping it left
				 * THIS node serving its own stale base, missing a
				 * peer's newer dirents (test1 stat->ENOENT on
				 * node2's just-created .md5 files after a barrier).
				 * Use the same node-local logged/written-seq
				 * discriminator the modify-path sibling and the
				 * xfs_da_read_buf hook already use:
				 * an in-AIL-but-destaged block is safe to refresh;
				 * only genuinely committed-unwritten work is kept.
				 */
				/*
				 * per-block prior-tenure test.  A block whose
				 * b_mxfs_dir_epoch LAGS the current master epoch was last
				 * coherently read in an EARLIER tenure and never refreshed
				 * this tenure (e.g. it was XBF_TRYLOCK-skipped on the
				 * new_tenure first-evict call) — it is a durable-but-stale
				 * base (Inv 1).  Catch it on ANY evict call, not just the
				 * first, closing the new_tenure TRYLOCK gap (the residual
				 * readdir=799).  Safe: valid_epoch was synced to cur_mep at
				 * tenure start so this tenure's own modified blocks carry
				 * b_epoch == cur_mep and are NEVER flagged.
				 */
				bool prior_tenure =
					(mxfs_dir_newtenure_evict && cur_mep != 0 &&
					 dbp->b_mxfs_dir_epoch != 0 &&
					 dbp->b_mxfs_dir_epoch < cur_mep);
				/*
				 * design review grant-gen prior-tenure
				 * discriminator (see mxfs_dir_grant_evict).  A
				 * block last read under an OLDER grant than the
				 * inode currently holds is a durable-but-stale
				 * prior-tenure base (grant_gen advances only via a
				 * slow-path re-grant = we released = Inv 1 drained).
				 * Reliable where epoch/dir_gen under-fire.
				 */
				bool grant_stale_base =
					(mxfs_dir_grant_evict &&
					 ip->i_dlm_cached_grant_gen != 0 &&
					 dbp->b_mxfs_grant_gen != 0 &&
					 dbp->b_mxfs_grant_gen !=
						ip->i_dlm_cached_grant_gen);
				/*
				 *  (instrumented): the cache_coherency@32
				 * "uv gone" dangling-dirent (Case B).  P-REINTRO probe
				 * (pal/linux/xfs_buf.c) PROVEN this fires with in_ail=1,
				 * dirty=0, undest=1 buffers whose bgen < dir_gen (dc_stale,
				 * the SAME predicate the write-side clobber machinery
				 * already trusts -- mxfs_dir_ex_write_guard/dataclobber,
				 * both default-relevant) -- yet NONE of the four
				 * discriminators above catch it: incarn_aba keys off
				 * INODE incarnation (different field), prior_tenure keys
				 * off b_mxfs_dir_epoch (requires epoch!=0, so a
				 * never-epoch-stamped block like the observed bgen=0
				 * dirgen=1 hit is excluded), grant_stale_base keys off
				 * b_mxfs_grant_gen (exact-inequality, different field,
				 * default ON yet still missed these exact hits).
				 * b_mxfs_dir_gen is stamped ONLY at cold READ time
				 * (xfs_da_read_buf), never at local modify
				 * (mxfs_dir_data_track stamps tenure_id/relepoch/incarn
				 * but not dir_gen) -- so a buffer cached across a stale
				 * window and RMW'd without an intervening re-read keeps
				 * carrying whatever content was present at last read,
				 * including entries a peer has since durably removed.
				 * SAFETY (learned from the relepoch regression at
				 * this exact site, dir_reuse 3/8 -- see the comment
				 * below): i_dlm_dir_gen only advances via a genuine
				 * grant TRANSITION (peer-handoff-detected at ~20571, or
				 * a grant-token change at ~20630) -- never mid-tenure
				 * under one continuous EX hold -- so it cannot false-
				 * fire against a buffer we are actively, continuously
				 * modifying.  Its one self-trigger path (our own
				 * release+reacquire) is exactly the case Architectural
				 * Invariant #1 already guarantees drained-durable before
				 * the unlock completes, so a forced re-read there just
				 * re-fetches our own already-durable content -- safe,
				 * unlike relepoch (stamped only at modify time from a
				 * counter that can advance for reasons unrelated to THIS
				 * buffer, so a stale-looking stamp did not imply stale
				 * CONTENT).  Kept as an explicit A/B lever (default 0)
				 * pending validation, matching every other discriminator
				 * in this function.
				 */
				bool dir_gen_stale =
					(mxfs_dir_gen_evict &&
					 ip->i_dlm_dir_gen != 0 &&
					 dbp->b_mxfs_dir_gen < ip->i_dlm_dir_gen);
				undurable = dirty ||
					    xfs_buf_ispinned(dbp) ||
					    (dbp->b_flags & _XBF_DELWRI_Q) ||
					    !(dbp->b_flags & XBF_DONE) ||
					    (in_ail && !incarn_aba && !new_tenure &&
					     !prior_tenure && !grant_stale_base &&
					     !dir_gen_stale &&
					     mxfs_dir_buf_is_undestaged(dbp));
				if (dir_gen_stale &&
				    (mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P-GENEVICT ino=%llu daddr=%llu bgen=%u dirgen=%llu in_ail=%d undurable=%d — force-evicting dir_gen-stale base (dc_stale predicate, uncovered by epoch/grant/incarn discriminators)\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						dbp->b_mxfs_dir_gen,
						(unsigned long long)ip->i_dlm_dir_gen,
						in_ail, undurable);
				/* a relepoch-based force-evict here
				 * (b_mxfs_relepoch < ip->i_dlm_epoch) REGRESSED dir_reuse
				 * to 3/8 — b_mxfs_relepoch is NOT reliably re-stamped after
				 * a local modify following a grant bump, so it false-flags
				 * this node's CURRENT undestaged work as stale and evicting
				 * it LOSES our dirents.  Reverted; the relepoch signal is
				 * only safe on the WRITE side (where the block is
				 * being written = destaged).  See
				 * `docs/history/ccloop-fix-relepoch-evict-gpt-design.md`. */
				if (grant_stale_base &&
				    (mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P36-GRANTEVICT ino=%llu daddr=%llu bgrant=%u cached_grant=%u in_ail=%d undestaged=%d undurable=%d — force-evict prior-grant stale base\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						dbp->b_mxfs_grant_gen,
						ip->i_dlm_cached_grant_gen,
						in_ail,
						mxfs_dir_buf_is_undestaged(dbp),
						undurable);
				/*
				 * on the FIRST modify of a new cross-node
				 * tenure (master epoch advanced since our last
				 * evict), an in-AIL block kept ONLY by the
				 * undestaged clause is durable-but-stale (Inv 1
				 * drained it before the peer's intervening EX) —
				 * force-evict it so the RMW cold-reads the peer's
				 * image.  dirty/pin/delwri/!DONE still hard-guard
				 * genuine in-flight bytes.
				 */
				if (new_tenure && in_ail && !incarn_aba &&
				    !dirty && !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q) &&
				    (dbp->b_flags & XBF_DONE) &&
				    (mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P26-NEWTENURE-EVICT ino=%llu daddr=%llu cur_mep=%u last_mep=%u undurable=%d — dropping durable-stale in-AIL base\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d, cur_mep,
						ip->i_dlm_dir_evict_mep, undurable);
				if (unlikely(incarn_aba &&
				    (mxfs_dirwr_enabled || mxfs_instr_enabled)))
					mxfs_probe("mxfs: P15-EVICT-INCARN-ABA ino=%llu daddr=%llu buf_incarn=%u cur_gen=%u undurable=%d\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						dbp->b_mxfs_dir_incarn,
						VFS_I(ip)->i_generation,
						undurable);
				/* PRIOR-TENURE override: a clean DONE block
				 * whose b_mxfs_dir_epoch (non-zero) LAGS the inode's current
				 * handoff epoch was last coherently read in a PRIOR grant
				 * tenure — we LOST EX to a peer since (double-grant RULED OUT
				 * → grants serialized → our own work on it was drained durable
				 * at our own release, Inv 1).  Its in_ail-undestaged "keep"
				 * was a FALSE POSITIVE for un-drained work; it is a STALE base
				 * a peer superseded.  Force-evict (undurable=false) so the
				 * modify re-reads the peer's durable image (count=126->77 fix).
				 * epoch!=0 required so an ambiguous never-stamped buffer is
				 * never wrongly dropped (no resurrection).  dirty/pin/delwri/
				 * !DONE stay hard-guarded (genuine CURRENT-tenure work; epoch
				 * cannot advance while we hold EX continuously). */
				{ extern int mxfs_dir_evict_prior_tenure;
				/* epoch!=0 guard DROPPED — the create-stamp
				 * (xfs_dir3_data_init/leaf_init) + modify-stamp
				 * (xfs_dir2_data_log_entry/header, xfs_dir3_leaf_log_header)
				 * make ANY block created/touched THIS tenure carry the current
				 * valid_epoch, so an epoch (incl 0) that LAGS valid_epoch is a
				 * genuine stale prior-tenure base (e.g. tenure-0 block0 served
				 * as a cache-hit).  Safe: valid_epoch advances only on a real
				 * handoff where our work was drained (Inv 1); dirty/pin/delwri/
				 * !DONE still guard in-flight current work. */
				if (mxfs_dir_evict_prior_tenure &&
				    ip->i_dlm_dir_valid_epoch != 0 &&
				    dbp->b_mxfs_dir_epoch < ip->i_dlm_dir_valid_epoch &&
				    !(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) &&
				    !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q) &&
				    (dbp->b_flags & XBF_DONE)) {
					undurable = false;
					mxfs_probe_ratelimited("mxfs: P16-PRIORTENURE-EVICT ino=%llu daddr=%llu buf_epoch=%u valid_epoch=%u — dropping stale prior-tenure base for re-read\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						dbp->b_mxfs_dir_epoch,
						ip->i_dlm_dir_valid_epoch);
				}
				/*
				 * (design review §8 split): the EVICT-side half of
				 * the prior-tenure epoch override — identical condition to
				 * the P16 block above but gated on dir_tenure_evict so it
				 * can be A/B-tested WITHOUT the read-path epoch_stale that
				 * dir_evict_prior_tenure also enables (the suspected
				 * shutdown source).  Runs under our own EX hold.
				 */
				if (mxfs_dir_tenure_evict &&
				    ip->i_dlm_dir_valid_epoch != 0 &&
				    dbp->b_mxfs_dir_epoch < ip->i_dlm_dir_valid_epoch &&
				    !(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) &&
				    !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q) &&
				    (dbp->b_flags & XBF_DONE)) {
					undurable = false;
					mxfs_probe_ratelimited("mxfs: P23-TENURE-EVICT ino=%llu daddr=%llu buf_epoch=%u valid_epoch=%u — dropping stale prior-tenure RMW base (modify-only)\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						dbp->b_mxfs_dir_epoch,
						ip->i_dlm_dir_valid_epoch);
				}
				}
			}

			/* (instrumented, minimal-repro): always-on, low-volume
			 * (multinode dir modify only) — log every data-block evict
			 * DECISION so a block KEPT stale on a modify (the suspected
			 * single-block RMW lost-update root) is visible without the
			 * heisenbug-prone instr gate.  dlm_mode + ex_grant_seq show
			 * the tenure; undurable=1 = KEPT (RMW will use this base). */
			{
				static atomic_t pevd = ATOMIC_INIT(0);
				if (atomic_inc_return(&pevd) <= 12000) {
					/* fingerprint the image this
					 * decision keeps/drops + CIL residency, so the
					 * ledger replay can see whether an evicted
					 * b_addr held committed adds no write ever
					 * carried (the in-core discard candidate). */
					uint32_t fs = 0, fx = 0, fc = 0;
					bool	 in_cil = bip &&
						!list_empty_careful(&bip->bli_item.li_cil);

					if (dbp->b_addr)
						fc = mxfs_dir3_data_fingerprint(mp,
							dbp->b_addr,
							BBTOB(dbp->b_length),
							((struct xfs_dir3_blk_hdr *)
							 dbp->b_addr)->magic ==
							cpu_to_be32(XFS_DIR3_BLOCK_MAGIC),
							&fs, &fx);
					mxfs_probe("mxfs: P68-EVDECIDE ino=%llu daddr=%llu undurable=%d staleprt=%d b_epoch=%u cur_mep=%u valid_epoch=%u in_ail=%d dirty=%d pin=%d delwri=%d done=%d in_cil=%d fcnt=%u fsum=0x%x fxor=0x%x mode=%u egseq=%llu comm=%s realns=%llu\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d, undurable,
						(undurable && cur_mep != 0 &&
						 dbp->b_mxfs_dir_epoch != 0 &&
						 dbp->b_mxfs_dir_epoch < cur_mep) ? 1 : 0,
						dbp->b_mxfs_dir_epoch, cur_mep,
						ip->i_dlm_dir_valid_epoch,
						(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) ? 1 : 0,
						(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) ? 1 : 0,
						xfs_buf_ispinned(dbp) ? 1 : 0,
						(dbp->b_flags & _XBF_DELWRI_Q) ? 1 : 0,
						(dbp->b_flags & XBF_DONE) ? 1 : 0,
						in_cil ? 1 : 0, fc, fs, fx,
						ip->i_dlm_mode,
						(unsigned long long)ip->i_mxfs_ex_grant_seq,
						current->comm,
						(unsigned long long)ktime_get_real_ns());
				}
			}

			if (!undurable) {
				/* Durable (incl. destaged-but-in-AIL): force the
				 * next read to FUA-refetch the peer's block. */
				dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
				dbp->b_mxfs_dir_gen = 0;
				if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P-EVICT-DONE ino=%llu daddr=%llu in_ail=%d\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						!!(bip && test_bit(XFS_LI_IN_AIL,
						     &bip->bli_item.li_flags)));
				/*
				 * (design review consult, PROVEN
				 * root): the soft-clear above (XBF_DONE cleared so the
				 * READ path re-fetches) leaves the buffer's BLI in the
				 * AIL.  A later xfsaild / sync-AIL push re-flushes the
				 * now-DONE=0 STALE b_addr over a peer's durable add —
				 * the dir_reuse readdir=799 loss (P-WMERGE: DONE=0
				 * in_ail=1 dirty=0 destaged held_mode=EX comm=dd).
				 * Clearing DONE alone (read-coherency) is not enough;
				 * we must also RETIRE the zombie BLI so no write path
				 * can submit the stale image.  This is NOT suppression
				 * (drops no write): the block is DESTAGED (lseq==wseq,
				 * !pinned, !delwri, !dirty) so its content is already on
				 * disk — xfs_buf_item_done (ail_delete + relse, the
				 * exact clean-checkpointed retirement xfs_buf iodone
				 * runs) loses nothing.  The buffer stays cached DONE=0
				 * so the next read FUA-refetches the peer's union.  Only
				 * when truly in-AIL + checkpointed (else ail_delete would
				 * shut down).  dbp is locked (incore TRYLOCK above). */
				/* retire a lingering DESTAGED clean in-AIL BLI
				 * (content already on disk -> safe).  NOTE: relaxing
				 * this to also retire UNDESTAGED BLIs is HARMFUL
				 * (lookup_fail=50, drops un-landed writes — design review warned).
				 * Keep the !undestaged gate.  Fires 0x in practice (the
				 * zombie is not in_ail at acquire-evict time). */
				if (mxfs_dir_zombie_retire && bip &&
				    test_bit(XFS_LI_IN_AIL,
					     &bip->bli_item.li_flags) &&
				    !test_bit(XFS_LI_DIRTY,
					      &bip->bli_item.li_flags) &&
				    !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q) &&
				    !mxfs_dir_buf_is_undestaged(dbp)) {
					dbp->b_mxfs_done_site = MXFS_SITE;
					xfs_buf_item_done(dbp, XFS_BLI_NO_IODONE);	/* frees bip */
					bip = NULL;
					if (unlikely(mxfs_dirwr_enabled ||
						     mxfs_instr_enabled))
						mxfs_probe_ratelimited("mxfs: P33-ZOMBIE-RETIRE ino=%llu daddr=%llu — retired lingering destaged BLI at acquire-evict (prevents stale reflush)\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)d);
				}
				/*
				 * NEW-TENURE BLI-RETIRE — the
				 * missing piece that made dir_newtenure_evict corrupt
				 * (readdir=0).  At the FIRST modify of a new cross-node
				 * tenure (master epoch advanced) the undestaged keep-
				 * clause was BYPASSED above (new_tenure) so this block
				 * was force-evicted (DONE cleared) — but its in-AIL BLI
				 * LINGERS and a later push reflushes the stale image
				 * over the peer's add (the dir_reuse 799/801 loss,
				 * mechanism).  RETIRE it: at new_tenure the
				 * block is DURABLE (Inv 1 drained our work at our prior
				 * release, BEFORE the peer's intervening tenure), so the
				 * "undestaged" flag is a FALSE POSITIVE and retiring
				 * loses nothing of ours.  Unlike the destaged-gated
				 * P33 retire above, this drops the !undestaged
				 * requirement — justified ONLY by the new_tenure
				 * durability guarantee.  dirty/pin/delwri still hard-
				 * guard genuine in-flight bytes (a continuous-EX block
				 * has new_tenure=false and is never matched). */
				if (((mxfs_dir_newtenure_evict &&
				     (new_tenure ||
				      (cur_mep != 0 &&
				       dbp->b_mxfs_dir_epoch != 0 &&
				       dbp->b_mxfs_dir_epoch < cur_mep))) ||
				     /* grant-stale base is durable by Inv 1
				      * (grant_gen changed => we released => drained)
				      * — retire its lingering BLI so no later push
				      * reflushes the stale image (same justification
				      * as new_tenure, more reliable signal). */
				     (mxfs_dir_grant_evict &&
				      ip->i_dlm_cached_grant_gen != 0 &&
				      dbp->b_mxfs_grant_gen != 0 &&
				      dbp->b_mxfs_grant_gen !=
					ip->i_dlm_cached_grant_gen)) &&
				    bip &&
				    test_bit(XFS_LI_IN_AIL,
					     &bip->bli_item.li_flags) &&
				    !test_bit(XFS_LI_DIRTY,
					      &bip->bli_item.li_flags) &&
				    !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q) &&
				    mxfs_dir_buf_is_undestaged(dbp)) {
					/*
					 * (D-0492): the arms above name a
					 * STALE BASE, not a durable one.  The
					 * "drained at our prior release" argument
					 * only covers content logged BEFORE that
					 * release; new_tenure is per inode (the
					 * first evict call of a tenure also sees
					 * the blocks this tenure has already
					 * logged), and the grant-gen stamp is taken
					 * at cold read and never refreshed by a
					 * modify.  Measured (0.70.9, 3 laps, 32
					 * nodes): 2204 retires of undestaged
					 * blocks, every comparable one missing at
					 * least one live entry on the platter, all
					 * logged in the current tenure.  A retired
					 * log item lets the log tail move past the
					 * transaction: the fsync-acked entries then
					 * exist only in this cache until the release
					 * drain, and a crash loses them from the
					 * journal and the platter alike.  A log item
					 * is retired only when the block is DESTAGED
					 * (written_seq == logged_seq); an undestaged
					 * one is kept in the AIL for the ordinary
					 * push or the release drain, and its in-core
					 * image stays valid — it is the only copy of
					 * committed content, so no cold read may
					 * replace it.  The epoch relation is printed
					 * because a genuinely prior-tenure undestaged
					 * block would be an invariant breach worth
					 * its own record; the measured population of
					 * those were free/leaf blocks re-logged this
					 * tenure without an epoch re-stamp.
					 */
					static atomic_t p492k_n = ATOMIC_INIT(0);

					dbp->b_flags |= XBF_DONE;
					if (atomic_inc_return(&p492k_n) <= 400)
						mxfs_probe("mxfs: P492-KEEP-UNDEST ino=%llu daddr=%llu lseq=%llu wseq=%llu new_tenure=%d cur_mep=%u b_epoch=%u valid_epoch=%u b_grant_gen=%u cached_grant_gen=%u epoch_rel=%s mode=%u ops=%s comm=%s — undestaged log item kept at a stale-base evict (retire requires destaged)\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)d,
							(unsigned long long)dbp->b_mxfs_logged_seq,
							(unsigned long long)dbp->b_mxfs_written_seq,
							new_tenure ? 1 : 0, cur_mep,
							dbp->b_mxfs_dir_epoch,
							ip->i_dlm_dir_valid_epoch,
							dbp->b_mxfs_grant_gen,
							ip->i_dlm_cached_grant_gen,
							dbp->b_mxfs_dir_epoch == cur_mep ?
								"current" : "prior",
							ip->i_dlm_mode,
							dbp->b_ops && dbp->b_ops->name ?
								dbp->b_ops->name : "?",
							current->comm);
				} else if (((mxfs_dir_newtenure_evict &&
				     (new_tenure ||
				      (cur_mep != 0 &&
				       dbp->b_mxfs_dir_epoch != 0 &&
				       dbp->b_mxfs_dir_epoch < cur_mep))) ||
				     (mxfs_dir_grant_evict &&
				      ip->i_dlm_cached_grant_gen != 0 &&
				      dbp->b_mxfs_grant_gen != 0 &&
				      dbp->b_mxfs_grant_gen !=
					ip->i_dlm_cached_grant_gen)) &&
				    bip &&
				    test_bit(XFS_LI_IN_AIL,
					     &bip->bli_item.li_flags) &&
				    !test_bit(XFS_LI_DIRTY,
					      &bip->bli_item.li_flags) &&
				    !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q)) {
					/* destaged: the content is on disk, the
					 * lingering item can only reflush a stale
					 * image — retiring it loses nothing. */
					dbp->b_mxfs_done_site = MXFS_SITE;
					xfs_buf_item_done(dbp, XFS_BLI_NO_IODONE);	/* frees bip */
					bip = NULL;
					if (unlikely(mxfs_dirwr_enabled ||
						     mxfs_instr_enabled))
						mxfs_probe_ratelimited("mxfs: P34-NEWTENURE-RETIRE ino=%llu daddr=%llu — retired durable-but-undestaged in-AIL BLI at new-tenure evict (cold re-read peer image)\n",
							(unsigned long long)ip->i_ino,
							(unsigned long long)d);
				}
			} else {
				/*
				 * ROOT FIX — EVICT-SIDE
				 * stale-base refresh (was the instr-only P37D
				 * detector).  A block KEPT undurable here is ASSUMED
				 * this-node-ahead (own un-checkpointed work), but
				 * cross-node that is WRONG when a PEER grew the dir
				 * while we held NL: keeping it then RMW-clobbers the
				 * peer's entries — the 240x bgen==dir_gen (stale=0)
				 * block-0 loss the write-side dataclobber guard cannot
				 * catch (the node modifies the stale base under EX so
				 * both tenure tokens read "current").  When this block
				 * is kept ONLY because it is in-AIL-undestaged (NOT
				 * dirty/pinned/delwri, and DONE), coherent plain-read
				 * the daddr and, if disk is a VALID same-owner dir
				 * block with STRICTLY MORE live dirents, drop XBF_DONE
				 * so the modify's read FUA-refetches the fresh base.
				 * Refreshing the base before a modify is ALWAYS correct
				 * (incl. a removal), unlike a write-side skip.  Gated
				 * mxfs_dirrefresh (default on); on KEEP (not refreshed)
				 * fall through to all_evicted=false so the consumer-
				 * refresh gen does not advance.
				 */
				extern int mxfs_dirrefresh;
				bool dr_refreshed = false;
				bool dr_dirty = bip && test_bit(XFS_LI_DIRTY,
						&bip->bli_item.li_flags);

				if (mxfs_dirrefresh && !dr_dirty &&
				    !xfs_buf_ispinned(dbp) &&
				    !(dbp->b_flags & _XBF_DELWRI_Q) &&
				    (dbp->b_flags & XBF_DONE) &&
				    (dbp->b_ops == &xfs_dir3_data_buf_ops ||
				     dbp->b_ops == &xfs_dir3_block_buf_ops) &&
				    mp->m_ddev_targp && mp->m_ddev_targp->bt_bdev) {
					extern int mxfs_pal_bdev_read_plain_bdev(
						struct block_device *, uint64_t,
						void *, uint32_t);
					uint32_t blen = BBTOB(dbp->b_length);
					void *snap = ((blen & 511) == 0 && blen) ?
						kmalloc(blen, GFP_NOFS) : NULL;
					unsigned int off0 =
						mp->m_dir_geo->data_entry_offset;
					unsigned int end = mp->m_dir_geo->blksize;

					if (snap && mxfs_pal_bdev_read_plain_bdev(
					    mp->m_ddev_targp->bt_bdev,
					    (uint64_t)d +
						mp->m_ddev_targp->bt_sector_offset,
					    snap, blen) == 0) {
						int dl = 0, il = 0;
						unsigned int o;
						struct xfs_dir3_blk_hdr *sh = snap;
						struct xfs_dir3_blk_hdr *ih = dbp->b_addr;
						uint32_t sm = be32_to_cpu(sh->magic);
						uint32_t im = be32_to_cpu(ih->magic);
						bool sok = (sm == XFS_DIR3_DATA_MAGIC ||
							    sm == XFS_DIR3_BLOCK_MAGIC);
						bool iok = (im == XFS_DIR3_DATA_MAGIC ||
							    im == XFS_DIR3_BLOCK_MAGIC);
						bool same_owner =
							(be64_to_cpu(sh->owner) ==
							 be64_to_cpu(ih->owner));

						for (o = off0; sok && o + 8 <= end; ) {
							struct xfs_dir2_data_unused *u =
								snap + o;
							if (be16_to_cpu(u->freetag) ==
							    XFS_DIR2_DATA_FREE_TAG) {
								unsigned int l =
								  be16_to_cpu(u->length);
								if (l < 8) break;
								o += l;
							} else {
								struct xfs_dir2_data_entry *e =
									snap + o;
								if (e->namelen == 0) break;
								dl++;
								o += xfs_dir2_data_entsize(
								      mp, e->namelen);
							}
						}
						for (o = off0; iok && o + 8 <= end; ) {
							struct xfs_dir2_data_unused *u =
								dbp->b_addr + o;
							if (be16_to_cpu(u->freetag) ==
							    XFS_DIR2_DATA_FREE_TAG) {
								unsigned int l =
								  be16_to_cpu(u->length);
								if (l < 8) break;
								o += l;
							} else {
								struct xfs_dir2_data_entry *e =
									dbp->b_addr + o;
								if (e->namelen == 0) break;
								il++;
								o += xfs_dir2_data_entsize(
								      mp, e->namelen);
							}
						}
						if (sok && iok && same_owner &&
						    dl > il) {
							dbp->b_flags &=
							    ~(XBF_DONE | _XBF_FUA_FRESH);
							dbp->b_mxfs_dir_gen = 0;
							dr_refreshed = true;
							mxfs_probe_ratelimited("mxfs: P-DIRREFRESH-EVICT ino=%llu daddr=%llu incore_live=%d disk_live=%d — refreshed stale RMW base before modify (peer ahead)\n",
								(unsigned long long)ip->i_ino,
								(unsigned long long)d,
								il, dl);
						}
					}
					if (snap)
						kfree(snap);
				}

				/* REVERTED: a leaf/free crc-differ refresh
				 * here is UNSAFE — crc inequality cannot tell "peer wrote
				 * newer" from "OUR committed-undestaged work is newer than the
				 * older disk image", so it reverted our own work back to disk
				 * (resurrection) and REGRESSED the mht=300 dir_reuse PASS to
				 * 0/8.  The acquire-side disk-compare is structurally racy
				 * anyway (peer's newer write often not yet on the LUN at our
				 * evict moment) — the fix belongs on the RELEASE side.  See
				 * `docs/history/docs/history/docs/history/sess16run-acquire-side-refresh-cannot-work-must-be-release-side.md`. */

				if (!dr_refreshed)
					all_evicted = false;
				/*
				 * INSTRUMENTED DETECTOR (always-on,
				 * leaf-only, rate-limited): the acquire-side refresh is
				 * about to KEEP this node's cached LEAF block because it
				 * is undurable (own un-checkpointed work).  If a peer
				 * modified the dir, keeping the stale leaf and RMW'ing it
				 * durably drops the peer's hash entries (the leaf-hash
				 * hole).  Fires only on a leaf-block skip → non-perturbing.
				 */
				if (dbp->b_ops == &xfs_dir3_leaf1_buf_ops ||
				    dbp->b_ops == &xfs_dir3_leafn_buf_ops) {
					struct xfs_dir3_leaf_hdr *lh = dbp->b_addr;
					static atomic_t p21s_n = ATOMIC_INIT(0);

					/* the leaf could not be refreshed
					 * (pinned/undestaged).  Arm the modify-path
					 * rebuild so the next dir RMW reconstructs the
					 * leaf hash index from the coherent DATA blocks
					 * instead of durably flushing this stale leaf. */
					xfs_iflags_set(ip, MXFS_IF_DIR_LEAF_STALE);
					if (atomic_inc_return(&p21s_n) <= 1200)
						mxfs_pal_log(MXFS_LOG_DEBUG,
							"mxfs: P21S-EVICTSKIP-LEAF ino=%llu daddr=%llu leaf_count=%u dirty=%d in_ail=%d pin=%d delwri=%d done=%d undest=%d dir_gen=%llu loaded_gen=%u comm=%s",
							(unsigned long long)ip->i_ino,
							(unsigned long long)d,
							be16_to_cpu(lh->count),
							!!(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)),
							!!(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)),
							xfs_buf_ispinned(dbp),
							!!(dbp->b_flags & _XBF_DELWRI_Q),
							!!(dbp->b_flags & XBF_DONE),
							mxfs_dir_buf_is_undestaged(dbp),
							(unsigned long long)ip->i_dlm_dir_gen,
							ip->i_dlm_dir_loaded_gen,
							current->comm);
				}
				if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
					mxfs_probe_ratelimited("mxfs: P-EVICT-SKIP ino=%llu daddr=%llu dirty=%d in_ail=%d pin=%d delwri=%d done=%d buf_incarn=%u cur_gen=%u buf_gen=%u lseq=%u wseq=%u undest=%d li_empty=%d\n",
						(unsigned long long)ip->i_ino,
						(unsigned long long)d,
						!!(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)),
						!!(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)),
						xfs_buf_ispinned(dbp),
						!!(dbp->b_flags & _XBF_DELWRI_Q),
						!!(dbp->b_flags & XBF_DONE),
						dbp->b_mxfs_dir_incarn,
						VFS_I(ip)->i_generation,
						dbp->b_mxfs_dir_gen,
						dbp->b_mxfs_logged_seq,
						dbp->b_mxfs_written_seq,
						mxfs_dir_buf_is_undestaged(dbp),
						list_empty(&dbp->b_li_list));
			}
			xfs_buf_relse(dbp);
		}
	}
	/*
	 * record the master epoch we just evicted against, so a second
	 * modify of the SAME tenure (epoch unchanged) does NOT re-treat its own
	 * in-flight work as a stale prior-tenure base.  Advances only when the
	 * epoch changed (a real handoff), matching new_tenure above.
	 */
	if (cur_mep != 0 && cur_mep != ip->i_dlm_dir_evict_mep)
		ip->i_dlm_dir_evict_mep = cur_mep;
	return all_evicted;
}

/*
 * RELEASE-side dir DATA/leaf buffer invalidation.  Called
 * from mxfs_dlm_bast_process AFTER the durability fence (data_durable) and the
 * inode-cluster flush, just before the on-disk DLM unlock.  Walks this dir's
 * in-core extent map and, for every cached dir block that is PROVABLY
 * clean+durable, clears XBF_DONE|_XBF_FUA_FRESH and zeroes b_mxfs_dir_gen so the
 * next access cold-reads the coherent shared LUN image instead of trusting a
 * cached buffer whose bestfree[] may predate a peer's later committed add.
 *
 * SAFETY: invalidates ONLY a buffer that is NOT dirty / NOT in the AIL / NOT
 * pinned / NOT delwri / NOT undestaged — i.e. its content is already on the
 * shared store (the release fence guaranteed this).  Clearing XBF_DONE on such
 * a buffer cannot lose data (re-read yields the same-or-newer image) and cannot
 * resurrect (we flush, never write-back here).  Any in-flight/undurable buffer
 * is left untouched — that is this node's own uncommitted work.  No-op for
 * SHORTFORM dirs (no data blocks) and single-node mounts.
 */
void
mxfs_dir_release_invalidate_data_blocks(struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_iext_cursor	icur;
	struct xfs_bmbt_irec	got;
	unsigned int		dir_blk_bb;

	if (!mxfs_dir_release_invalidate || !ip)
		return;
	/*  (design review): only a peer that requested EX can modify this
	 * dir, so only then is our cached image stale.  When no EX was requested
	 * (MHT self-demote, PR-reader BAST, noino drain, genuinely private dir)
	 * keep the cache — re-reading it from the shared LUN on the next acquire
	 * is the 32-node dlm_scaling read storm.  Held ≥PR guarantees no silent
	 * peer modify.  Gated (default off) until validated vs the coherency suite. */
	if (mxfs_dir_release_skip_nonex && !ip->i_dlm_dir_want_ex)
		return;
	if (!mp || !mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return;
	if (ip->i_df.if_format != XFS_DINODE_FMT_EXTENTS &&
	    ip->i_df.if_format != XFS_DINODE_FMT_BTREE)
		return;
	if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE &&
	    xfs_need_iread_extents(&ip->i_df))
		return;

	dir_blk_bb = XFS_FSB_TO_BB(mp, mp->m_dir_geo->fsbcount);

	for_each_xfs_iext(&ip->i_df, &icur, &got) {
		xfs_daddr_t	d_start, d_end, d;

		if (got.br_startblock == HOLESTARTBLOCK)
			continue;
		d_start = XFS_FSB_TO_DADDR(mp, got.br_startblock);
		d_end = d_start + XFS_FSB_TO_BB(mp, got.br_blockcount);

		for (d = d_start; d + dir_blk_bb <= d_end; d += dir_blk_bb) {
			struct xfs_buf		*dbp = NULL;
			struct xfs_buf_log_item	*bip;

			if (xfs_buf_incore(mp->m_ddev_targp, d, dir_blk_bb,
					   XBF_TRYLOCK, &dbp) != 0 || !dbp)
				continue;	/* uncached/locked => re-read or in-flight */
			bip = dbp->b_log_item;
			/*
			 * Invalidate ONLY a provably clean+durable buffer.  Any
			 * dirty / in-AIL / pinned / delwri / undestaged buffer is
			 * this node's own not-yet-landed work and MUST be kept
			 * (the fence above should already have landed it; if it
			 * somehow has not, keeping it is the safe choice).
			 */
			if ((bip && (test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags) ||
				     test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))) ||
			    xfs_buf_ispinned(dbp) ||
			    (dbp->b_flags & _XBF_DELWRI_Q) ||
			    !(dbp->b_flags & XBF_DONE) ||
			    mxfs_dir_buf_is_undestaged(dbp)) {
				xfs_buf_relse(dbp);
				continue;
			}
			dbp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			dbp->b_mxfs_dir_gen = 0;
			mxfs_probe_ratelimited(
			    "mxfs: P-RELINVAL ino=%llu daddr=%lld — invalidated clean+durable dir block at EX release (no buffer survives handoff)\n",
			    (unsigned long long)ip->i_ino, (long long)d);
			xfs_buf_relse(dbp);
		}
	}
}

/*
 * CONSUMER-side eager dir-block refresh (the reader half of the
 * publish-before-notify coherency fix).
 *
 * PROVEN (instrumented): the writer side now publishes its dir blocks
 * durably to the shared LUN before bumping peers' i_dlm_dir_gen, but a PEER
 * READER still served a STALE in-core dir block.  Measured root: the lazy
 * per-buffer read-time hook (xfs_da_read_buf) stamps b_mxfs_dir_gen =
 * i_dlm_dir_gen BEFORE the reread, so a block reread while a DIFFERENT
 * concurrent writer's modify bumped the shared per-dir gen — at an instant
 * that writer's change to THIS block was not yet visible to this read — gets
 * stamped current with stale content and is then NEVER re-read (gen matches),
 * caching stale-as-fresh.  A full remount (fresh device reads) clears it,
 * proving the shared medium is coherent and the bug is purely the peer's
 * in-core xfs_buf cache.
 *
 * Fix: at the TOP of every cross-node dir READ (readdir/lookup), when a peer
 * has modified this dir since our last refresh (i_dlm_dir_gen advanced past
 * i_dlm_dir_evicted_gen), EAGERLY drop ALL clean cached dir DATA blocks (the
 * same release-path primitive), so the read that follows refetches the peer's
 * durable committed image from the coherent shared target.  This replaces the
 * restamp-prone lazy hook with an up-front whole-dir invalidation keyed on the
 * dir-level gen — no per-buffer stamp race.  Undurable (this node's own
 * un-checkpointed) blocks are SKIPPED by mxfs_dir_evict_data_blocks, so a node
 * that is itself mid-modify never loses its own work.  Plain reads (no FUA)
 * are correct: the writer's bio already completed to the shared cache.
 *
 * Cheap: no-op single-node, no-op when the dir is unchanged (gen matches), and
 * only walks the (few) dir blocks when a peer actually modified the dir.
 * Caller need not hold ILOCK; we take ILOCK_SHARED (nested-shared-safe — see
 * xfs_file_readdir) for extent-list stability across the evict walk.
 */
static int
mxfs_dlm_dir_consumer_refresh_impl(struct xfs_inode *dp, int fallible)
{
	struct xfs_mount	*mp;
	bool			new_incarn;

	if (!dp)
		return 0;
	mp = dp->i_mount;
	if (!mp || !mp->m_mxfs_dlm)
		return 0;
	/*
	 * 0.72.2 (D-SURVIVOR-SINGLE-NODE-BYPASS-SERVES-STALE-VIEW-AFTER-PEER-
	 * DEATH-0904): the single-node no-op stands for a mount that never had
	 * a peer.  The SOLE SURVIVOR of a peer's death runs this refresh like
	 * a cohort member: the flag/gen signals below were armed by the dead
	 * peer's directory modifications, no BAST will arrive to service them
	 * on the acquire path, and skipping them here left xfs_dir_lookup on
	 * a pre-death inline root fork (ENOENT for a fsync'd mkdir).  Cheap
	 * when nothing is pending: the gates below do no I/O for a directory
	 * whose gen matches.
	 */
	if (mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    !mxfs_v5_dlm_sole_survivor(mp->m_mxfs_dlm))
		return 0;
	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return 0;

	/*
	 * consume MXFS_IF_DIR_RELOAD on the LOOKUP
	 * path too (xfs_readdir already does this before getdents).  A peer's
	 * DIR_MODIFY evict-ring event arms this flag whenever it modifies the
	 * dir; a full mxfs_dlm_reload_inode rebuilds the data-fork EXTENT MAP
	 * (xfs_idestroy_fork + xfs_inode_from_disk) so a subsequent
	 * xfs_dir_lookup maps dir offsets through the peer's current extent
	 * map instead of a stale one that points at a freed/reused block
	 * (the XFS_DABUF_MAP_HOLE_OK / xfs_dir3_block_verify shutdown).  The
	 * lighter i_dlm_dir_gen data-block evict below cannot fix a stale
	 * extent map — it only re-reads daddrs the map already names.  Must
	 * run with no ILOCK held (reload takes i_lock via down_write_trylock);
	 * xfs_lookup calls us before taking any ILOCK.  Event-driven: no peer
	 * modify => flag clear => no disk traffic.
	 *
	 * ALSO reload on the reliable gen-staleness
	 * signal (i_dlm_dir_gen > i_dlm_dir_loaded_gen), not just the evict-ring
	 * flag.  PROVEN read-side root: the async evict-ring DIR_MODIFY event is
	 * laggy/lost in production timing, so MXFS_IF_DIR_RELOAD stays clear even
	 * though the acquire already bumped dir_gen past loaded_gen — the reader
	 * then keeps a stale BLOCK-format inode after a peer's block->shortform
	 * delete-shrink and cold-reads the freed data block (uv "got=N"; PROVEN by
	 * drop_caches fixing it = the LUN is correct, the in-core inode is stale).
	 * Gated so an uncontended dir (gen==loaded) does ZERO disk traffic, and
	 * mxfs_dlm_reload_inode advances loaded_gen on success so this fires once
	 * per peer change, not per lookup (no /91 per-readdir-poll regress).
	 */
	if (xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_RELOAD) ||
	    dp->i_dlm_dir_gen > dp->i_dlm_dir_loaded_gen) {
		dp->i_dlm_stale = true; dp->i_dlm_stale_src = 2;
		/* reader consuming a peer's DIR_MODIFY: get the peer's full
		 * image (no ILOCK held, no own in-flight dir mods) — post_release. */
		mxfs_dlm_reload_inode(dp, XFS_DIR3_FT_UNKNOWN, true);
		if (dp->i_dlm_stale)
			xfs_iflags_set(dp, MXFS_IF_DIR_RELOAD);
	}

	/*
	 * (design review design-consult ABA fix): mirror the modify-path fix — a
	 * freshly-instantiated/reused dir (i_dlm_dir_gen==0) may still have a
	 * peer's PREVIOUS-incarnation dir blocks cached at the same reused
	 * daddrs (cache is daddr-indexed).  i_dlm_dir_gen counts within one
	 * incarnation and can collide across reuse, so also force a one-shot
	 * whole-dir evict whenever the on-disk inode generation differs from
	 * the one we last evicted for, so the next readdir/lookup cold-reads
	 * the peer's durable image.
	 */
	new_incarn = (dp->i_dlm_dir_evicted_incarn != VFS_I(dp)->i_generation);
	/*
	 * mirror the modify-path mxfs_dir_force_evict
	 * bypass on the READER path.  PROVEN ROOT (P26-IGET-FAIL): a cold-read
	 * lookup on the shared reused dir returns a dirent pointing at a FREED
	 * PRIOR-incarnation inode (iget -ENOENT) — the in-core dir DATA block is
	 * stale (a previous round's dirents at the reused daddr).  The gen-gate
	 * below SKIPS the evict because THIS NODE's own create wave already set
	 * evicted_gen/evicted_incarn this round, so the reader never drops the
	 * stale block and reads a prior incarnation's inode numbers.  The local
	 * gen is not a cross-node "peer modified" signal, so with
	 * force_evict ON, drop clean cached dir blocks on every reader refresh
	 * too — the next xfs_dir_lookup/getdents FUA-refetches the peer's durable
	 * current image.  SAFE: the evict skips undurable (dirty/pinned/in-AIL)
	 * blocks, so this node never loses its own un-checkpointed work.
	 */
	if (!mxfs_dir_force_evict &&
	    !new_incarn && dp->i_dlm_dir_gen == dp->i_dlm_dir_evicted_gen)
		return 0;				/* fresh AND same incarnation */

	{
		/* leak-A fix (design review review): this direct
		 * ILOCK_SHARED runs INSIDE xfs_lookup's create-intent arm
		 * bracket but never consulted the registry, so every armed
		 * lookup opened with a wire-PR tenure that poisoned the
		 * create's EX into the EDEADLK/drop/drain cycle (with
		 * dir_force_evict=1 this fires on EVERY lookup).  Tag when
		 * armed; ONE mode variable feeds both lock and unlock so
		 * begin/end DLM holder counts always mirror. */
		uint refresh_mode = XFS_ILOCK_SHARED;

		if (mxfs_createint_dir_armed(dp)) {
			refresh_mode |= XFS_ILOCK_MXFS_CREATEINT;
			if (unlikely(mxfs_instr_enabled))
				mxfs_probe_ratelimited("mxfs: P-CI-A refresh-under-arm ino=%llu cached_dlm_mode=%u\n",
					(unsigned long long)dp->i_ino,
					dp->i_dlm_mode);
		}
		/*
		 * 0.84.4: on the readdir path this acquire may be refused.
		 * Nothing above changed what makes this refresh due: the
		 * reload consumed its own flag and re-arms it on a bail, and
		 * the eviction gate is dir_gen against evicted_gen, which only
		 * the eviction below advances — so a refused acquire leaves
		 * the eviction pending for the next read exactly as it stood.
		 */
		if (fallible) {
			int ret = mxfs_ilock_fallible(dp, refresh_mode);

			if (ret)
				return fallible == 2 ?
					mxfs_lookup_refused(dp, "refresh", ret) :
					mxfs_readdir_refused(dp, "refresh", ret);
		} else {
			xfs_ilock(dp, refresh_mode);
		}
		/* Only mark this gen "refreshed" if EVERY cached dir block was
		 * durable and evicted.  If any block was undurable (pinned/
		 * in-AIL) it was left stale and skipped — leave
		 * i_dlm_dir_evicted_gen behind so the next read retries it once
		 * durable (else it survives until the gen next advances = the
		 * residual unlink/create-visibility survivor). */
		if (mxfs_dir_evict_data_blocks(dp)) {
			dp->i_dlm_dir_evicted_gen = dp->i_dlm_dir_gen;
			dp->i_dlm_dir_evicted_incarn = VFS_I(dp)->i_generation;
		}
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited("mxfs: P104-CONSUMER-REFRESH ino=%llu gen=%u evicted_gen=%u incarn=%u new_incarn=%d\n",
				(unsigned long long)dp->i_ino, dp->i_dlm_dir_gen,
				dp->i_dlm_dir_evicted_gen,
				VFS_I(dp)->i_generation, new_incarn);
		xfs_iunlock(dp, refresh_mode);
	}
	return 0;
}

/* The blocking form, for a caller that has not been audited for a refused
 * acquire: its refresh waits as it always did. */
void
mxfs_dlm_dir_consumer_refresh(struct xfs_inode *dp)
{
	mxfs_dlm_dir_consumer_refresh_impl(dp, 0);
}
EXPORT_SYMBOL(mxfs_dlm_dir_consumer_refresh);

/* The readdir path's form: the acquire may be refused and the listing fails. */
int
mxfs_dlm_dir_consumer_refresh_fallible(struct xfs_inode *dp)
{
	return mxfs_dlm_dir_consumer_refresh_impl(dp, 1);
}
EXPORT_SYMBOL(mxfs_dlm_dir_consumer_refresh_fallible);

/* 0.84.13: the lookup path's form — the acquire may be refused and the
 * lookup fails, named as the lookup's own refusal. */
int
mxfs_dlm_dir_consumer_refresh_lookup(struct xfs_inode *dp)
{
	return mxfs_dlm_dir_consumer_refresh_impl(dp, 2);
}
EXPORT_SYMBOL(mxfs_dlm_dir_consumer_refresh_lookup);
int mxfs_dir_iflush_fence;	/* when 1, skip an iflush that would publish a dir block0 HIGHER than disk's canonical (lowest-block0-wins) — prevents the inode extent[0] divergence that loses node1_f1. */
module_param_named(dir_iflush_fence, mxfs_dir_iflush_fence, int, 0644);
/* (design-consult design): the read-path under-buffer-lock coherency
 * backstop.  The pre-read gen-invalidation in xfs_da_read_buf uses XBF_TRYLOCK
 * and SKIPS when the cached dir buffer is transiently locked (P34-TRYLOCK-STALE,
 * PROVEN firing under 4-node contention) — serving a STALE XBF_DONE dir DATA/leaf
 * block to a create/remove RMW, which then drains a stale-base block to the LUN
 * and durably clobbers a peer's dirent (dir_reuse_coherency 4/tcp: node4_f37 /
 * node4_f19.md5 lost on ALL nodes incl. creator).  This backstop runs AFTER
 * xfs_trans_read_buf_map has returned the buffer LOCKED (so it is deadlock-free —
 * we already own the lock, no trylock, no separate lock-acquire ordering vs a
 * peer drain): if a multinode dir DATA/leaf buffer is a CACHE HIT (XBF_DONE) whose
 * b_mxfs_dir_gen is older than the inode's i_dlm_dir_gen (reliably bumped on every
 * slow-path post-handoff re-acquire) AND it is CLEAN (no dirty/pinned/in-AIL/delwri/
 * undestaged local work — those are our own committed-unwritten dirents and must be
 * kept), then the pre-read inval was skipped: clear XBF_DONE+_XBF_FUA_FRESH and
 * FUA-re-read the peer's durable image before any RMW.  Fresh reads are stamped
 * (dir_stamp_fresh) == i_dlm_dir_gen so they never re-read here (no loop, no
 * cold-miss double-read).  Default ON. */
int mxfs_dir_postread_reread;	/* reverted to 0 (refuted: P67 never fired on clobber; loss is not gen-stale read). */
module_param_named(dir_postread_reread, mxfs_dir_postread_reread, int, 0644);
int mxfs_dir_postread_leaf_only = 1;	/* default 1: when dir_postread_reread is on, restrict the forced FUA re-read to LEAF/NODE mapping blocks (the proven DABUF_MAP_HOLE source = stale leaf referencing freed data blocks).  A DATA block re-read FUA-reads the PLATTER which lags the target writeback cache -> torn read -> Metadata CRC error shutdown.  Leaf-only fixes the hole without tearing a data block. */
module_param_named(dir_postread_leaf_only, mxfs_dir_postread_leaf_only, int, 0644);
/*
 * (D-0517): when 1, every inode-cluster WRITE FUA-reads the platter
 * copy and logs P-DINO-CLOBBER if any slot's in-core changecount is below
 * the platter's (pal/linux/xfs_buf.c).  LAB reproduction knob; one
 * synchronous FUA read per cluster write.  mxfs_dino_clobber_n counts
 * every regression seen (the fleet sweep reads it through the log).
 */
int mxfs_dino_clobber_check;
module_param_named(dino_clobber_check, mxfs_dino_clobber_check, int, 0644);
MODULE_PARM_DESC(dino_clobber_check, "FUA-verify every inode-cluster write against the platter and log P-DINO-CLOBBER on a changecount regression (LAB)");
atomic_t mxfs_dino_clobber_n = ATOMIC_INIT(0);
MODULE_PARM_DESC(dir_postread_reread,
	"read-path under-buffer-lock dir-block coherency backstop: 1=on (default), "
	"0=off. Re-reads a stale clean cached dir DATA/leaf block the pre-read "
	"XBF_TRYLOCK invalidation skipped under contention (P34-TRYLOCK-STALE), "
	"preventing the durable dirent lost-update (dir_reuse_coherency 4/8-node).");
/* (instrumented, PROVEN via P-DIRIFLUSH dlm_mode=0/NL flushes of the shared
 * dir inode): a node that has RELEASED the dir's DLM EX must NOT publish the dir
 * inode's data fork.  The durable dirent loss in dir_reuse_coherency 4/tcp
 * (node3_f40 / node4_f37, P67-POSTREAD-REREAD never fired => NOT a data-block
 * content stale-RMW) is the dir-INODE EXTENT-MAP flip-flop proved: a
 * non-owner's stray xfsaild flush writes its STALE in-core extent map over the
 * current EX owner's authoritative map, orphaning a logical block's daddr so the
 * dirents in it become unreachable cluster-wide.  Enforce "only the EX owner (or
 * the release-drain RELFLUSH) publishes the dir inode" — skip any other dir-inode
 * flush cleanly (mark stale, no I/O), so a later EX (re)acquire reloads+adopts
 * the canonical image.  Default ON. */
int mxfs_dir_iflush_owner_fence;	/* reverted to 0 (inert: NL dir-inode flushes are all legit RELFLUSH; extent map converged). */
module_param_named(dir_iflush_owner_fence, mxfs_dir_iflush_owner_fence, int, 0644);
MODULE_PARM_DESC(dir_iflush_owner_fence,
	"only the DLM-EX owner (or release-drain RELFLUSH) may flush a multinode "
	"dir inode: 1=on (default), 0=off. Blocks a released node's stale xfsaild "
	"flush from clobbering the owner's dir extent map (the dir_reuse_coherency "
	"4/8-node extent-map flip-flop durable dirent loss).");

/* P32F-NXSHRINK-FENCE: the dir_reuse_coherency mht=50 SHUTDOWN
 * root (PROVEN, instrumented, P32-IFLUSH-NXSHRINK fired dlm_mode=5/EX comm=rm).  At
 * rapid EX handoffs a node serves EX on the FAST PATH (no slow-path reload), so
 * its in-core dir data-fork extent map stays STALE (smaller than the
 * peer-grown on-disk map); a subsequent rm then iflushes that smaller map over
 * the larger durable one for the SAME incarnation -> extent-map REVERT ->
 * leaf-vs-data tear -> EFSCORRUPTED shutdown.  Discriminate stale-revert from a
 * LEGIT shrink with the RELIABLE level-triggered handoff epoch: if the master's
 * current dir_epoch EXCEEDS i_dlm_dir_valid_epoch, our base predates a peer
 * modify we never adopted -> the shrink is a stale revert.  Fence it (skip the
 * flush, mark stale; the next acquire reloads+adopts the disk superset).  A
 * legit shrink we performed ourselves has valid_epoch == current (we adopted at
 * the acquire that preceded our rm) so it is NOT fenced.  Default ON. */
int mxfs_dir_nxshrink_fence;	/* DEFAULT 0 — discriminator (epoch>valid) proven WRONG (never fired on the real P32 events); keep gated off, do not let an unproven iflush fence skip a legit shrink. */
module_param_named(dir_nxshrink_fence, mxfs_dir_nxshrink_fence, int, 0644);

/* D3 arm 3 — dir EPOCH flush fence (P32E in
 * xfs_iflush).  Unlike the arm above (whose target events ran UNDER
 * EX where cur==valid and the predicate could not fire), this fences the
 * PROVEN post-release zombie flush: xfsaild pushing a retained dir item at
 * NL after a peer's EX tenure superseded the disk image (fdw ghost n5_8:
 * test8/test24 mode=0 writes resurrected a removed SF dirent 166ms after the
 * owner's removal landed).  In that class the peer's acquire HAS advanced
 * the master dir_epoch past our valid_epoch, so the predicate is exact.
 * Default ON. */
int mxfs_dir_epoch_flush_fence = 1;
module_param_named(dir_epoch_flush_fence, mxfs_dir_epoch_flush_fence, int, 0644);
MODULE_PARM_DESC(dir_epoch_flush_fence,
                 "Skip flushing a same-incarnation dir inode whose master "
                 "dir_epoch exceeds our valid_epoch (peer superseded; the "
                 "flush could only revert). 1=on (default), 0=off");

int mxfs_dir_nl_logged_skip = 1;
module_param_named(dir_nl_logged_skip, mxfs_dir_nl_logged_skip, int, 0644);
MODULE_PARM_DESC(dir_nl_logged_skip,
                 "Skip writing a logged DIR inode slot whose in-core grant "
                 "is NL (prior-tenure image would revert peers): 1=on "
                 "(default), 0=legacy always-write-logged");

/*
 * (D-TMPFILE-CHURN-the budget rule-PERF-400, design-consult ruling priority 2): the
 * per-ifree AGI FUA re-read in xfs_inactive_ifree (mxfs_ag_buf_disk_differs,
 * 0.22 ms measured, ~40% of ifree) — containment for the stale prior-tenure
 * in-core AGI class that D-399 fixed at root.  1 = legacy every-ifree read and
 * decide-on-disk when clean-but-divergent (0.23.14 default until the shadow
 * arm proves clean); 2 = SHADOW: sample 1/64, log P-IFR-AGI-STALE-SHADOW and
 * count a clean divergence but keep the in-core decision; 0 = off.
 */
int mxfs_ifr_agi_disk_check = 1;
module_param_named(ifr_agi_disk_check, mxfs_ifr_agi_disk_check, int, 0644);
MODULE_PARM_DESC(ifr_agi_disk_check,
                 "Per-ifree AGI platter re-read: 1=legacy every ifree "
                 "(default), 2=sampled shadow 1/64 (log+count, in-core "
                 "decision), 0=off");
unsigned long mxfs_ifr_agi_shadow_mismatch_n;
module_param_named(ifr_agi_shadow_mismatch_n, mxfs_ifr_agi_shadow_mismatch_n, ulong, 0444);
MODULE_PARM_DESC(ifr_agi_shadow_mismatch_n,
                 "Shadow counter: sampled ifree AGI reads that found a "
                 "clean-but-divergent platter image (must stay 0)");

/* acquire-side PRIOR-TENURE evict override (mxfs_dir_evict_data_blocks).
 * When 1, a clean DONE dir block whose b_mxfs_dir_epoch (non-zero) lags the inode's
 * current i_dlm_dir_valid_epoch is force-evicted (re-read) even if the payload-LSN
 * "undestaged" heuristic would keep it — because epoch-lag proves a peer modified
 * since our base loaded and (grants serialized, double-grant ruled out) our own work
 * was drained at our release.  Targets the count=126->77 cross-tenure dir lost-update.
 * Default 0 (under test). */
int mxfs_dir_evict_prior_tenure;
module_param_named(dir_evict_prior_tenure, mxfs_dir_evict_prior_tenure, int, 0644);
MODULE_PARM_DESC(dir_nxshrink_fence,
	"skip an iflush about to write a SMALLER dir data-fork extent map over a "
	"larger on-disk one of the same incarnation when our base epoch lags the "
	"master handoff epoch (stale fast-path-serve extent-map revert): 1=on "
	"(default), 0=off.");

/*
 * EVICT-SIDE stale-base refresh — the ROOT fix for
 * the 240× bgen==dir_gen (stale=0) dir DATA-block clobber that the write-side
 * dataclobber guard cannot catch (the node RMWs a stale base while holding EX,
 * so both tenure tokens read "current").  In mxfs_dir_evict_data_blocks the
 * modify-path evict KEEPS a block flagged undurable; when it is kept ONLY
 * because it is in-AIL-undestaged (not truly dirty/pinned/delwri) and the
 * coherent on-disk copy has STRICTLY MORE live dirents (P37D-proven peer
 * growth), this forces a refetch (clear XBF_DONE) so the RMW rebuilds on the
 * fresh base.  Refreshing the base before a modify is always correct (incl. a
 * removal), unlike a write-side skip.  0=off, 1=on (default).
 */
int mxfs_dirrefresh;	/* default 0: content-compare variant fired 0x (wrong target — data blocks durable at evict, only leaf kept) */
module_param_named(dirrefresh, mxfs_dirrefresh, int, 0644);
MODULE_PARM_DESC(dirrefresh,
                 "Evict-side stale dir DATA-base refresh before RMW: "
                 "0=off (default), 1=on");
