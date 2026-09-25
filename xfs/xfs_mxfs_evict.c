// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- inode eviction, deferred reaping and the LRU sweep
 */
#define MXFS_TU_ID 23	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
/*
 * FIX-3 — the loss FINALIZER tripwire (design review design-consult ruling: GFS2/
 * OCFS2 are strictly flush-before-demote; a dirty fork at NL must be
 * unrepresentable, and tearing one down is the moment acknowledged data
 * becomes unrecoverable — the in-core copy is the ONLY copy).  With FIX-1/
 * FIX-2 this is structurally unreachable; if it fires anyway, a loud
 * shutdown is honest where silent loss is not, and the print carries the
 * full state for the next troubleshooting loop.
 */
int mxfs_evict_obligation_shutdown = 1;
module_param_named(evict_obligation_shutdown, mxfs_evict_obligation_shutdown, int, 0644);
MODULE_PARM_DESC(evict_obligation_shutdown,
		 "If an inode reaches eviction with its publication ledger "
		 "open (pending != durable, committed change not at home), "
		 "attempt a last-chance publish, then shut down rather than "
		 "silently losing acknowledged data (1=on, 0=log only)");

/* ─── Eviction ─── */

/*
 * Release cached DLM lock when inode is being reclaimed.
 * Called from xfs_reclaim_inode before i_ino is zeroed.
 */
void
mxfs_dlm_evict(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;

	/*
	 *  (instrumented instrument — hunting a PROVEN but
	 * un-root-caused VFS_BUG_ON_INODE(I_FREEING|I_CLEAR) crash inside
	 * iput(), hit twice live: once via mxfs_dlm_bast_dwork_fn's own
	 * xfs_irele (mitigated, see mxfs_dlm_dwork_safe_irele a few hundred
	 * lines above), once via a plain `rm` -> do_unlinkat -> iput on an
	 * UNRELATED call site this session did not touch — proving the real
	 * bug is an upstream reference-count imbalance somewhere in the DLM/
	 * BAST machinery, not any one xfs_irele call site).  VFS only reaches
	 * evict() once i_count has genuinely hit 0 — if mxfs's OWN bookkeeping
	 * still shows a live demoter, active holders, a pin, or a pending BAST
	 * at that exact moment, one of THOSE mechanisms believes it still owns
	 * a reference that VFS disagrees is outstanding: the accounting is
	 * already wrong by the time we get here, on THIS inode, regardless of
	 * which caller's iput() happens to trip the assertion.  Always-on
	 * (eviction is once-per-inode-lifetime, not a hot path); capped.
	 */
	{
		static atomic_t p125_n = ATOMIC_INIT(0);
		bool suspect = ip->i_dlm_demoter != NULL ||
			       ip->i_dlm_ex_holders != 0 ||
			       ip->i_dlm_pr_holders != 0 ||
			       ip->i_dlm_pin_count != 0 ||
			       ip->i_dlm_bast_pending;

		if (suspect && atomic_inc_return(&p125_n) <= 5000)
			mxfs_probe("mxfs: P125-EVICT-SUSPECT ino=%llu mode=%u state=%u ex=%u pr=%u pin=%u demoter=%d bast_pending=%d stale=%d i_count=%d i_state=0x%lx comm=%s exh_pid=%d exh_comm=%s exh_age_ms=%lld — evict() entered with mxfs bookkeeping still non-quiescent\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode, ip->i_dlm_state,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count,
				ip->i_dlm_demoter != NULL,
				ip->i_dlm_bast_pending, ip->i_dlm_stale,
				atomic_read(&VFS_I(ip)->i_count),
				mxfs_istate(VFS_I(ip)), current->comm,
				ip->i_dlm_exh_pid, ip->i_dlm_exh_comm,
				ip->i_dlm_exh_since_ns ?
				(s64)((ktime_get_real_ns() -
				       ip->i_dlm_exh_since_ns) / 1000000) : -1);
		if (suspect && mxfs_watch_ino && ip->i_ino == mxfs_watch_ino)
			mxfs_dlmtr_dump();
	}

	if (!mp->m_mxfs_dlm)
		return;

	/*
	 * FIX-3 tripwire (see the knob decl for the design).  An open
	 * publication ledger here means a committed — possibly O_SYNC-
	 * acknowledged — change exists ONLY in the fork this evict is about
	 * to destroy: the platter is stale and every later reload adopts the
	 * stale platter (the PROVEN 20260731 loss finalizer, P-RELOAD-
	 * IDENTICAL cc=4 over an in-core cc=6).  If we still hold EX the
	 * publish is fully authorized — land it now.  Otherwise this node's
	 * distributed state machine has already failed (a release escaped
	 * the FIX-2 gate): say so and, by default, shut down instead of
	 * silently losing acknowledged data.  Exemptions mirror the gate:
	 * ISTALE/dead-incarnation/dlm_stale forks carry nothing of ours to
	 * land; a shutdown FS has no obligation.
	 */
	if (!mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    READ_ONCE(ip->i_mxfs_pub_pending_seq) !=
		READ_ONCE(ip->i_mxfs_pub_durable_seq) &&
	    !xfs_iflags_test(ip, XFS_ISTALE) &&
	    !ip->i_mxfs_dead_incarn_gen &&
	    !ip->i_dlm_stale &&
	    !xfs_is_shutdown(mp)) {
		bool p237_landed = false;

		/* (design-consult ruling, home-free settle): a shell already
		 * marked ISTALE_CAW is a stale incarnation — the last-chance
		 * publish must never write it over a peer's or a newer local
		 * incarnation.  Its ledger is settled by equivalence at the
		 * home-free site or the tripwire stays fail-closed. */
		if (ip->i_dlm_mode == MXFS_LOCK_EX &&
		    !xfs_iflags_test(ip, XFS_ISTALE_CAW)) {
			(void)mxfs_inode_cluster_durable(ip);
			p237_landed =
				READ_ONCE(ip->i_mxfs_pub_pending_seq) ==
				READ_ONCE(ip->i_mxfs_pub_durable_seq);
		}
		if (!p237_landed) {
			static atomic_t p237_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p237_n) <= 400)
				pr_err("mxfs: P237-EVICT-OBLIGATION ino=%llu mode=%u state=%u pend=%llu dur=%llu flush=%llu ili_f=0x%x pin=%d in_ail=%d nlink=%u imode=0%o comm=%s — evicting a fork whose committed change never reached home; acknowledged data would be lost cluster-wide%s\n",
					(unsigned long long)ip->i_ino,
					ip->i_dlm_mode, ip->i_dlm_state,
					(unsigned long long)ip->i_mxfs_pub_pending_seq,
					(unsigned long long)ip->i_mxfs_pub_durable_seq,
					(unsigned long long)ip->i_mxfs_pub_flush_seq,
					ip->i_itemp ? ip->i_itemp->ili_fields : 0,
					atomic_read(&ip->i_pincount),
					(ip->i_itemp && test_bit(XFS_LI_IN_AIL,
					    &ip->i_itemp->ili_item.li_flags)) ? 1 : 0,
					VFS_I(ip)->i_nlink, VFS_I(ip)->i_mode,
					current->comm,
					mxfs_evict_obligation_shutdown ?
						"; shutting down" : "");
			if (mxfs_evict_obligation_shutdown)
				xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		} else {
			mxfs_probe("mxfs: P237-EVICT-LANDED ino=%llu — open obligation landed by the evict-side last-chance publish (EX still held)\n",
				(unsigned long long)ip->i_ino);
		}
	}

	/*
	 * deferred-publish: an unpublished inode holds i_dlm_mode=EX
	 * locally but has NO on-disk slot.  Drop it from the unpublished list
	 * and skip the disk release entirely (releasing a slot we never
	 * acquired would corrupt the CAW table).  reclaim only reaches here on
	 * a CLEAN inode, so its data is already durable on disk — a peer that
	 * later reaches this inode number reads the durable disk copy with no
	 * held grant to coordinate.  If publish_unpublished raced us and won
	 * the claim (flag already clear), it acquired a real slot and we fall
	 * through to the normal release below.
	 */
	if (mxfs_dlm_unpublish_drop(ip)) {
		/*
		 * D-INODE-WIRE-EX-ORPHAN-ON-EVICT: the "unpublished ⇒
		 * no on-disk slot" premise above is violated in practice —
		 * dlmtr-traced single-file repro: every created file's type-1
		 * slot EXISTS (gen=1 EX) while the inode still rides the
		 * unpublished list, so this skip orphaned one wire-EX slot
		 * per created-then-evicted file (13.4K accumulated from one
		 * board).  Trust the WIRE, not the flag — same discipline as
		 * the 326 retention fix: one hint-read; if the wire holds
		 * anything for us, fall through to the normal release below
		 * instead of returning.  A truly slotless unpublished inode
		 * still takes the cheap skip.
		 */
		if (mp->m_mxfs_dlm &&
		    mxfs_v5_dlm_inode_granted_mode(mp->m_mxfs_dlm,
						   ip->i_ino) !=
			MXFS_LOCK_NL) {
			mxfs_probe_ratelimited("mxfs: P-UNPUB-WIRE-DESYNC ino=%llu mode=%u — unpublished bookkeeping but a live wire grant exists; running the real release\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode);
		} else {
			/* a deliberate give-up of the local-only
			 * (UNPUBLISHED_EX) tenure — announce it so the NL
			 * store below classifies as clean release, not a
			 * late revoke. */
			spin_lock(&ip->i_dlm_lock);
			mxfs_inode_authority_begin_release_locked(ip, MXFS_SITE);
			spin_unlock(&ip->i_dlm_lock);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_mode = MXFS_LOCK_NL;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
			{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
			ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
			mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
			ip->i_dlm_ex_holders = 0; MXFS_DLMTR_H(ip);
			ip->i_dlm_pr_holders = 0; MXFS_DLMTR_H(ip);
			return;
		}
	}

	if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE &&
	    ip->i_dlm_mode == MXFS_LOCK_NL)
		return;

	/*
	 * Cancel any pending BAST work.
	 *
	 * (D-UNMOUNT-BUSY-INODES candidate): BOTH arms are armed with an
	 * igrab (mxfs_dlm_queue_pr_demote / queue_ex_demote), and the ONLY
	 * places that reference is dropped are inside the work functions —
	 * mxfs_dlm_bast_work_fn's xfs_irele and mxfs_dlm_dwork_safe_irele.  A
	 * cancel_*_sync that returns TRUE means the work was QUEUED AND NEVER
	 * RAN, so that reference is dropped by nobody: a leak of exactly one
	 * per cancelled arm.  (Returning FALSE means it was not pending, or it
	 * was already running and we waited for it — in which case the work
	 * function did its own drop and we must NOT double-release.)
	 *
	 * The pre-existing comment argued this cannot happen, "the dwork holds
	 * an iget ref that keeps the inode out of reclaim, so it has already
	 * run by the time we reach evict".  That is reasoning, not
	 * measurement, and it is exactly the shape the zero-defect bar warns about — so
	 * probe it instead of trusting it.  Note the captured leak signature
	 * fits this mechanism precisely: icount=1, dwork_pending=0,
	 * bwork_pending=0, bast_pending=0, dlm_mode=PR, dlm_state=CACHED.  A
	 * prior session read "bast_pending=0" as evidence AGAINST the dwork;
	 * that inference was backwards, because the line below clears that
	 * flag immediately after the cancel.
	 *
	 * The release is gated so the mechanism can be A/B'd on ONE build:
	 * knob off = observe the leak, knob on = observe it repaired.
	 */
	{
		extern int mxfs_cancel_ref_release;
		bool	c_w, c_d;

		c_w = cancel_work_sync(&ip->i_dlm_bast_work);
		c_d = cancel_delayed_work_sync(&ip->i_dlm_bast_dwork);
		if (c_w || c_d) {
			static atomic_t p204n = ATOMIC_INIT(0);

			if (atomic_inc_return(&p204n) <= 2000)
				mxfs_probe("mxfs: P204-CANCEL-ARMED-REF ino=%llu work=%d dwork=%d icount=%d mode=%u state=%u bastq_src=%u release=%d — cancelled a QUEUED bast arm; its igrab ref is dropped by nobody\n",
					(unsigned long long)ip->i_ino,
					c_w ? 1 : 0, c_d ? 1 : 0,
					atomic_read(&VFS_I(ip)->i_count),
					ip->i_dlm_mode, ip->i_dlm_state,
					ip->i_dlm_bastq_src,
					mxfs_cancel_ref_release);
			if (mxfs_cancel_ref_release) {
				/* One arm == one igrab, so release once per
				 * cancelled arm.  Guarded exactly like the
				 * work functions' own drops: never touch an
				 * already-freeing inode. */
				int n = (c_w ? 1 : 0) + (c_d ? 1 : 0);

				while (n--) {
					int cnt = atomic_read(&VFS_I(ip)->i_count);
					unsigned long st = mxfs_istate(VFS_I(ip));

					if (cnt < 1 || (st & (I_FREEING | I_CLEAR))) {
						mxfs_probe("mxfs: P204-CANCEL-BADREF ino=%llu i_count=%d i_state=0x%lx — NOT releasing\n",
							(unsigned long long)ip->i_ino,
							cnt, st);
						break;
					}
					xfs_irele(ip);
				}
			}
		}
	}
	ip->i_dlm_bast_pending = false;

	/*
	 * FIX (durable dir-block lost-update root):
	 *
	 * xfs_reclaim_inode reaches here once the inode CORE is clean
	 * (xfs_inode_clean) and unpinned — but a DIRECTORY's data-fork block
	 * buffers (the dir DATA/leaf/free blocks) are independent xfs_buf's
	 * tracked only in the AIL; reclaim's xfs_iflush writes the inode
	 * cluster, NOT those.  The old "reclaim only reaches here on a CLEAN
	 * inode, so its data is already durable" assumption is FALSE for dirs.
	 *
	 * If we release the on-disk DLM slot now with dir blocks still dirty /
	 * in-AIL, a peer acquires the dir, FUA-reads STALE disk (missing this
	 * node's committed dirents), RMWs and DURABLY CLOBBERS them — the
	 * 90/120 "node lost its own files" lost-update.  PROVEN (
	 * P-NOINO-BAST): the shared test dir inode is reclaimed mid-run, so a
	 * peer's later BAST hits the no-inode direct-unlock path having never
	 * drained these blocks.
	 *
	 * Drain the dir's own data blocks durable BEFORE the unlock, the same
	 * guarantee bast_process gives on a normal BAST handoff.  Targeted
	 * per-block synchronous bwrite (NOT whole-AG ail_push_sync, which
	 * deadlocks) bounded by the dir size — a few buffers.  We already hold
	 * XFS_ILOCK_EXCL (== i_lock, taken by xfs_reclaim_inode), so the
	 * extent list is stable and we must NOT re-take i_lock.  log_force
	 * first clears any transient CIL pin so xfs_bwrite's wait_unpin can't
	 * hang.  Multi-node directories only.
	 */
	/*
	 * (D-0491) instrumented instrument, always on: until 0.70.5 the
	 * drain arm below covered EXTENT-format directories only.  A
	 * btree-format directory (the 32-node shared create directory grows
	 * past the extent fork within seconds) reclaimed while this node held
	 * it EX released the on-disk grant with whatever committed-unwritten
	 * data blocks it still had cached; those blocks survived reclaim
	 * (undestaged rotate) and were next offered to the LUN by a sub-EX
	 * release, which the write fence refuses — the lost-dirent shape of
	 * run 065945Z.  Count them here, at the moment the grant is about to
	 * leave, so the gap is measured rather than argued; the census after
	 * the drain (P491-EVICT-DRAINED) shows what the drain left.  i_lock
	 * is held by reclaim.
	 */
	bool	evict_precensus_flagged = false;

	if (ip->i_dlm_mode != MXFS_LOCK_NL &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode)) {
		struct mxfs_dir_undest_census	ec;
		int	ecrc = mxfs_dir_undest_census(ip, &ec);
		int	ef4_unknown = 0;
		long	ef4 = mxfs_f4_open_for_dir(mp, ip->i_ino, &ef4_unknown);

		if (ecrc != 0 || ec.undest || ec.inail || ec.locked || ef4) {
			static atomic_t p491e_n = ATOMIC_INIT(0);

			evict_precensus_flagged = true;
			if (atomic_inc_return(&p491e_n) <= 400)
				mxfs_probe("mxfs: P491-EVICT-UNDEST ino=%llu fmt=%d mode=%u gmode=%u state=%u rc=%d undest=%d inail=%d locked=%d cached=%d f4_open=%ld f4_unknown=%d first_daddr=%lld lseq=%llu wseq=%llu has_bli=%d done=%d drain_arm=%d comm=%s — directory grant leaving through inode reclaim with committed-unwritten data blocks cached\n",
					(unsigned long long)ip->i_ino,
					ip->i_df.if_format, ip->i_dlm_mode,
					mxfs_v5_dlm_inode_granted_mode(mp->m_mxfs_dlm,
								       ip->i_ino),
					ip->i_dlm_state, ecrc,
					ec.undest, ec.inail, ec.locked, ec.cached,
					ef4, ef4_unknown,
					(long long)ec.first_daddr,
					(unsigned long long)ec.first_lseq,
					(unsigned long long)ec.first_wseq,
					ec.first_has_bli, ec.first_done,
					(ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
					 ip->i_df.if_format == XFS_DINODE_FMT_BTREE) ? 1 : 0,
					current->comm);
		}
	}
	/*
	 * (D-0491, PROVEN by the 0.70.4 census, 3 laps of 3):
	 * the arm above was gated on EXTENTS format only.  The 32-node shared
	 * create directory converts to BTREE within seconds, so every reclaim
	 * of it while this node held EX released the on-disk grant with its
	 * committed-unwritten data blocks still in core (P491-EVICT-UNDEST
	 * mode=5 undest=2..5 drain_arm=0 on exactly the node whose entries
	 * were then lost, one per lap), the next release entered at PR, the
	 * directory write fence refused the re-land, and the block was freed
	 * with its obligation open.  BTREE takes the same drain: the flush
	 * helper already covers it (owner scan + bmbt scan, then the extent
	 * walk when the extents are in core).  A block whose log item was
	 * already retired without a write is invisible to the owner scan (it
	 * keys on DIRTY/IN_AIL/pinned/delwri), so the map-independent
	 * undestaged landing scan runs as well — the same pass the no-inode
	 * BAST release uses for exactly this class.  Then the drain is
	 * CHECKED: if committed-unwritten blocks remain, the grant must not
	 * leave — say so and fail closed under the same policy as the
	 * inode-cluster tripwire above (evict_obligation_shutdown), because a
	 * silent release here is a durable cluster-wide loss.  Reclaim holds
	 * i_lock; nothing below takes it.
	 */
	if (ip->i_dlm_mode != MXFS_LOCK_NL &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    (ip->i_df.if_format == XFS_DINODE_FMT_EXTENTS ||
	     ip->i_df.if_format == XFS_DINODE_FMT_BTREE)) {
		struct mxfs_dir_undest_census	pc;
		int	landed, left, pcrc, pf4_unknown = 0;
		long	pf4;

		xfs_log_force(mp, XFS_LOG_SYNC);
		mxfs_dir_flush_data_blocks(ip);
		landed = mxfs_dir_noino_land_scan(mp, ip->i_ino, true);
		mxfs_blkdev_flush_epoch(mp);

		pcrc = mxfs_dir_undest_census(ip, &pc);
		left = mxfs_dir_noino_land_scan(mp, ip->i_ino, false);
		pf4 = mxfs_f4_open_for_dir(mp, ip->i_ino, &pf4_unknown);
		/* s492a: a drain that left every field at zero printed
		 * nothing, so the second exercised case had no post-drain line
		 * — print whenever the pre-census had something to drain too. */
		if (evict_precensus_flagged || landed || left || pcrc != 0 ||
		    pc.undest || pc.inail || pc.locked || pf4) {
			static atomic_t p491d_n = ATOMIC_INIT(0);
			bool undrained = ip->i_dlm_mode == MXFS_LOCK_EX &&
					 (left || pc.undest || pc.inail);

			if (atomic_inc_return(&p491d_n) <= 400)
				mxfs_probe("mxfs: P491-EVICT-DRAINED ino=%llu fmt=%d mode=%u landed=%d left=%d rc=%d undest=%d inail=%d locked=%d cached=%d f4_open=%ld f4_unknown=%d first_daddr=%lld lseq=%llu wseq=%llu undrained=%d comm=%s — reclaim-exit drain of the directory's committed-unwritten blocks before the grant leaves\n",
					(unsigned long long)ip->i_ino,
					ip->i_df.if_format, ip->i_dlm_mode,
					landed, left, pcrc,
					pc.undest, pc.inail, pc.locked, pc.cached,
					pf4, pf4_unknown,
					(long long)pc.first_daddr,
					(unsigned long long)pc.first_lseq,
					(unsigned long long)pc.first_wseq,
					undrained ? 1 : 0, current->comm);
			if (undrained) {
				pr_err("mxfs: P491-EVICT-UNDRAINED ino=%llu left=%d undest=%d inail=%d — committed directory blocks still unwritten after the reclaim-exit drain; releasing EX now would lose them cluster-wide%s\n",
					(unsigned long long)ip->i_ino,
					left, pc.undest, pc.inail,
					mxfs_evict_obligation_shutdown ?
						"; shutting down" : "");
				if (mxfs_evict_obligation_shutdown)
					xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
			}
		}
	}

	/*
	 * FIX (shortform-dir durable lost-update root, PROVEN by the
	 * P-NOINO-BAST ino=2097281 cross_visibility timeline): a SHORTFORM
	 * (FMT_LOCAL) directory's dirents live INLINE in the dinode, so the
	 * EXTENTS-only branch above does nothing for it.  When the shared
	 * shortform dir inode is reclaimed mid-run, releasing its DLM slot here
	 * WITHOUT destaging the inode cluster lets a peer FUA-read the stale
	 * platter dinode and durably clobber this node's just-committed dirent
	 * (e.g. node1.txt vanishes from every node).  Make the dinode
	 * platter-durable before the release.  P-EVICT-SFDIR is always-on so
	 * the path is provable at instr=0.
	 */
	if (ip->i_dlm_mode != MXFS_LOCK_NL &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    S_ISDIR(VFS_I(ip)->i_mode) &&
	    ip->i_df.if_format == XFS_DINODE_FMT_LOCAL) {
		bool durable = mxfs_inode_cluster_durable(ip);
		if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
			mxfs_probe_ratelimited("mxfs: P-EVICT-SFDIR ino=%llu durable=%d\n",
				(unsigned long long)ip->i_ino, durable);
	}

	/*
	 * D-0975: the grant is about to leave through reclaim; this node's
	 * cached extent-tree blocks of the inode end with it (same barrier as
	 * the release pipeline's, same fail-closed policy as the obligation
	 * tripwires above).
	 */
	if (ip->i_dlm_mode != MXFS_LOCK_NL && !xfs_is_shutdown(mp)) {
		int	terc = mxfs_bmbt_tenure_end_evict(ip, "reclaim");

		if (terc) {
			pr_err("mxfs: P975-EVICT-WEDGE ino=%llu rc=%d mode=%u — cached extent-tree blocks could not be retired before the grant leaves through reclaim%s\n",
				(unsigned long long)ip->i_ino, terc,
				ip->i_dlm_mode,
				mxfs_evict_obligation_shutdown ?
					"; shutting down" : "");
			if (mxfs_evict_obligation_shutdown)
				xfs_force_shutdown(mp, SHUTDOWN_META_IO_ERROR);
		}
	}

	/* Release the DLM lock if held */
	if (ip->i_dlm_mode != MXFS_LOCK_NL) {
		mxfs_idbg("mxfs: P-H22-CALL site=EVICT ino=%llu mode=%u\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_mode);

		/*
		 * (D-FOREIGN-REPLAY item 2, the evict ordering gap):
		 * until now the certificate stayed PROVING across the wire
		 * releases below and was only revoked by the NL store at the
		 * end of this function — publish-then-revoke.  In that window
		 * a peer could be granted the freed slot and mint a tenure
		 * while our journal's authority claims still named this one.
		 * Announce release-begin before relinquishment becomes
		 * PEER-EFFECTIVE (design-consult ruling B: that, not
		 * "eviction begin", is the invariant — peer-visible activity
		 * under the still-held grant is legitimate).  It must stay
		 * AFTER the P237 last-chance publish and the /
		 * durability arms above: a successful P237 CAS is itself a
		 * proving act, and log items formatted by the durability
		 * arms must carry the live tenure's authority.  A FAILED
		 * P237 needs no phantom-loss handling: unpublished means no
		 * wire grant was ever believed held, UNPUBLISHED_EX already
		 * says "no on-disk authority", and the gate fails such
		 * images closed.  The P6R-RETAIN arm
		 * below keeps the wire PR grant, but in-core tenure is being
		 * given up either way (the NL store at function end), and a
		 * clean wire-confirmed PR can carry no proving certificate,
		 * so begin_release is a no-op there by construction.
		 */
		spin_lock(&ip->i_dlm_lock);
		mxfs_inact_cert_evict_check_locked(ip, MXFS_SITE);
		mxfs_inode_authority_begin_release_locked(ip, MXFS_SITE);
		spin_unlock(&ip->i_dlm_lock);

		/*
		 *  /for a GENUINELY FREED inode use
		 * the free-aware unlock so CAW piggybacks a dir_epoch/
		 * last_ex_slot clear onto its own tombstone CAS, so the NEXT
		 * node to reuse this ino number doesn't inherit a stale
		 * cross-node-handoff signal from this now-dead incarnation
		 * (dlm_scaling@32 op-rate fix).  Must NOT treat a plain
		 * idle-cache reclaim as a free -- that case needs the normal
		 * idle-gap epoch inheritance preserved.
		 *
		 * (D-AGI-UNLINKED tombstone-semantics): "genuinely
		 * freed" is MXFS_IF_FREE_COMMITTED (our ifree committed), NOT
		 * nlink==0.  A cached/reloaded copy of a PEER's live
		 * open-unlinked inode also has nlink==0; the deterministic
		 * AGI-bucket reproducer showed this evict free-tombstoning
		 * the live peer's slot (gen reset + epoch clear) after a
		 * guard-skipped inactivation.
		 */
		if (ip->i_dlm_routed_iclus && !ip->i_dlm_unpublished) {
			/* ICLUSTER release_check: is_free piggybacks the
			 * tombstone CAS only if THIS call performs the
			 * cluster release (sweep-clean under a pending BAST
			 * — tombstone hygiene approximation).  Unpublished
			 * inodes never claimed the cluster; skip. */
			mxfs_inode_authority_check_published(ip, MXFS_SITE);
			(void)mxfs_iclus_unlock(mp, ip->i_ino,
				ip->i_dlm_mode == MXFS_LOCK_EX ?
				MXFS_LOCK_EX : MXFS_LOCK_PR,
				xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED));
		} else if (xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED)) {
			mxfs_inode_authority_check_published(ip, MXFS_SITE);
			mxfs_v5_dlm_inode_unlock_free(mp->m_mxfs_dlm, ip->i_ino);
		}
		else if (mxfs_evict_retain_pr &&
			 ip->i_dlm_mode == MXFS_LOCK_PR &&
			 xfs_inode_clean(ip) &&
			 !xfs_is_unmounting(mp) && !xfs_is_shutdown(mp) &&
			 /*
			  * 0.89.0 (D-0977): a shell that published an open
			  * mark is not retained on TCP — the mark clears only
			  * inside a release this shell drives (the noino BAST
			  * unlock a retained grant later takes carries no
			  * shell, so no clear), and a mark nobody clears
			  * defers the owner's reap until the fence purge.
			  */
			 !(ip->i_mxfs_open_pub &&
			   mxfs_v5_dlm_open_clear_rides_release(mp->m_mxfs_dlm)) &&
			 /*
			  * D-EVICT-RETENTION-WIRE-EX-LEAK: the branch
			  * condition above trusts the IN-MEMORY mode, but the
			  * wire can hold EX while memory says PR (live-proven:
			  * 200-file bulk-create repro — P6R-RETAIN fired for
			  * inos whose on-disk slot showed granted EX, gen=1,
			  * never released; 13.4K such orphan-EX slots
			  * accumulated from one board's rsync_paired files,
			  * ~435/node).  A retained wire-EX blocks every other
			  * node until a demand-noino unlock that may never
			  * come.  Retain ONLY on wire-confirmed PR: one
			  * hint-path sector read, paid solely when every
			  * cheaper condition already voted to retain.  Any
			  * other answer (EX/PW = the leak; NL/none = phantom
			  * retention, also live-observed) falls through to the
			  * normal unlock, which handles each correctly.
			  */
			 mxfs_v5_dlm_inode_granted_mode(mp->m_mxfs_dlm,
							ip->i_ino) ==
				MXFS_LOCK_PR) {
			/*
			 * EVICT-RETAIN-PR (instrumented stack capture, 32/caw
			 * dir_reuse): barrier-aligned drop_caches had all 32
			 * nodes in caw_slot<-unlock_gen<-v5_dlm_inode_unlock<-
			 * mxfs_dlm_evict simultaneously CAS-clearing their PR
			 * bits on the SAME hot slots (the shared dir), each
			 * unlock walking retry backoff toward its 5s deadline
			 * — 5-9s of the round's 16s, and pure waste: verify
			 * re-acquires the same PR ~100ms later.  A clean PR
			 * grant is retention-safe across evict: readers
			 * coexist with the on-wire bit (re-acquire is an
			 * idempotent compat-add), a writer's EX demand routes
			 * through the proven no-inode BAST direct-unlock
			 * (/noino drain fence — data already
			 * durable here by definition of clean), the FREE
			 * boundary cannot see foreign retained bits (free
			 * requires EX, which excluded them first), and
			 * unmount's release_all sweep clears own bits
			 * wholesale.  EX/PW are NEVER retained (orphan-EX
			 * starvation class).  Own-mode-conflict on a later
			 * own EX want resolves via P-SELF-STALE-EDEADLK
			 * recovery (rare shape; correct, just slower).
			 */
			static int p6r_n;

			/*
			 * (design-consult ruling C): retaining a clean wire-PR
			 * grant with no in-core certificate is sound — PR is a
			 * cache state, never image authority.  But a
			 * certificate that is NOT already NONE here means a
			 * proving EX tenure coexisted with mode==PR (no EX→PR
			 * demote exists in the tree, so that state is
			 * unreachable by design) — a bug to surface, not
			 * another silent no-op case.  begin_release above
			 * moved any proving state to RELEASING, so != NONE is
			 * the complete test.  Lockless u8 read, diagnostic
			 * only, same contract as check_published.
			 */
			if (unlikely(READ_ONCE(ip->i_mxfs_auth_state) !=
				     MXFS_AUTH_NONE))
				mxfs_probe_ratelimited("mxfs: P248-RETAIN-CERT-ANOMALY ino=%llu auth_state=%u — PR retain arm reached with a non-NONE authority certificate; EX-class tenure coexisted with PR mode\n",
					(unsigned long long)ip->i_ino,
					READ_ONCE(ip->i_mxfs_auth_state));
			if (p6r_n++ < 2000)
				mxfs_probe("mxfs: P6R-RETAIN ino=%llu — clean PR grant retained across evict (demand-released via noino BAST)\n",
					(unsigned long long)ip->i_ino);
		} else {
			mxfs_inode_authority_check_published(ip, MXFS_SITE);
			/* 0.89.0 (D-0977): the evict clear rides this release
			 * (see the block below) — the only durable form on TCP,
			 * one CAS instead of two on CAW. */
			mxfs_v5_dlm_inode_unlock_open(mp->m_mxfs_dlm, ip->i_ino, 0,
				(ip->i_mxfs_open_pub &&
				 !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
				 !xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED)) ?
					-1 : 0);
			if (ip->i_mxfs_open_pub)
				ip->i_mxfs_open_pub = false;
		}
	}

	/*
	 * open tracking — lazy CLEAR at evict.  Eviction is the VFS's
	 * guarantee that this node has NO remaining protected activity for
	 * the inode (no fds, no mappings; page cache truncated by evict), so
	 * clearing here satisfies the quiescence-before-clear invariant by
	 * construction.  Runs regardless of grant mode: an open-unlinked
	 * inode BASTed down to NL still carries our bit, and the owner's
	 * deferred reap converges only when the last closer's evict lands
	 * this clear.  FREE_COMMITTED skips: unlock_free already zeroed the
	 * whole field in its own CAS.
	 *
	 * 0.89.0 (D-0977): reached with pub still set only on the arms whose
	 * release did not carry the clear (ICLUSTER, or no grant to release).
	 * On CAW the standalone CAS clears it; on TCP a mark with no release
	 * to ride clears only through a grant taken for the purpose — at NL
	 * the shell is gone, so the mark stays until this node's next release
	 * of the inode publishes its absolute state, or its fence purge.
	 */
	if (ip->i_mxfs_open_pub && mp->m_mxfs_dlm &&
	    !mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) &&
	    !xfs_iflags_test(ip, MXFS_IF_FREE_COMMITTED)) {
		if (mxfs_v5_dlm_open_clear_rides_release(mp->m_mxfs_dlm))
			mxfs_probe_ratelimited(
			    "mxfs: P977-EVICT-MARK-LEFT ino=%llu dlm_mode=%u — evicted with a published mark and no release to carry the clear\n",
				(unsigned long long)ip->i_ino, ip->i_dlm_mode);
		else
			mxfs_v5_dlm_inode_open_clear(mp->m_mxfs_dlm, ip->i_ino);
		ip->i_mxfs_open_pub = false;
	}

	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_mode = MXFS_LOCK_NL;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	ip->i_dlm_epoch++; ip->i_dlm_epoch_src = MXFS_SITE; mxfs_relbar_epoch_check(ip);
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_state = MXFS_DLM_ISTATE_NONE;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	ip->i_dlm_ex_holders = 0; MXFS_DLMTR_H(ip);
	ip->i_dlm_pr_holders = 0; MXFS_DLMTR_H(ip);
}

void mxfs_defer_reap_add(struct xfs_mount *mp, uint64_t ino, uint32_t gen,
			 int16_t bucket)
{
	mxfs_defer_reap_add_mode(mp, ino, gen, bucket, MXFS_REAP_OWN);
}

/*
 * 0.11.359 (D-REAP-WORK-UAF-PANIC-AFTER-UNMOUNT): every arm of the reap
 * delayed_work goes through here.  m_mxfs_reap_work is embedded in the
 * mount, so a schedule that lands AFTER mxfs_defer_reap_destroy's cancel —
 * e.g. a deferred zombie evicted during late unmount reap-adding, or a
 * recovery batch finishing mid-teardown — re-queues a 30s timer that fires
 * into freed mount memory ("Workqueue: events 0x<garbage>" GP panics, 5
 * captured on host serial logs).  After destroy sets m_mxfs_reap_dead the
 * arm becomes a loud no-op: the log line both proves the mechanism and is
 * the fix.  Durable state (buckets) makes the skipped work safe — the next
 * mount of the slot re-drives it.
 */
void mxfs_reap_sched(struct xfs_mount *mp, unsigned int delay_ms,
			    const char *why)
{
	if (READ_ONCE(mp->m_mxfs_reap_dead)) {
		mxfs_probe_ratelimited("mxfs: P89-REAP-SCHED-AFTER-DESTROY (%s) — reap work is torn down; durable bucket state carries the duty\n",
				    why);
		return;
	}
	schedule_delayed_work(&mp->m_mxfs_reap_work,
			      msecs_to_jiffies(delay_ms));
}

void mxfs_defer_reap_add_mode(struct xfs_mount *mp, uint64_t ino,
			      uint32_t gen, int16_t bucket, uint8_t kind)
{
	struct mxfs_reap_entry *e, *n;

	n = kzalloc(sizeof(*n), GFP_NOFS);
	spin_lock(&mp->m_mxfs_reap_lock);
	list_for_each_entry(e, &mp->m_mxfs_reap_list, l) {
		if (e->ino == ino) {
			/* Freer authority (OWN or ADOPTED) outranks a
			 * retire-only dupe; never downgrade. */
			if (kind != MXFS_REAP_RETIRE &&
			    e->kind == MXFS_REAP_RETIRE)
				e->kind = kind;
			spin_unlock(&mp->m_mxfs_reap_lock);
			kfree(n);
			return;
		}
	}
	if (!n) {
		/* Allocation failure: entry not tracked this time, but the
		 * zombie is durable in the bucket.  (design review liveness
		 * hazard): "a later local touch" is NOT guaranteed — arm the
		 * own-bucket rescan so the worker re-discovers it from the
		 * durable record. */
		spin_unlock(&mp->m_mxfs_reap_lock);
		set_bit(MXFS_REAPF_OWN_RESCAN, &mp->m_mxfs_reap_duties);
		mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "add-enomem");
		mxfs_probe("mxfs: P87-REAP-ADD-ENOMEM ino=%llu — own-bucket rescan armed\n",
			(unsigned long long)ino);
		return;
	}
	n->ino = ino;
	n->gen = gen;
	n->bucket = bucket;
	n->kind = kind;
	list_add_tail(&n->l, &mp->m_mxfs_reap_list);
	mp->m_mxfs_reap_count++;
	spin_unlock(&mp->m_mxfs_reap_lock);
	mxfs_reap_sched(mp, MXFS_REAP_FIRST_MS, "add");
}

/*
 * (design-consult ruling 2): the deferred reap re-enters xfs_inactive at
 * cadence after an inactivation-certificate refusal.  Count the refusals on
 * the reap entry (which outlives the in-core inode) so a PERMANENT refusal
 * escalates instead of retrying forever; returns the count including this
 * refusal (0 only if no entry could be tracked — the ENOMEM rescan case).
 */
int mxfs_defer_reap_cert_refused(struct xfs_mount *mp, uint64_t ino,
				 uint32_t gen, int16_t bucket)
{
	struct mxfs_reap_entry *e;
	int n = 0;

	mxfs_defer_reap_add(mp, ino, gen, bucket);
	spin_lock(&mp->m_mxfs_reap_lock);
	list_for_each_entry(e, &mp->m_mxfs_reap_list, l) {
		if (e->ino == ino) {
			if (e->cert_refusals < 255)
				e->cert_refusals++;
			n = e->cert_refusals;
			break;
		}
	}
	spin_unlock(&mp->m_mxfs_reap_lock);
	return n;
}

void mxfs_defer_reap_done(struct xfs_mount *mp, uint64_t ino)
{
	struct mxfs_reap_entry *e;

	spin_lock(&mp->m_mxfs_reap_lock);
	list_for_each_entry(e, &mp->m_mxfs_reap_list, l) {
		if (e->ino == ino) {
			list_del(&e->l);
			mp->m_mxfs_reap_count--;
			spin_unlock(&mp->m_mxfs_reap_lock);
			mxfs_probe_ratelimited("mxfs: P89-REAP-DONE ino=%llu\n",
				(unsigned long long)ino);
			kfree(e);
			return;
		}
	}
	spin_unlock(&mp->m_mxfs_reap_lock);
}

void mxfs_reap_worker(struct work_struct *work)
{
	struct xfs_mount *mp = container_of(to_delayed_work(work),
					    struct xfs_mount,
					    m_mxfs_reap_work);
	struct mxfs_reap_entry *e, *tmp;
	LIST_HEAD(batch);
	int remaining;
	unsigned int sp_slot;

	if (xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
		return;

	/* a foreign slice whose recovery could not be published
	 * left its slot bit set.  Re-drive the replay worker (the replay
	 * itself is LSN-gated and idempotent, so redoing it is free); the
	 * duty clears once no dead slot remains outstanding.
	 *
	 * (incident474, design-consult b2): runs FIRST, before any
	 * lock-taking sweep below — a sweep blocked on an unpurged victim's
	 * grant must never starve the replay retry that would purge it. */
	if (test_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties)) {
		/* (#21): a TORN-latched slot is deterministically
		 * unreplayable — re-driving the worker for it would refuse
		 * again every pass (#11).  The duty is done when nothing
		 * RETRYABLE remains; torn slots stay frozen behind their
		 * dead bits until a new death event re-arms them. */
		if (bitmap_subset(mp->m_mxfs_foreign_dead_slots,
				  mp->m_mxfs_foreign_torn_slots, 64))
			clear_bit(MXFS_REAPF_FREPLAY, &mp->m_mxfs_reap_duties);
		else
			queue_work(system_unbound_wq,
				   &mp->m_mxfs_foreign_replay_work);
	}

	/*
	 * b2: the sweep retry and the bucket-scan duties all take
	 * inode EX grants; while ANY victim's slice replay is still pending
	 * they must not run — that ordering is the proven 474 deadlock.
	 * Skipped work stays recorded (pending bits / duty bits), and the
	 * worker-tail reschedule below retries once recovery drains.  The
	 * sweeps run as registered recovery context so an acquire timeout on
	 * a victim certified mid-sweep requeues (b3) instead of escalating
	 * to this survivor's shutdown.
	 */
	if (bitmap_empty(mp->m_mxfs_foreign_dead_slots, 64)) {
		struct mxfs_recovtask recov;

		mxfs_recovtask_enter(&recov, MXFS_RECOV_PHASE_CLEANUP);
		/* C8: bounded retry of incomplete survivor sweeps (a
		 * failed iget mid-walk leaves the slot pending; the bucket is
		 * the durable record).  Runs before the entry batch so a
		 * sweep's own deferred zombies join this pass's retries. */
		for_each_set_bit(sp_slot, mp->m_mxfs_sweep_pending_slots, 64) {
			if (!bitmap_empty(mp->m_mxfs_foreign_dead_slots, 64) ||
			    xfs_is_shutdown(mp))
				break;
			if (mxfs_survivor_sweep_slot(mp, sp_slot) == 0)
				clear_bit(sp_slot, mp->m_mxfs_sweep_pending_slots);
		}

		/* duties (see MXFS_REAPF_*): own-bucket rescan, then
		 * the guarded unclaimed-bucket pass.  A bit stays set on
		 * failure and the tail reschedule retries — the buckets are
		 * the durable record. */
		if (test_bit(MXFS_REAPF_OWN_RESCAN, &mp->m_mxfs_reap_duties) &&
		    bitmap_empty(mp->m_mxfs_foreign_dead_slots, 64) &&
		    mxfs_own_bucket_rescan(mp) == 0)
			clear_bit(MXFS_REAPF_OWN_RESCAN, &mp->m_mxfs_reap_duties);
		if (test_bit(MXFS_REAPF_UBSCAN, &mp->m_mxfs_reap_duties) &&
		    bitmap_empty(mp->m_mxfs_foreign_dead_slots, 64) &&
		    mxfs_unclaimed_bucket_scan(mp) == 0)
			clear_bit(MXFS_REAPF_UBSCAN, &mp->m_mxfs_reap_duties);
		mxfs_recovtask_exit(&recov);
	}

	spin_lock(&mp->m_mxfs_reap_lock);
	list_splice_init(&mp->m_mxfs_reap_list, &batch);
	spin_unlock(&mp->m_mxfs_reap_lock);

	list_for_each_entry_safe(e, tmp, &batch, l) {
		struct xfs_inode *ip = NULL;
		int rc = xfs_iget(mp, NULL, e->ino, XFS_IGET_UNTRUSTED, 0,
				  &ip);

		mxfs_probe_ratelimited(
		    "mxfs: P88-REAP-RETRY ino=%llu gen=%u iget_rc=%d\n",
			(unsigned long long)e->ino, e->gen, rc);
		if (rc) {
			/* Freed elsewhere / vanished: entry retired. */
			list_del(&e->l);
			spin_lock(&mp->m_mxfs_reap_lock);
			mp->m_mxfs_reap_count--;
			spin_unlock(&mp->m_mxfs_reap_lock);
			kfree(e);
			continue;
		}
		/* v3: make gen/nlink COHERENT before deciding.  A
		 * cache-hit iget can carry a stale-high nlink (this node
		 * never observed a dead peer's droplink) or a stale
		 * pre-reuse gen; deciding on either mis-retires or spins.
		 * The ilock ride runs the acquire-side reload exactly when
		 * the copy is stale/NL, and is a cached-grant no-op
		 * otherwise.  Runs BEFORE the authority-flag restore below
		 * so the reload's flag strip cannot race it. */
		xfs_ilock(ip, XFS_ILOCK_SHARED);
		xfs_iunlock(ip, XFS_ILOCK_SHARED);
		if (VFS_I(ip)->i_generation != e->gen ||
		    VFS_I(ip)->i_nlink != 0) {
			/* Reincarnated or resurrected (linkat): retire. */
			list_del(&e->l);
			spin_lock(&mp->m_mxfs_reap_lock);
			mp->m_mxfs_reap_count--;
			spin_unlock(&mp->m_mxfs_reap_lock);
			kfree(e);
			xfs_irele(ip);
			continue;
		}
		if (e->kind == MXFS_REAP_RETIRE) {
			/* opener-side retirement — prune the local
			 * dentry aliases so the last reference can drop and
			 * evict/inactivation runs with whatever authority
			 * the inode already carries (survivor-sweep restore,
			 * or none: B1/B4 then skip and the real freer's own
			 * reap converges).  One-shot: a still-open local fd
			 * re-adds at ITS last close. */
			d_prune_aliases(VFS_I(ip));
			list_del(&e->l);
			spin_lock(&mp->m_mxfs_reap_lock);
			mp->m_mxfs_reap_count--;
			spin_unlock(&mp->m_mxfs_reap_lock);
			mxfs_probe_ratelimited(
			    "mxfs: P92-REAP-RETIRE ino=%llu gen=%u — opener alias pruned post-last-close\n",
				(unsigned long long)e->ino, e->gen);
			kfree(e);
			xfs_irele(ip);
			continue;
		}
		/* Restore the authority snapshot (see struct comment): the
		 * gen match above proves this is the incarnation we deferred;
		 * this mount is its responsible freer and knows its bucket.
		 * ADOPTED (survivor-sweep) authority uses its own flag so
		 * the P2L-OWNFREE disk-free bypass stays strictly OWN. */
		xfs_iflags_set(ip, e->kind == MXFS_REAP_ADOPTED ?
				   MXFS_IF_ADOPTED_UNLINK :
				   MXFS_IF_LOCAL_UNLINK);
		if (e->bucket >= 0)
			ip->i_unlinked_bucket = e->bucket;
		/* the freer's own zombie can ALSO be dentry-pinned
		 * (we unlinked a path a local fd had open, or the sweep
		 * adopted an inode this node has an alias for) — prune so
		 * the irele below can actually reach inactivation. */
		d_prune_aliases(VFS_I(ip));
		/* The irele re-drives evict → xfs_inactive: either the B6
		 * guard defers again (mxfs_defer_reap_add dedupes against the
		 * re-queued entry) or the free proceeds and
		 * mxfs_defer_reap_done retires it. */
		list_del(&e->l);
		spin_lock(&mp->m_mxfs_reap_lock);
		list_add_tail(&e->l, &mp->m_mxfs_reap_list);
		spin_unlock(&mp->m_mxfs_reap_lock);
		xfs_irele(ip);
	}

	spin_lock(&mp->m_mxfs_reap_lock);
	remaining = mp->m_mxfs_reap_count;
	spin_unlock(&mp->m_mxfs_reap_lock);
	if (remaining > 0 ||
	    !bitmap_empty(mp->m_mxfs_sweep_pending_slots, 64) ||
	    mp->m_mxfs_reap_duties)
		mxfs_reap_sched(mp, MXFS_REAP_RETRY_MS, "worker-tail");
}
static struct delayed_work mxfs_lru_sweep_dwork;
int mxfs_lru_sweep_enable;	/* DEFAULT 0.  The sweep was built
				 * against a misdiagnosis — the "stranded"
				 * inodes are page-cache-held, which upstream
				 * DELIBERATELY keeps off the inode LRU
				 * (mapping_shrinkable, fs/inode.c; mm/truncate
				 * re-adds when the cache empties), so the
				 * igrab/iput re-add is refused and the sweep
				 * no-ops in a loop.  drop_caches=3 evicts them
				 * normally (verified: slab 221→65).  Kept as
				 * an opt-in diagnostic only. */
module_param_named(lru_sweep, mxfs_lru_sweep_enable, int, 0644);
MODULE_PARM_DESC(lru_sweep,
		 "opt-in repatriation sweep (default 0 — see note; page-held inodes are off-LRU by upstream design)");

/*
 * The sweep's batch, off the stack (1 KB).  Only mxfs_lru_sweep_fn touches it,
 * and a work item never runs concurrently with itself.
 */
static struct inode *mxfs_lru_sweep_batch[MXFS_LRU_SWEEP_BATCH];

static void mxfs_lru_sweep_fn(struct work_struct *work)
{
	struct xfs_mount	*mp = READ_ONCE(mxfs_dbg_mp);
	struct super_block	*sb;
	struct inode		*inode;
	struct inode		**batch = mxfs_lru_sweep_batch;
	int			nb = 0, total = 0;

	if (!mp || !mp->m_super || !mxfs_lru_sweep_enable ||
	    xfs_is_shutdown(mp) || xfs_is_unmounting(mp))
		goto rearm;
	sb = mp->m_super;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (nb >= MXFS_LRU_SWEEP_BATCH)
			break;
		spin_lock(&inode->i_lock);
		if (!(mxfs_istate(inode) & (I_DIRTY_ALL | I_SYNC | I_FREEING |
					I_WILL_FREE | I_NEW)) &&
		    !atomic_read(&inode->i_count) &&
		    list_empty(&inode->i_lru)) {
			/* __iget equivalent: ref 0->1 under i_lock with the
			 * freeing states excluded above. */
			atomic_inc(&inode->i_count);
			batch[nb++] = inode;
		}
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);

	while (nb > 0) {
		total++;
		iput(batch[--nb]);	/* iput_final re-runs the LRU add on
					 * the now clean+unused inode */
	}
	if (total)
		mxfs_probe("mxfs: P-LRU-SWEEP repatriated %d stranded inode(s)\n",
			total);
rearm:
	schedule_delayed_work(&mxfs_lru_sweep_dwork,
			      msecs_to_jiffies(MXFS_LRU_SWEEP_MS));
}

void mxfs_lru_sweep_start(void)
{
	INIT_DELAYED_WORK(&mxfs_lru_sweep_dwork, mxfs_lru_sweep_fn);
	schedule_delayed_work(&mxfs_lru_sweep_dwork,
			      msecs_to_jiffies(MXFS_LRU_SWEEP_MS));
}
EXPORT_SYMBOL(mxfs_lru_sweep_start);

void mxfs_lru_sweep_stop(void)
{
	cancel_delayed_work_sync(&mxfs_lru_sweep_dwork);
}
EXPORT_SYMBOL(mxfs_lru_sweep_stop);

/*
 * NEWARCH Phase 0 measurement instrument — DELIBERATELY SLOW.  When set,
 * mxfs_dlm_ilock_begin demotes every CACHED in-core grant to NL/NONE so
 * every acquire falls into the slow path (on-disk CAW + inode reload +
 * drain-evict of cached dir blocks); xfs_da_read_buf invalidates every
 * cached dir DATA buffer on lookup so the sanctioned read path refetches
 * from the SCST-coherent shared target.  Result: every metadata op pays
 * a CAW slot round-trip + buffer reload.  This is "provably correct at
 * any cost" — it answers Phase 0's gate question (NEWARCH §5): if even
 * fully-synchronous cannot pass cache_coherency, the exclusion primitive
 * is broken below the notification layer (fix P106 first); if it passes
 * AND still meaningfully beats GFS2/OCFS2 the notification pipe is the
 * only missing piece (proceed to Phase 1+2); if it passes but collapses
 * to GFS2 speeds the speed was the incoherence and Path A is at risk
 * (escalate).  NOT a shipping mode.  Probe tag: P0-FCOH (mxfs.instr gated).
 */
int mxfs_force_coherent;
module_param_named(force_coherent, mxfs_force_coherent, int, 0644);
MODULE_PARM_DESC(force_coherent,
                 "NEWARCH Phase 0 measurement instrument — force every "
                 "metadata acquire to slow path and every cached dir "
                 "block to be re-read: 0=off (default), 1=force fully "
                 "synchronous (deliberately slow, measurement only).");

/*
 * DIAGNOSTIC: when set, INODE-type CAW locks are granted in-memory
 * only (no disk find_slot/read_slot/caw_slot round-trip), exactly like the
 * single-node fast path.  This measures the performance ceiling if the
 * per-new-inode CAW grant cost (the proven rsync_paired bottleneck) were
 * eliminated.  UNSAFE for real cross-node inode sharing — diagnostic only;
 * default 0.
 */
int mxfs_inode_caw_local;
module_param_named(inode_caw_local, mxfs_inode_caw_local, int, 0644);
MODULE_PARM_DESC(inode_caw_local,
                 "DIAGNOSTIC: grant INODE CAW locks in-memory only "
                 "(0=off default, 1=skip disk CAW for inode locks)");

/*
 * D-CAW-YIELD-STARVATION-SHUTDOWN fix knobs.
 * A compatible fresh INODE acquire that defers to yield_to used to be
 * invisible to the ticket (releases snapshot yield_to = waiters and the
 * defer path never registered) — under continuous handoff on a hot shared
 * directory it starved through the whole retry budget and the rc=-110
 * ilock_begin policy then force-shut-down the FS on 10 of 32 nodes at
 * once.  caw_fresh_register (fix A) CAS-registers the deferrer's waiter
 * bit on its first deferral; caw_fresh_yield_bound (fix B) is the number
 * of consecutive compatible-yield deferrals a REGISTERED fresh acquire
 * tolerates before it stops deferring and takes the compatible claim
 * (~25 ms/lap measured; 16 ~= 400 ms).  0 disables the respective part
 * (pre-fix behaviour, A/B control).  Conversions are untouched (
 * priority, v0.10.41 pure-PR-batch exception).
 */
int mxfs_caw_fresh_register = 1;
module_param_named(caw_fresh_register, mxfs_caw_fresh_register, int, 0644);
MODULE_PARM_DESC(caw_fresh_register,
                 "register fresh compatible-yield INODE/AG acquires as waiters "
                 "so release tickets include them (1=on default, 0=pre-fix; "
                 "AG added 0.24.2)");

int mxfs_caw_fresh_yield_bound = 16;
module_param_named(caw_fresh_yield_bound, mxfs_caw_fresh_yield_bound, int, 0644);
MODULE_PARM_DESC(caw_fresh_yield_bound,
                 "consecutive compatible-yield deferrals a registered fresh "
                 "INODE/AG acquire tolerates before claiming anyway "
                 "(16 default, 0=defer forever = pre-fix; AG: 16 x 3-12 ms)");

int mxfs_inode_caw_skip;
module_param_named(inode_caw_skip, mxfs_inode_caw_skip, int, 0644);
MODULE_PARM_DESC(inode_caw_skip,
                 "DIAGNOSTIC: grant INODE CAW locks with NO disk CAW and NO "
                 "mem_lock_track (SOLO ceiling measurement only)");

/*
 * when 1, AG/inode/dir metadata reads ALWAYS go FUA (ignore the
 * _XBF_FUA_FRESH amortization gate).  Diagnostic+fix lever for the AG
 * double-allocation: if a bnobt buffer wrongly retains _XBF_FUA_FRESH
 * across a release (invalidate_ag_meta missed it), the "fresh" read is a
 * stale cached read and a peer double-allocates the block.  Forcing FUA
 * makes every metadata read pierce the storage cache (correct but with
 * more SCSI round-trips).  If this stops the double-alloc/shutdown, the
 * stale-cached-read hypothesis is confirmed.
 */
/*
 * gate the multi-node sync_fs AIL-push+flush (cross-node di_size
 * coherence — fixes rename_visibility empty-content 15->2-5).  DEFAULT 0:
 * the whole-AIL xfs_ail_push_all_sync is too slow under sustained load and
 * made the full cache_coherency.sh criterion TIME OUT (>900s).  Set 1 to
 * enable the fix (rename gets 2-5 fails but slow).  NEXT SESSION: replace the
 * whole-AIL push in xfs_super.c with a BOUNDED/targeted iflush, then make
 * this default 1.  See docs/history/session-39-lessons.md.
 */
int mxfs_sync_iflush = 1;	/* DEFAULT ON: sync_fs now does a BOUNDED PER-AG push (this node's preferred AG only, stall-abort capped) instead of the whole-AIL push that deadlocked cross-AG. Per-AG avoids the cross-AG xfsaild cycle; the bounded cap prevents wedging sync(2). Pushes our dirty di_size to the on-disk cluster so a peer's FUA-read sees real file content, not di_size=0 (empty-content fix). */
module_param_named(sync_iflush, mxfs_sync_iflush, int, 0644);
MODULE_PARM_DESC(sync_iflush,
                 "Multi-node sync(2) pushes the AIL + flushes for cross-node "
                 "di_size coherence: 0=off default (criterion completes), "
                 "1=on (rename empty-content fixed but slow)");

int mxfs_fua_always = 1;	/* DEFAULT 1 (REQUIRED for coherency on this LIO cluster). fua_disable=0 enables FUA reads; the _XBF_FUA_FRESH amortization gate (fua_always=0) is NOT reliable for cross-node dir coherency — gated full 4/tcp defaults run = crash_consistency 3/4 + dir_reuse 0/4 (a gated 17/17 once was luck). Forcing FUA on every coherency-metadata read keeps dir_reuse + crash_consistency SOLID. Cost: extra FUA per dir-EX handoff can make tcp_dlm_scaling marginal vs its 60s window (seen 2/4 once); addressed separately. NOTE: was default 0 for the SCST target (FUA reads the un-destaged platter, stale) — that target is not the cluster in use. */
MODULE_PARM_DESC(fua_always,
                 "Force FUA on every coherency metadata read, ignoring the "
                 "_XBF_FUA_FRESH amortization: 0=off (default), 1=always-FUA");

/*
 * lever: disable the SCSI READ(16)-FUA read path entirely so all
 * coherency-metadata reads use the normal bio path.  On the SCST target
 * (vendor SCST_FIO) all initiators share one write-back device cache, so a
 * normal read sees a peer's just-written (but not-yet-destaged) data, while
 * an FUA read pierces to the OLDER platter and returns stale content (the
 * di_size=0 / bnobt-pristine root).  The FUA-read workaround was built for
 * the old LIO target which kept a per-initiator read cache; it is harmful
 * on SCST.  1=skip FUA reads (use bio).
 */
/*
 * surgical per-inode inode-cluster write (default OFF).  When 1,
 * xfs_buf_submit writes ONLY this node's dirty inode sectors (from b_li_list)
 * via FUA instead of the whole cluster buffer, so a stale copy of a peer's
 * inode in our cluster buffer never clobbers the peer (the 4-node
 * cross_write_read xfs_inode_buf_verify corruption).
 */
int mxfs_surgical_inode_write;
module_param_named(surgical_inode_write, mxfs_surgical_inode_write, int, 0644);
MODULE_PARM_DESC(surgical_inode_write,
                 "Write only this node's dirty inode sectors on inode-cluster "
                 "flush (avoids clobbering peer inodes): 0=off (default), 1=on");

/*
 * toggle for mxfs_submit_partial_inode_write (the
 * partial-sector inode-cluster write).  Default ON (=1) preserves the
 * cross-node false-sharing protection.  Set 0 to force a WHOLE-buffer inode
 * write — a instrumented diagnostic for the dir_reuse_coherency durable inode-alloc
 * REVERT (node2's own contiguous inode chunk partially free on disk: the
 * partial write may skip a freshly-allocated-but-checkpointed inode's sector,
 * leaving its chunk-init free di_mode durable).
 */
int mxfs_partial_iwrite = 1;
module_param_named(partial_iwrite, mxfs_partial_iwrite, int, 0644);
MODULE_PARM_DESC(partial_iwrite,
                 "Partial-sector inode-cluster writes: 1=on (default),"
                 "0=force whole-buffer write (diagnostic)");

/*
 * instrumented INSTRUMENT — does a SOLE SURVIVOR whole-write inode clusters
 * that carry slots it has no authority for?
 *
 * mxfs_submit_partial_inode_write() is the cross-node false-sharing
 * protection: it omits the sectors of in-core inodes this node released to a
 * peer (i_dlm_mode == NL, not logged this round), because our cached image of
 * those is stale prior-tenure and whole-writing the cluster reverts the peer's
 * durable inode.  It also carries P218-CLUSTER-AUTHORITY, the always-on
 * detector for unauthorised passenger slots.
 *
 * BOTH are switched off by a single test at the top of that function:
 * mxfs_v5_dlm_is_single_node(), which is DYNAMIC MEMBERSHIP.  So from the
 * instant a two-node cluster's peer leaves, the survivor resumes whole-buffer
 * inode-cluster writes AND the detector that would have noticed stops running
 * -- the same "the probe is unreachable in exactly the branch that matters"
 * shape that hid D-0949 for the whole campaign.
 *
 * 0.83.3 (D-0955): THE PREDICATE IS THE FIX, and this is its A/B switch.
 * A mount that has NEVER had a peer gives up nothing by whole-writing: no
 * other writer ever existed, so every cached slot is its own.  A sole
 * survivor is a different animal: it still holds the images it cached while
 * a peer owned slots in the same cluster, and no BAST will ever arrive to
 * refresh them.  With this at 1 (the default) a sole survivor takes the
 * partial path exactly as it did under multi-node membership -- the
 * un-logged slots it has no write tenure for are masked out of the write
 * (P218-PASSENGER-SKIP) and the detector keeps running.  0 restores the
 * pre-fix whole-buffer behaviour for a same-filesystem, same-age comparison
 * (tests/d0946_disklive_knob_vs_aging.sh alternates it in place).
 *
 * Measured before the fix (2/tcp, clean unmount and death):
 * the six unauthorised passenger slots the record was filed on were the
 * mkfs realtime inodes 129/130 riding the root cluster -- reserved, never
 * owned by the peer, not stale.  Four workload shapes with the platter probe
 * (mxfs_dino_clobber_probe) on every cluster write found zero slots behind
 * the platter; the mixed-cluster precondition (a peer's live inode beside
 * this node's cached free image in one cluster) could not be produced
 * because the allocator refuses a peer's just-freed numbers while they cool.
 * The mechanism is still open by code reading -- cooling ends -- so the
 * gate is closed on the predicate rather than left to the allocator.
 */
int mxfs_partial_iwrite_sole = 1;
module_param_named(partial_iwrite_sole, mxfs_partial_iwrite_sole, int, 0644);
MODULE_PARM_DESC(partial_iwrite_sole,
                 "Sole survivor keeps the partial inode-write path (masks "
                 "un-logged slots it has no write tenure for): 1=on "
                 "(default), 0=pre-0.83.3 whole-buffer write for A/B");
EXPORT_SYMBOL(mxfs_partial_iwrite_sole);
