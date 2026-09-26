// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- coherent inode reloads at iget
 */
#define MXFS_TU_ID 6	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * FIX-B — lookup-iget ENOENT sticky-stale cluster buffer.
 *
 * r11 dlm_scaling: node4 resolved .dlm_scaling's dirent (inum=2554, created
 * by node1 seconds earlier) but xfs_iget returned -ENOENT for the ENTIRE 64s
 * window (P26-IGET-FAIL at teardown still failing) while nodes 2/3 iget'd the
 * same inum fine -> the platter was current; node4's CACHED inode-cluster
 * buffer (XBF_DONE from an earlier read when the inum was free) kept serving
 * the FREE image, and nothing on the miss path revalidates it (node4 never
 * acquires that AG, so the AG-gen hooks never fire).  On a multi-node
 * dirent-resolved ENOENT, invalidate the cluster buffer (same safety rules as
 * the owner-evict: skip pinned/dirty/delwri) so the retry FUA-cold-reads the
 * creator's destaged dinode.  Returns 1 if a buffer was invalidated (caller
 * should retry the iget), 0 otherwise.
 */
int
mxfs_dlm_iget_miss_reload(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
	extern int xfs_imap(struct xfs_perag *, struct xfs_trans *,
			    xfs_ino_t, struct xfs_imap *, uint);
	struct xfs_perag	*pag;
	struct xfs_imap		imap;
	struct xfs_buf		*bp = NULL;
	int			ret = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ino));
	if (!pag)
		return 0;
	memset(&imap, 0, sizeof(imap));
	if (xfs_imap(pag, NULL, ino, &imap, 0) == 0 && imap.im_len &&
	    xfs_buf_incore(mp->m_ddev_targp, imap.im_blkno,
			   imap.im_len, XBF_TRYLOCK, &bp) == 0 && bp) {
		struct xfs_buf_log_item *bip = bp->b_log_item;

		/*
		 * PROVEN BY INSTRUMENT (r3 dlm_scaling node6 got=0,
		 * run_dlm_scaling_20260704T154337Z): the invalidate below is
		 * USELESS when any OTHER slot's inode log item sits on this
		 * cluster buffer's li_list — the retry's FUA re-read is then
		 * captured by the P91 logged-buffer guard (P91-FUA-SKIP-LOGGED
		 * daddr=33491808 li_empty=0 ×10 interleaved with the
		 * P12-IGETMISS-RELOAD loop), which re-serves the SAME stale
		 * in-core image and does not set _XBF_FUA_FRESH → the ladder
		 * spins invalidate→P91-capture→ENOENT forever and mkdir -p
		 * fails (parent_ls=[]).  Only take the whole-buffer invalidate
		 * when NO slot is logged (li_list empty); otherwise fall
		 * through to the FIX-E slot-level FUA patch, which is exactly
		 * the tool for a partially-logged cluster buffer.
		 */
		if (list_empty(&bp->b_li_list) &&
		    (bp->b_flags & XBF_DONE) &&
		    !(bp->b_flags & XBF_STALE) &&
		    !xfs_buf_ispinned(bp) &&
		    !(bp->b_flags & _XBF_DELWRI_Q) &&
		    !(bip && test_bit(XFS_LI_DIRTY, &bip->bli_item.li_flags)) &&
		    !(bip && test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags))) {
			bp->b_flags &= ~(XBF_DONE | _XBF_FUA_FRESH);
			ret = 1;
		}
		/*
		 * FIX-E: SLOT-LEVEL FUA PATCH.  The invalidate above is
		 * necessary but NOT sufficient: the retry's re-read can be
		 * captured by the logged-buffer guard when ANOTHER
		 * slot's inode log item sits on this cluster buffer's li_list
		 * (P91-FUA-SKIP-LOGGED li_empty=0) — the guard serves the
		 * in-core image in place, so OUR target slot stays stale
		 * forever (PROVEN: 64× P12-IGETMISS-RELOAD/P91 cycle,
		 * run_dlm_scaling_20260704T094645Z; platter had the winner's
		 * dir 0x41ed while the served slot read 0x0).  The guard's
		 * authority claim is per-LOGGED-SLOT, not per-buffer: patch
		 * JUST the target ino's slot bytes from a FUA read of the
		 * platter — unless the target itself is locally logged (then
		 * local core IS authoritative and iget's failure is genuine).
		 */
		if (!ret && (bp->b_flags & XBF_DONE) &&
		    !(bp->b_flags & XBF_STALE) && bp->b_addr &&
		    imap.im_boffset + mp->m_sb.sb_inodesize <=
							BBTOB(bp->b_length)) {
			struct xfs_log_item	*lip;
			bool			target_logged = false;

			list_for_each_entry(lip, &bp->b_li_list, li_bio_list) {
				if (lip->li_type == XFS_LI_INODE) {
					struct xfs_inode_log_item *ilip =
						container_of(lip,
						    struct xfs_inode_log_item,
						    ili_item);
					if (ilip->ili_inode &&
					    ilip->ili_inode->i_ino == ino) {
						target_logged = true;
						break;
					}
				}
			}
			if (!target_logged) {
				extern int mxfs_pal_scsi_read_fua_bdev(
					struct block_device *, uint64_t,
					void *, uint32_t);
				uint32_t	blen = BBTOB(bp->b_length);
				void		*tmp = kmalloc(blen, GFP_NOFS);

				if (tmp) {
					uint64_t lba = (uint64_t)imap.im_blkno +
					    mp->m_ddev_targp->bt_sector_offset;

					if (mxfs_pal_scsi_read_fua_bdev(
						mp->m_ddev_targp->bt_bdev,
						lba, tmp, blen) == 0) {
						struct xfs_dinode *tdip =
						    (struct xfs_dinode *)
						    ((char *)tmp +
						     imap.im_boffset);

						if (be16_to_cpu(tdip->di_magic)
						    == MXFS_DINODE_MAGIC) {
							memcpy((char *)bp->b_addr
							    + imap.im_boffset,
							    tdip,
							    mp->m_sb.sb_inodesize);
							ret = 2;
							{
							static atomic_t p13sp =
								ATOMIC_INIT(0);
							if (atomic_inc_return(&p13sp) <= 400)
								mxfs_probe("mxfs: P13-SLOTPATCH ino=%llu daddr=%lld boff=%u disk_mode=0%o — target slot FUA-patched into logged cluster buf\n",
								    (unsigned long long)ino,
								    (long long)imap.im_blkno,
								    imap.im_boffset,
								    be16_to_cpu(tdip->di_mode));
							}
						}
					}
					kfree(tmp);
				}
			}
		}
		xfs_buf_relse(bp);
	}
	xfs_perag_put(pag);
	if (ret) {
		static atomic_t p12ig = ATOMIC_INIT(0);
		if (atomic_inc_return(&p12ig) <= 400)
			mxfs_probe("mxfs: P12-IGETMISS-RELOAD ino=%llu daddr=%lld — dirent-resolved ENOENT; cluster buf invalidated, retrying iget\n",
				(unsigned long long)ino,
				(long long)imap.im_blkno);
	}
	return ret;
}

/*
 * FIX-D: dirent-resolved iget failure VISIBILITY NUDGE.
 *
 * PROVEN (run_dlm_scaling_20260704T075050Z): the .dlm_scaling mkdir-race
 * loser's iget of the winner's freshly-created dir ino returned -ENOENT —
 * its in-core shell was the dead prior incarnation (mode=0, P4ST dangler)
 * and the platter was one MORE generation behind (a live reg-file image;
 * the winner's create existed only in its log; di_gen did NOT change
 * across the realloc, so gen guards see one incarnation).  The winner's
 * BAST->drain->iflush->release chain freshens the platter in ~7ms
 * (P-DIRIFLUSH + P51-REL drain_ms=7), and peers whose PR grant arrived
 * after publication got the dinode MIRROR (P74-GRANT have_mirror=1
 * prov=1) and recovered — but the loser's early attempts got no mirror,
 * adopted the stale platter (P34D src=fua), and nothing retried: mkdir -p
 * failed, the node scored got=0 (the dlm_scaling/dlm_fairness/drc
 * fresh-inode visibility family).
 *
 * The nudge: acquire the ino's inode-DLM grant in PR by NUMBER — this
 * BASTs the creator (EX-cached there), forcing its dinode iflush +
 * release, and provisions the mirror on our grant — then release it and
 * let the caller retry iget (the mirror/adopt machinery then serves the
 * fresh incarnation).  Always worth one more retry on a multi-node mount:
 * even a failed acquire (EDEADLK/timeout) usually means the creator is
 * mid-drain.  The caller bounds the retries.
 */
int
mxfs_dlm_iget_visibility_nudge(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
	int	rc;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	rc = mxfs_v5_dlm_inode_lock(mp->m_mxfs_dlm, ino, MXFS_LOCK_PR,
				    NULL);
	if (rc == 0)
		mxfs_v5_dlm_inode_unlock(mp->m_mxfs_dlm, ino);
	/* ICLUSTER: with cluster granularity a REG
	 * creator's cached EX lives on the CLUSTER resource — the per-inode
	 * nudge above finds an empty slot and BASTs nobody.  We cannot know
	 * S_ISREG here (iget failed), so also PR-nudge the ino's cluster:
	 * BASTs a cluster-EX creator into dinode iflush + release exactly
	 * like the per-inode nudge; the follow-up unlock is a release_check
	 * (grant retained unless a peer waits).  Rare recovery path — the
	 * extra acquire is noise. */
	if (mxfs_icluster_dlm &&
	    mxfs_v5_dlm_transport_caw(mp->m_mxfs_dlm)) {
		int crc = mxfs_iclus_lock(mp, ino, MXFS_LOCK_PR, NULL);

		if (crc == 0)
			(void)mxfs_iclus_unlock(mp, ino, MXFS_LOCK_PR, false);
	}
	{
		static atomic_t p13vn = ATOMIC_INIT(0);

		if (atomic_inc_return(&p13vn) <= 400)
			mxfs_probe("mxfs: P13-VISNUDGE ino=%llu lock_rc=%d — dirent-resolved iget failed; PR-nudged creator publish, retrying iget\n",
				(unsigned long long)ino, rc);
	}
	return 1;
}
EXPORT_SYMBOL(mxfs_dlm_iget_visibility_nudge);

/*
 * FIX-D v2: DEAD-SHELL reload for dirent-resolved iget failures.
 *
 * PROVEN (run_dlm_scaling_20260704T081037Z): the raw-DLM nudge above fired
 * (37×, lock_rc=0) but could not converge — the loser's failure was a LIVE
 * in-core mode-0 shell (P-IGET-ENOENT incore_mode=0 reclaimable=0, the P4ST
 * dangler: a prior-incarnation inode whose reload once adopted the freed
 * platter state), while the PLATTER already had the winner's fresh dir
 * (fua_disk_mode=0x41ed) and the cached cluster buffer was stale + delwri-
 * queued (cached_disk_mode=0 flags=0x80020, un-invalidatable).  xfs_iget
 * cache-HITS the dead shell and check_free_state returns -ENOENT before any
 * buffer/mirror logic runs.  The raw nudge never touches the shell: the
 * mirror arrives at the DLM layer but nothing applies it.
 *
 * The fix: find the shell (same radix pattern as the evict-ring consumer),
 * take a VFS reference, and run the NORMAL reload machinery
 * (mxfs_dlm_reload_inode: grant acquire -> P74 mirror consume / FUA read ->
 * P34D adopt -> P-RELOAD-IOPS-REWIRE resurrects mode 0 -> dir, proven in
 * the dlm_fairness face-A trace).  On success the caller's iget retry
 * cache-hits a live inode.
 */
int
mxfs_dlm_iget_shell_reload(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	struct inode		*vip = NULL;
	int			acted = 0;

	if (!mp->m_mxfs_dlm || mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return 0;
	pag = xfs_perag_get(mp, XFS_INO_TO_AGNO(mp, ino));
	if (!pag)
		return 0;
	mxfs_ici_lock(pag);
	ip = radix_tree_lookup(&pag->pag_ici_root, XFS_INO_TO_AGINO(mp, ino));
	if (ip && ip->i_ino == ino) {
		spin_lock(&ip->i_flags_lock);
		/* A reclaimable/new shell is the recycle path's job;
		 * only grab a live instantiated shell. */
		if (!(ip->i_flags & (XFS_IRECLAIMABLE | XFS_INEW |
				     XFS_IRECLAIM)))
			vip = igrab(VFS_I(ip));
		spin_unlock(&ip->i_flags_lock);
	}
	spin_unlock(&pag->pag_ici_lock);
	xfs_perag_put(pag);
	if (ip && !vip) {
		/*
		 * FIX-D v3: a shell EXISTS but igrab failed — it is
		 * mid-teardown (VFS I_FREEING/I_CLEAR: unlinked, waiting on
		 * background inodegc/reclaim).  PROVEN (ds 114453Z): the
		 * mkdir-race loser's iget cache-HITS this mode-0 shell for
		 * >2 full retry cycles (15 nudges) because inodegc never got
		 * to it under load.  Force the queued inactivations through
		 * so the shell becomes reclaimable and the retry's iget takes
		 * the recycle path against the (nudge-published)
		 * platter.  Retry-worthy.
		 */
		extern int xfs_inodegc_flush(struct xfs_mount *);
		static atomic_t p13gc = ATOMIC_INIT(0);

		(void)xfs_inodegc_flush(mp);
		if (atomic_inc_return(&p13gc) <= 400)
			mxfs_probe("mxfs: P13-GCFLUSH ino=%llu — mid-teardown shell blocked iget; inodegc flushed, retrying\n",
				(unsigned long long)ino);
		/* daf50d34 (mkdir_storm r3 HIT root): return 2, not 1,
		 * so the lookup retry loop can tell "waiting on guaranteed-
		 * progress local teardown" apart from the bounded nudge/
		 * reload paths.  A mid-teardown shell ALWAYS clears (evict/
		 * inodegc completes); giving up after the shared 8-try
		 * (~360ms) budget turned a transient wait into a durable
		 * ENOENT on a live cross-node dirent — test1's path walk of
		 * the fresh .mkdir_storm failed twice (P26-IGET-FAIL ×2,
		 * 16 GCFLUSH), its mkdir died ENOENT, and the round-3
		 * dirent was never created (the "node1 missing" storm HIT).
		 * The shell cleared ~5s later; the deep inodegc backlog was
		 * 18 just-unlinked subdirs' DLM teardowns. */
		return 2;
	}
	if (!vip)
		return 0;

	if (VFS_I(ip)->i_mode == 0 || ip->i_dlm_stale) {
		mxfs_dlm_reload_inode(ip, XFS_DIR3_FT_UNKNOWN, true);
		acted = (VFS_I(ip)->i_mode != 0);
		{
			static atomic_t p13sr = ATOMIC_INIT(0);

			if (atomic_inc_return(&p13sr) <= 400)
				pr_warn("mxfs: P13-SHELLRELOAD ino=%llu mode_after=0%o acted=%d — dead-shell reload for dirent-resolved iget\n",
					(unsigned long long)ino,
					VFS_I(ip)->i_mode, acted);
		}
	}
	iput(vip);
	return acted;
}
EXPORT_SYMBOL(mxfs_dlm_iget_shell_reload);
bool
mxfs_drain_ilock_read(struct xfs_inode *ip)
{
	unsigned int	waited_ms = 0;

	while (!down_read_trylock(&ip->i_lock)) {
		if (xfs_is_shutdown(ip->i_mount))
			return false;
		if (waited_ms >= MXFS_DRAIN_ILOCK_MAX_MS) {
			pr_warn("mxfs: P132-ILOCK-TIMEOUT ino=%llu waited_ms=%u cnt=%ld — i_lock unacquirable in release drain; shutdown (lock NOT released stale)\n",
				(unsigned long long)ip->i_ino, waited_ms,
				atomic_long_read(&ip->i_lock.count));
			xfs_force_shutdown(ip->i_mount,
					   SHUTDOWN_META_IO_ERROR);
			return false;
		}
		msleep(2);
		waited_ms += 2;
		if (waited_ms == 5000 || (waited_ms % 30000) == 0)
			pr_warn("mxfs: P132-ILOCK-STUCK ino=%llu waited_ms=%u rd_held=%d cnt=%ld wr_last=%pS pid=%d comm=%s rd_last=%pS pid=%d comm=%s un_last=%pS\n",
				(unsigned long long)ip->i_ino, waited_ms,
				atomic_read(&ip->i_mxfs_ilk_rd_held),
				atomic_long_read(&ip->i_lock.count),
				(void *)ip->i_mxfs_ilk_wr_ret,
				ip->i_mxfs_ilk_wr_pid, ip->i_mxfs_ilk_wr_comm,
				(void *)ip->i_mxfs_ilk_rd_ret,
				ip->i_mxfs_ilk_rd_pid, ip->i_mxfs_ilk_rd_comm,
				(void *)ip->i_mxfs_ilk_un_ret);
	}
	return true;
}

/* ═════════════════════════════════════════════════════════════════════════
 * ICLUSTER mediating layer — Phase 1 CORE.
 * Full design: DLM_PLAN.md "ICLUSTER PLAN"; review-endorsed batching pivot.
 *
 * One on-disk DLM resource per XFS inode cluster (MXFS_LTYPE_ICLUSTER,
 * base = ino & ~(inodes_per_cluster-1)) mediates ALL regular-file dinode
 * coherence.  This layer owns the per-cluster local refcounts; the
 * existing per-inode i_dlm_* machinery sits above it unchanged, and the
 * v5/caw layers below it move the actual slot.
 *
 * ⚠ mxfs.icluster_dlm MUST STAY 0 until BOTH of these land (next steps in
 * state.md): (1) the BAST fan-out that invalidates every covered cached
 * inode before the on-disk release, and (2) the call-site routing in
 * ilock_begin/bast_process/inactive.  With the knob off this layer is
 * inert scaffolding.
 * ═════════════════════════════════════════════════════════════════════════ */

int mxfs_icluster_dlm;
/* 0444 (load-time only): a runtime flip would let inodes acquired via
 * one path release via the other (leaked slot / spurious WARN).  Set via
 * modprobe/insmod parameter; prep reloads the module each deploy. */
module_param_named(icluster_dlm, mxfs_icluster_dlm, int, 0444);
MODULE_PARM_DESC(icluster_dlm,
	"Inode-cluster DLM granularity for regular files: 0=per-inode "
	"(default; ICLUSTER wiring incomplete), 1=cluster resources");
