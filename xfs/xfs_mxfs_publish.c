// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- publishing unpublished inodes and directories
 */
#define MXFS_TU_ID 22	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"
int mxfs_creator_baseline_stamp;
module_param_named(creator_baseline_stamp, mxfs_creator_baseline_stamp, int, 0644);
MODULE_PARM_DESC(creator_baseline_stamp,
	"stamp the dir staleness baselines when a self-created dir takes its first real EX grant (bit0=dir_valid_epoch, bit1=cached_grant_gen); 0=pre-fix sentinels");

/* ─── deferred-publish ─── */

/*
 * Grant a brand-new inode (XFS_IGET_CREATE) its DLM lock locally, with no
 * on-disk CAW.  The creator owns the inode exclusively (it is invisible to
 * peers until its parent dirent is durable AND its slot is published), so we
 * grant EX, mark CACHED, bump the holder for the lock the caller is taking,
 * and link it onto the per-mount unpublished list.  See header + design note.
 */
void
mxfs_dlm_grant_local_new(
	struct xfs_inode	*ip,
	uint8_t			mode)
{
	struct xfs_mount	*mp = ip->i_mount;

	spin_lock(&ip->i_dlm_lock);
	/* P77: this function OVERWRITES mode/state
	 * unconditionally.  If the struct is a REUSED in-core inode with
	 * live demote machinery (state DEMOTING/BAST, queued bast work,
	 * nonzero holders), the overwrite orphans that machinery — a
	 * candidate producer of run68's phantom-EX wedge.  Shout first. */
	if (ip->i_dlm_state != MXFS_DLM_ISTATE_NONE ||
	    ip->i_dlm_ex_holders || ip->i_dlm_pr_holders ||
	    ip->i_dlm_mode != MXFS_LOCK_NL) {
		static atomic_t p77_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p77_n) <= 3000)
			pr_warn("mxfs: P77-GRANTNEW-CLOBBER ino=%llu prev_mode=%u prev_state=%u prev_ex=%u prev_pr=%u pin=%u work_busy=%d comm=%s\n",
				(unsigned long long)ip->i_ino,
				ip->i_dlm_mode, ip->i_dlm_state,
				ip->i_dlm_ex_holders, ip->i_dlm_pr_holders,
				ip->i_dlm_pin_count,
				work_busy(&ip->i_dlm_bast_work),
				current->comm);
	}
	/* Creator-exclusive: hold EX regardless of the requested mode. */
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_mode = MXFS_LOCK_EX;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	/* EX at the mode level, provably NOT durable — no CAS ever ran
	 * for this inode, there is no slot to prove anything with.  Becomes
	 * provable only when the lazy publish worker's own acquire result is
	 * installed (UNPUBLISHED_EX -> DURABLE_EX). */
	mxfs_inode_authority_note_unpublished_locked(ip, MXFS_SITE);
	/* (design review DLM-epoch guard): fresh EX tenure for a new inode. */
	mxfs_ex_epoch_churn_check(ip, MXFS_SITE);
	ip->i_mxfs_ex_grant_seq = atomic64_inc_return(&mxfs_ex_epoch);
	/* stamp fresh-EX acquire time for MHT batching */
	ip->i_dlm_ex_acquire_ns = ktime_get_ns();
	ip->i_dlm_tenure_ops = 0;
	ip->i_dlm_tenure_firstop_ns = 0;
	/*
	 *  — BASELINE THE STALENESS TRACKERS AT CREATE.
	 *
	 * PROVEN (32/caw dirent_durability, test29, in-window):
	 *   P195-STALE-BASE-ALREADY-DIRTY ino=27263105 grant_epoch=2 valid_epoch=0
	 *       grant_gen=2019 cached_gen=0 gen_moved=1 dirty_seq=359 ex_grant_seq=359
	 *
	 * This path creates an inode WITHOUT a real DLM acquire (deferred
	 * publish), and it stamped the tenure counter but left BOTH staleness
	 * baselines at their "never set" sentinel: i_dlm_cached_grant_gen = 0
	 * and i_dlm_dir_valid_epoch = 0.  Every detector that asks "has this
	 * lock changed hands / has a peer published since my base loaded?"
	 * compares against those, and several are explicitly gated on
	 * `cached_grant_gen != 0` — so for a directory THIS node created they
	 * are inert for the lifetime of the in-core inode, no matter how many
	 * times peers take the lock and modify it.  Above: the master is at
	 * generation 2019 and epoch 2 while our baselines still read 0/0.
	 *
	 * Consequence: the creator keeps a base that no guard will ever call
	 * stale, adds its own child to it, and the write-side backstop then
	 * (correctly) refuses to publish the behind-disk result — so the entry
	 * is dropped while mkdir(2) returned 0.  That is the silent-loss path.
	 *
	 *  /— THE STAMP CANNOT HAPPEN HERE.  Proven,
	 * not suspected, and the block that used to sit here is deleted:
	 *
	 *  1. It was DEAD.  The gate was S_ISDIR(VFS_I(ip)->i_mode), but the
	 *     only caller is xfs_iget_cache_miss under XFS_IGET_CREATE, where
	 *     i_mode is still 0 (xfs_init_new_inode sets it later, and even
	 *     i_generation is only assigned at xfs_icache.c:1902).  Probe
	 *     P209-CREATE-BASELINE, placed INSIDE the block, read 0 on every
	 *     node across a full 32-node dirent_durability run.
	 *  2. It could not have worked if reached.  This path creates the inode
	 *     WITHOUT a real DLM acquire (deferred publish), so the DLM has no
	 *     grant record for the number and both queries return 0 — the
	 *     `if (bgg)` / `if (bep)` guards skipped and the sentinels survived.
	 *  3. It was a latent sleep-in-atomic.  We are inside
	 *     spin_lock(&ip->i_dlm_lock) here (unlocked ~90 lines below), and
	 *     mxfs_v5_dlm_inode_grant_gen -> mxfs_dlm_caw_grant_seq32 ->
	 *     caw_grant_meta_seq takes a SLEEPING mutex (dlm/dlm_caw.c:1120).
	 *     Same class as the 2/tcp wedge.
	 *
	 * The baseline is established instead at the moment the values first
	 * EXIST — this node's first real EX grant for the inode, i.e. the
	 * publish — by mxfs_dlm_creator_baseline_query/_apply (sites 1-3).  See
	 * the mxfs_creator_baseline_stamp block comment for why that point is
	 * the only one where stamping cannot launder a peer update.
	 */
	{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
	ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
	mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	if (mode == MXFS_LOCK_EX) {
		ip->i_dlm_ex_holders++; MXFS_DLMTR_H(ip);
		mxfs_exh_stamp_locked(ip);
	} else {
		ip->i_dlm_pr_holders++; MXFS_DLMTR_H(ip);
	}
	spin_unlock(&ip->i_dlm_lock);

	/* v0.5.4 fresh cache-miss create — no peer can hold a stale
	 * reference to this ino's incarnation (see i_mxfs_reused_create). */
	ip->i_mxfs_reused_create = false;

	spin_lock(&mp->m_mxfs_unpub_lock);
	if (!ip->i_dlm_unpublished) {
		ip->i_dlm_unpublished = true;
		/* v0.5.6: parent unknown until xfs_create/xfs_symlink records
		 * it post-dirent; 0 = matched by every scoped BAST drain. */
		ip->i_mxfs_unpub_parent = 0;
		list_add_tail(&ip->i_dlm_unpub_link, &mp->m_mxfs_unpub_list);
	}
	spin_unlock(&mp->m_mxfs_unpub_lock);

	mxfs_idbg("mxfs: deferred-publish GRANT-LOCAL ino=%llu mode=%u\n",
		(unsigned long long)ip->i_ino, mode);
}

/*
 * ROOT FIX (cross_write_read empty-md5, PROVEN BY INSTRUMENT via
 * P128-PUBLISH-BAIL + P103-RELOAD-REUSE-ADOPT): re-arm deferred-publish for a
 * CREATE that was satisfied from the inode CACHE (recycle of an IRECLAIMABLE
 * freed incarnation, reset_inode_for_create of a live stale one, or a freed
 * mode==0 cache hit).  Those inodes keep the PRIOR incarnation's DLM fields:
 * i_dlm_mode=EX with i_dlm_unpublished=false — but the prior incarnation's
 * on-disk slot was RELEASED by xfs_inactive at free time.  The new create then
 * runs on a PHANTOM in-core EX: mxfs_dlm_publish_inode fast-bails on the clear
 * unpub flag, no slot is ever acquired, a peer's acquire of the reused number
 * grants CLEAN (empty slot, no BAST), and the creator is never forced to flush
 * the new dinode → the peer adopts it at its not-yet-durable size=0 image
 * (readers see an existing file as empty).
 *
 * Restore the brand-new-inode invariant (creator-exclusive local EX, on the
 * unpublished list) exactly as mxfs_dlm_grant_local_new does for cache-miss
 * creates — WITHOUT touching the holder counts (the caller's xfs_ilock
 * accounts those normally).  xfs_create's publish-on-create then acquires the
 * real slot.  A peer that meanwhile holds a (stale) slot on this number is
 * BASTed by that EX acquire and invalidates — also coherent.
 */
void
mxfs_dlm_rearm_unpublished(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			rearmed = false;

	/* 0.83.3 (D-0955) / 0.87.16: every mount's recycled-number create gets
	 * its unpublished-EX tenure like any member's -- a membership early-out
	 * here left s583c's directory at NL with the dead peer's stale mark,
	 * and a never-multi one left every lone mount's inode without the
	 * authority its logged images need at replay. */
	if (!mp->m_mxfs_dlm)
		return;

	spin_lock(&ip->i_dlm_lock);
	if (ip->i_dlm_mode != MXFS_LOCK_EX)
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_mode = MXFS_LOCK_EX;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	/* a re-armed unpublished incarnation is local-only EX — see
	 * mxfs_dlm_grant_local_new.  Any tenure the PREVIOUS incarnation of
	 * this inode number proved is dead here. */
	mxfs_inode_authority_note_unpublished_locked(ip, MXFS_SITE);
	/* Fresh incarnation = fresh EX tenure (epoch guard). */
	mxfs_ex_epoch_churn_check(ip, MXFS_SITE);
	ip->i_mxfs_ex_grant_seq = atomic64_inc_return(&mxfs_ex_epoch);
	ip->i_dlm_ex_acquire_ns = ktime_get_ns();
	ip->i_dlm_tenure_ops = 0;
	ip->i_dlm_tenure_firstop_ns = 0;
	/* Don't clobber a pending BAST downconvert on a real prior slot. */
	if (ip->i_dlm_state == MXFS_DLM_ISTATE_NONE)
		{ u8 dtr_om = ip->i_dlm_mode, dtr_os = ip->i_dlm_state;
		ip->i_dlm_state = MXFS_DLM_ISTATE_CACHED;
		mxfs_dlmtr_rec(ip, dtr_om, dtr_os, MXFS_SITE); }
	spin_unlock(&ip->i_dlm_lock);

	/* v0.5.4 reused in-core incarnation — peers may still name
	 * this ino from the prior incarnation; keep the synchronous
	 * unpublished-EX backstop armed (see i_mxfs_reused_create). */
	ip->i_mxfs_reused_create = true;

	/* Option B: cache-hit CREATE = new incarnation — drop the prior
	 * life's dir-base baseline so the publish stamp (creator sites) can
	 * establish a fresh one (see the reset_inode_for_create sibling). */
	if (mxfs_dir_adopt_at_acquire) {
		ip->i_dlm_dir_valid_epoch = 0;
		ip->i_dlm_dir_valid_incarn = 0;
		WRITE_ONCE(ip->i_dlm_base_valid, 0);
		ip->i_dlm_creator_base_state = MXFS_CBASE_UNSET;
	}

	spin_lock(&mp->m_mxfs_unpub_lock);
	if (!ip->i_dlm_unpublished) {
		ip->i_dlm_unpublished = true;
		/* v0.5.6: parent unknown until xfs_create/xfs_symlink records
		 * it post-dirent; 0 = matched by every scoped BAST drain. */
		ip->i_mxfs_unpub_parent = 0;
		list_add_tail(&ip->i_dlm_unpub_link, &mp->m_mxfs_unpub_list);
		rearmed = true;
	}
	spin_unlock(&mp->m_mxfs_unpub_lock);

	if (rearmed)
		mxfs_probe_ratelimited(
		    "mxfs: P128-REARM-UNPUB ino=%llu dlm_mode=%u — cache-hit CREATE on reused inode, deferred-publish re-armed\n",
			(unsigned long long)ip->i_ino, ip->i_dlm_mode);
}

/*
 * Remove an inode from the unpublished list and clear the flag.  Returns true
 * if the inode WAS unpublished (caller must NOT do an on-disk release — there
 * is no slot).  Safe no-op (returns false) if not unpublished.
 */
bool
mxfs_dlm_unpublish_drop(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	bool			was;

	if (!mp->m_mxfs_dlm)
		return false;

	spin_lock(&mp->m_mxfs_unpub_lock);
	was = ip->i_dlm_unpublished;
	if (was) {
		list_del_init(&ip->i_dlm_unpub_link);
		ip->i_dlm_unpublished = false;
	}
	spin_unlock(&mp->m_mxfs_unpub_lock);
	return was;
}

/*
 * Publish (acquire a real on-disk EX slot for) every inode on the unpublished
 * list.  Called from a peer BAST (inode or AG): the peer is blocked on the
 * lock that BAST'd us and cannot reach any of our locally-granted inodes until
 * we release it; we publish them all first so the peer's subsequent ilock of
 * each one BASTs us and we flush its data before the peer reads it.
 *
 * We publish BY INODE NUMBER (read under the list lock), so the ip pointer is
 * never dereferenced after the lock is dropped — no UAF vs concurrent reclaim.
 * A racing reclaim either (a) drops the inode first (we skip it; its data is
 * durable, peer reads disk) or (b) loses the claim race and later releases the
 * slot we acquired (peer reads durable disk).  Both outcomes are coherent.
 */
/*
 * v0.5.6: scope predicate for the BAST-side
 * publish drain.  A peer blocked on the lock we are releasing can reach
 * an unpublished inode only by (a) reading the released DIRECTORY's
 * dirents and chasing a child ino — covered by the parent_ino scope —
 * or (b) walking the released AG's AGI/inobt (inode alloc, bulkstat) —
 * covered by the agno scope.  Entries whose parent is unrecorded
 * (parent == 0: tmpfile, whiteout, or the tiny window between
 * grant_local_new and xfs_create's assignment) match EVERY scope, so a
 * missed assignment degrades to over-publishing, never to the
 * peer-acquires-empty-slot hole.  Called under m_mxfs_unpub_lock.
 */
static bool
mxfs_dlm_unpub_in_scope(
	struct xfs_mount	*mp,
	struct xfs_inode	*ip,
	xfs_ino_t		parent_ino,
	xfs_agnumber_t		agno)
{
	if (ip->i_mxfs_unpub_parent == 0)
		return true;
	if (parent_ino != 0 && ip->i_mxfs_unpub_parent == parent_ino)
		return true;
	if (agno != NULLAGNUMBER &&
	    XFS_INO_TO_AGNO(mp, ip->i_ino) == agno)
		return true;
	return false;
}

/*
 * v0.5.5: pop-and-claim loop shared by the
 * inline drain and the parallel drain workers.  Pops one inode at a
 * time off m_mxfs_unpub_list (clear-then-acquire — safe here because
 * every caller of mxfs_dlm_publish_unpublished holds the peer blocked
 * on the BAST'd lock until the whole drain returns) and claims its
 * on-disk EX slot.  Safe to run concurrently from several workers:
 * each list entry is popped exactly once under m_mxfs_unpub_lock.
 * v0.5.6: pops only IN-SCOPE entries (see mxfs_dlm_unpub_in_scope) —
 * the 16-node whole-list drain (~8.7k claims/node, ~96k cluster-wide
 * vs the 65536-slot table) ground releases into minutes and starved
 * EX waiters into 120s timeouts (scaling_curve root cause 2).
 */
/*
 * FIX-I durability settle for one unpublished child (extracted from
 * the drain loop's pre_mode!=EX branch so the routed pre-pass in
 * mxfs_dlm_publish_unpublished can reuse it): make the child's inode-
 * cluster buffer platter-durable before a dir handoff exposes its name,
 * so a peer's clean grant cannot FUA-read a pre-icreate platter image.
 * Local and bounded (log_force + settle poll); takes no DLM locks.
 */
static void
mxfs_dlm_unpub_child_settle(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
{
	extern int xfs_imap(struct xfs_perag *,
			struct xfs_trans *, xfs_ino_t,
			struct xfs_imap *, uint);
	struct xfs_perag *fi_pag = xfs_perag_get(mp,
			XFS_INO_TO_AGNO(mp, ino));
	struct xfs_imap	fi_imap;
	struct xfs_buf	*fi_bp = NULL;

	memset(&fi_imap, 0, sizeof(fi_imap));
	if (fi_pag &&
	    xfs_imap(fi_pag, NULL, ino, &fi_imap, 0) == 0 &&
	    fi_imap.im_len &&
	    xfs_buf_incore(mp->m_ddev_targp,
			   fi_imap.im_blkno,
			   fi_imap.im_len,
			   XBF_TRYLOCK, &fi_bp) == 0 &&
	    fi_bp) {
		struct xfs_buf_log_item *fi_bip =
				fi_bp->b_log_item;
		bool fi_dirty =
		    (fi_bp->b_flags & _XBF_DELWRI_Q) ||
		    xfs_buf_ispinned(fi_bp) ||
		    (fi_bip &&
		     (test_bit(XFS_LI_DIRTY,
			&fi_bip->bli_item.li_flags) ||
		      test_bit(XFS_LI_IN_AIL,
			&fi_bip->bli_item.li_flags))) ||
		    !list_empty_careful(
			&fi_bp->b_li_list);

		if (fi_dirty) {
			int fi_i;

			/* incore's hold survives the
			 * unlock; the flusher needs
			 * the lock */
			xfs_buf_unlock(fi_bp);
			xfs_log_force(mp, XFS_LOG_SYNC);
			xfs_ail_push_all(mp->m_ail);
			for (fi_i = 0; fi_i < 125; fi_i++) {
				fi_bip = fi_bp->b_log_item;
				if (!(fi_bp->b_flags &
				      (_XBF_DELWRI_Q |
				       XBF_WRITE)) &&
				    !xfs_buf_ispinned(fi_bp) &&
				    (!fi_bip ||
				     !test_bit(XFS_LI_IN_AIL,
				       &fi_bip->bli_item.li_flags)))
					break;
				if (fi_i % 25 == 24)
					xfs_ail_push_all(mp->m_ail);
				msleep(2);
			}
			{
				static atomic_t p15j_n =
					ATOMIC_INIT(0);
				if (atomic_inc_return(&p15j_n) <= 400)
					mxfs_probe("mxfs: P15J-PUBSKIP-FLUSH ino=%llu daddr=%lld waited_ms=%d settled=%d — evicted-unpublished child made durable before dir handoff\n",
						(unsigned long long)ino,
						(long long)fi_imap.im_blkno,
						fi_i * 2,
						fi_i < 125 ? 1 : 0);
			}
			xfs_buf_rele(fi_bp);
		} else {
			xfs_buf_relse(fi_bp);
		}
	}
	if (fi_pag)
		xfs_perag_put(fi_pag);
}
}

/*
 *  — CREATOR BASELINE STAMP (see mxfs_creator_baseline_stamp).
 *
 * Two entry points, because the publish sites differ in what they may do:
 *
 *  _query()  — SLEEPS.  Reads the DLM's post-claim epoch/grant-gen for `ino`.
 *              Both queries bottom out in caw_grant_meta_get/caw_grant_meta_seq,
 *              which take ctx->grant_meta_lock (a SLEEPING mutex, dlm_caw.c:1120).
 *              Call ONLY from sleepable context, never under a spinlock — the
 *              2/tcp wedge was exactly this shape (sleeping rwsem under
 *              pag_ici_lock).
 *  _apply()  — pure stores, no query, no allocation.  Safe under a spinlock, so
 *              a publish site that must stamp while holding m_mxfs_unpub_lock
 *              can hoist the _query() above the lock and apply inside it.
 *
 * The eligibility test lives in _apply() so every site enforces it identically.
 * i_mxfs_self_created is the load-bearing guard: it is set only by xfs_create's
 * success path and cleared by mxfs_dlm_bast_notify on the FIRST peer BAST, so
 * while it holds, no peer has requested this inode's lock and therefore no peer
 * can have published anything we could launder away.
 *
 * The stamped fields are not covered by ip->i_dlm_lock at their other write
 * sites either (the fast-path stamps at mxfs_dlm_ilock_begin and the adopt
 * stamp in mxfs_dlm_reload_inode both run after spin_unlock); they are tenure-
 * protected.  Here the inode is still unpublished and self-created, so this
 * node is the only possible writer.
 */
static void
mxfs_dlm_creator_baseline_apply(
	struct xfs_inode	*ip,
	uint32_t		bep,
	uint32_t		bgg,
	unsigned int		site)
{
	uint32_t		old_ep, old_gg;

	if (!ip || ip->i_ino == 0)
		return;
	if (!S_ISDIR(VFS_I(ip)->i_mode))
		return;
	/* A peer BAST would have cleared this; without it we cannot claim the
	 * in-core image is the authoritative successor. */
	if (!ip->i_mxfs_self_created)
		return;
	/* Only the never-established state is ours to fill.  A real adopt or a
	 * slow-path grant has already recorded a meaningful baseline; never
	 * overwrite one — that IS the laundering case.  Tracked as an EXPLICIT
	 * state rather than "the number is still 0" (design review's prescription):
	 * a legitimate baseline of epoch 0 is reachable, and inferring "never
	 * set" from the value cannot tell the two apart.
	 *
	 * i_dlm_cached_grant_gen is deliberately NOT part of this precondition.
	 * Measured 2/caw this session: a self-created dir can reach P195 with
	 * cached_gen=27 and valid_epoch=0 — the dir-EX fast path stamps the
	 * grant gen (mxfs_dlm_ilock_begin) independently of the epoch, so
	 * requiring both to be 0 would refuse the stamp in exactly the case
	 * that still loses the dirent. */
	if (ip->i_dlm_creator_base_state != MXFS_CBASE_UNSET)
		return;
	if (ip->i_dlm_dir_valid_epoch != 0)
		return;

	old_ep = ip->i_dlm_dir_valid_epoch;
	old_gg = ip->i_dlm_cached_grant_gen;
	/* State advances in BOTH arms — SEEN when the knob is off — so the probe
	 * below is a KNOB-INDEPENDENT exposure counter that fires exactly once
	 * per eligible inode in either arm.  A fix-gated exposure counter makes
	 * the reproducing arm report zero exposure, which is how first
	 * typeflip A/B nearly produced an unfalsifiable "pass". */
	if (mxfs_dir_adopt_at_acquire) {
		/*
		 * Option B (design review contract item 6) — the creator stamp is
		 * SUBORDINATED to the adopt-at-acquire machinery: at the first
		 * real EX grant of a self-created dir the in-core image is the
		 * authoritative successor (self_created still set = no peer has
		 * even requested the lock), so stamping (epoch, gen, valid) here
		 * is what makes the acquire gate's != compares meaningful — and
		 * what stops the gate's sentinel leg from adopting a
		 * not-yet-destaged disk image over the live create at the first
		 * fast-path serve.  mxfs.creator_baseline_stamp remains the A/B
		 * lever for the gate-off arm only.
		 */
		ip->i_dlm_creator_base_state = MXFS_CBASE_VALID;
		mxfs_dir_base_stamp(ip, bep, bgg, site);
	} else if (mxfs_creator_baseline_stamp) {
		ip->i_dlm_creator_base_state = MXFS_CBASE_VALID;
		if (mxfs_creator_baseline_stamp & MXFS_CBS_EPOCH) {
			ip->i_dlm_dir_valid_epoch = bep;
			ip->i_dlm_dir_valid_incarn = VFS_I(ip)->i_generation;
		}
		if (mxfs_creator_baseline_stamp & MXFS_CBS_GRANTGEN)
			ip->i_dlm_cached_grant_gen = bgg;
	} else {
		ip->i_dlm_creator_base_state = MXFS_CBASE_SEEN;
	}

	{
		static atomic_t p210n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p210n) <= 600)
			mxfs_probe("mxfs: P210-CREATOR-BASELINE ino=%llu site=%u bep=%u bgg=%u old_ep=%u old_gg=%u mask=%d state=%u — self-created dir reached its first real EX grant\n",
				(unsigned long long)ip->i_ino, site,
				bep, bgg, old_ep, old_gg,
				mxfs_creator_baseline_stamp,
				ip->i_dlm_creator_base_state);
	}
}

/* SLEEPS — see the block comment above. */
void
mxfs_dlm_creator_baseline_query(
	struct xfs_inode	*ip,
	unsigned int		site)
{
	struct mxfs_v5_dlm	*dlm;
	uint32_t		bep, bgg;

	if (!ip || ip->i_ino == 0 || !ip->i_mount)
		return;
	dlm = ip->i_mount->m_mxfs_dlm;
	if (!dlm || mxfs_v5_dlm_is_single_node(dlm))
		return;
	/* Cheap in-memory rejects before paying the grant_meta mutex.  These
	 * MUST mirror _apply's preconditions exactly, or the two arms pay
	 * different costs and the exposure counts stop being comparable. */
	if (!S_ISDIR(VFS_I(ip)->i_mode) || !ip->i_mxfs_self_created)
		return;
	if (ip->i_dlm_creator_base_state != MXFS_CBASE_UNSET)
		return;
	if (ip->i_dlm_dir_valid_epoch != 0)
		return;

	bep = mxfs_v5_dlm_inode_dir_epoch(dlm, ip->i_ino);
	bgg = mxfs_v5_dlm_inode_grant_gen(dlm, ip->i_ino);
	mxfs_dlm_creator_baseline_apply(ip, bep, bgg, site);
}

static unsigned int
mxfs_dlm_publish_drain_loop(
	struct xfs_mount	*mp,
	xfs_ino_t		parent_ino,
	xfs_agnumber_t		agno,
	xfs_ino_t		*seen_defer)	/* MXFS_PUB_SEEN_DEFER_MAX */
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	struct xfs_inode	*ip, *match;
	uint64_t		ino;
	unsigned int		n = 0;
	int			rc;
	/* inos this drain already deferred (live holder + failed
	 * claim).  Without the guard the relist->re-pop cycle busy-spins the
	 * drain worker (measured: 146s soft lockup on kworker/u11:18 while
	 * dir 131's handoff sat inside this loop and peers BAST-stormed). */
	unsigned int		n_defer = 0, di;
	/* step 5.3(d): provenance of the fallback cluster claim. */
	struct mxfs_grant_result pub_gres;
	uint64_t		pub_gen_snap = MXFS_AUTH_GEN_NONE;

	for (;;) {
		uint8_t		pre_mode = MXFS_LOCK_EX;
		uint8_t		pre_state = MXFS_DLM_ISTATE_CACHED;
		bool		pub_routed = false;

		ino = 0;
		match = NULL;
		spin_lock(&mp->m_mxfs_unpub_lock);
		list_for_each_entry(ip, &mp->m_mxfs_unpub_list,
				    i_dlm_unpub_link) {
			bool deferred = false;

			if (!mxfs_dlm_unpub_in_scope(mp, ip, parent_ino, agno))
				continue;
			for (di = 0; di < n_defer; di++)
				if (seen_defer[di] == ip->i_ino) {
					deferred = true;
					break;
				}
			if (deferred)
				continue;
			match = ip;
			break;
		}
		if (match) {
			list_del_init(&match->i_dlm_unpub_link);
			match->i_dlm_unpublished = false;
			ino = match->i_ino;
			/* P78: snapshot FS-layer lock state while the
			 * entry is provably alive (on-list under the lock).
			 * ICLUSTER: routability snapshotted here too — match
			 * may be freed once the spinlock drops. */
			pub_routed = mxfs_iclus_routed(match);
			if (pub_routed)
				/* the claim below is cluster-backed; the
				 * inode's release must route there too */
				match->i_dlm_routed_iclus = true;
			pre_mode = match->i_dlm_mode;
			pre_state = match->i_dlm_state;
		}
		spin_unlock(&mp->m_mxfs_unpub_lock);

		if (!match)
			break;
		if (ino == 0)
			continue;	/* reclaiming; disk durable, skip */

		/*
		 * FIX-28 — the P78 probe promoted to a guard.
		 * The publish exists to close the 16057 hazard: an UNPUBLISHED
		 * inode whose FS layer holds a live cached EX is invisible to
		 * the DLM, so a peer acquires it cleanly and both modify.  That
		 * hazard exists ONLY while the FS-layer mode is still EX.  When
		 * the pop-time snapshot shows the EX is already gone (released,
		 * demoted, evicted, or the number reused), claiming a master EX
		 * anyway creates a PHANTOM the FS layer never drives: run r4
		 * measured ~1000 such claims per node per suite (P78-PUB-PHANTOM),
		 * each a ghost holder that peers must break via the orphan-
		 * release path — grant delays, tds residual ghosts, and the
		 * dlm_scaling/fault setup-visibility flakes.  Skip the claim;
		 * a later re-acquire of the inode goes through the slow path
		 * (mode is not EX) which claims the on-disk lock properly.
		 */
		if (pre_mode != MXFS_LOCK_EX) {
			static atomic_t p78s_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p78s_n) <= 2000)
				mxfs_probe("mxfs: P78-PUB-SKIP ino=%llu pre_mode=%u pre_state=%u — FS-layer EX gone; phantom master claim skipped\n",
					(unsigned long long)ino,
					pre_mode, pre_state);
			/*
			 * FIX-I (PROVEN BY INSTRUMENT, 2/tcp r6 ino
			 * 0x883400): the skipped child lost its EX via VFS
			 * EVICTION (crash_consistency's drop_caches) — its
			 * icreate/dinode state may still be dirty-unwritten
			 * (CIL, AIL, or a reclaim-queued delwri cluster buf)
			 * while the dirent naming it becomes peer-visible via
			 * THIS dir handoff.  With the slot never claimed, a
			 * peer's acquire grants CLEANLY (no BAST to us, no
			 * mirror — P74-GRANT absent) and its FUA read pulls
			 * the PRE-ICREATE platter: prior-mkfs dinodes → uuid
			 * verifier reject → EFSCORRUPTED → iget retry ladder
			 * loops on the same platter → EIO (durable-vs-visible
			 * invariant hole).  Make the child's cluster durable
			 * BEFORE the handoff returns: the peer is blocked on
			 * the BAST'd dir until then.  Bounded; fires only when
			 * the cluster is provably not yet durable.
			 */
			mxfs_dlm_unpub_child_settle(mp, ino);
			continue;
		}

		if (pub_routed) {
			/*
			 * EAGER-DEMOTE PUBLISH — the
			 * routed replacement for the cluster EX claim that
			 * stood here.  Instrumented history, all measured on the
			 * 8/cawd board:
			 *   1. The claim (mxfs_iclus_lock EX) remote-waited
			 *      on peer-held clusters FROM THE BAST PIPELINE
			 *      and closed a cross-node bast-worker cycle
			 *      (470s P-WAIT-EXTEND wedges).
			 *   2. Under reader-PR contention it EDEADLK-failed
			 *      AFTER the pop — child delisted, no on-disk
			 *      claim, local EX intact: peers then clean-grant
			 *      the cluster and FUA-read the pre-flush platter
			 *      (the cwr exp="" stale-read class).
			 * Claiming is the wrong primitive for a routed child:
			 * the CLUSTER is legitimately shared.  What the
			 * handoff actually requires is that the platter be
			 * AUTHORITATIVE for the child before its name is
			 * peer-visible.  So: run the child's OWN per-inode
			 * demote pipeline (full data writeback + durable
			 * dinode + local NL + iclus release sweep) right
			 * here, in the drain worker — local, bounded,
			 * contention-independent.  No claim exists to fail;
			 * no invisible EX survives; the reader's clean grant
			 * reads correct bytes.  A live local holder aborts
			 * the release (P15 re-check) — re-list, and
			 * ilock_end's pending-BAST demote + the next publish
			 * converge it.
			 */
			struct xfs_inode *dip = NULL;
			bool run_bp = false;

			if (xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0,
				     &dip) == 0 && dip) {
				spin_lock(&dip->i_dlm_lock);
				dip->i_dlm_bast_pending = true;
				if (dip->i_dlm_demoter == NULL) {
					MXFS_SET_DEMOTER(dip);
					run_bp = true;
				}
				spin_unlock(&dip->i_dlm_lock);
				if (run_bp) {
					struct mxfs_dirdrain_task dde;

					mxfs_dirdrain_enter(&dde);
					mxfs_dlm_bast_process(dip);
					mxfs_dirdrain_exit(&dde);
					MXFS_CLEAR_DEMOTER(dip);
				}
				spin_lock(&dip->i_dlm_lock);
				if (dip->i_dlm_mode != MXFS_LOCK_NL) {
					static atomic_t ppedm_n =
						ATOMIC_INIT(0);
					int crc;

					spin_unlock(&dip->i_dlm_lock);
					/* Live local holder kept the grant —
					 * the demote cannot proceed.  Restore
					 * the OLD exclusion primitive for
					 * exactly this case: claim the
					 * cluster EX from THIS worker.  Safe
					 * now: the caller's batch wait
					 * is 5s-bounded, so a remote-waiting
					 * claim can no longer wedge the bast
					 * pipeline (it just lands late,
					 * detached).  On success the child is
					 * DLM-visible and peers BAST us as
					 * before. */
					/* fairness A/B: the claim
					 * fallback added EX pressure on the
					 * hottest cluster (fairness churns
					 * ONE shared cluster; every live-
					 * holder abort claimed it) — starved
					 * 2-3 nodes below 50 rounds.  The
					 * abort path already armed
					 * bast_pending, so the holder's
					 * ilock_end runs the full demote
					 * (durable + NL + sweep) within the
					 * op's remaining microseconds — the
					 * publish-equivalent, µs-deferred.
					 * Relist so the NEXT publish verifies
					 * convergence. */
					/* step 5.3(d), ruling coverage
					 * gap (i): this worker's OWN claim is
					 * the evidence that promotes the child
					 * from local-only EX to a durable
					 * tenure.  Snapshot the gen before the
					 * claim, install under i_dlm_lock. */
					pub_gen_snap = MXFS_AUTH_GEN_NONE;
					if (mxfs_pub_defer_claim) {
						spin_lock(&dip->i_dlm_lock);
						pub_gen_snap =
							dip->i_mxfs_auth_gen;
						spin_unlock(&dip->i_dlm_lock);
					}
					crc = mxfs_pub_defer_claim ?
						mxfs_iclus_lock(mp, ino,
							MXFS_LOCK_EX,
							&pub_gres) : -EAGAIN;
					if (crc == 0) {
						spin_lock(&dip->i_dlm_lock);
						mxfs_dlm_authority_install(dip,
							&pub_gres,
							pub_gen_snap, true,
							MXFS_SITE);
						spin_unlock(&dip->i_dlm_lock);
					}
					if (crc) {
						spin_lock(&mp->m_mxfs_unpub_lock);
						if (!dip->i_dlm_unpublished &&
						    dip->i_ino == ino) {
							dip->i_dlm_unpublished = true;
							dip->i_mxfs_unpub_parent =
								parent_ino;
							list_add_tail(
							    &dip->i_dlm_unpub_link,
							    &mp->m_mxfs_unpub_list);
						}
						spin_unlock(&mp->m_mxfs_unpub_lock);
						if (n_defer <
						    MXFS_PUB_SEEN_DEFER_MAX)
							seen_defer[n_defer++] =
								ino;
					}
					if (atomic_inc_return(&ppedm_n) <= 400)
						mxfs_probe("mxfs: P-PUB-EDEMOTE-DEFER ino=%llu mode=%u ran=%d claim_rc=%d — live holder kept the grant\n",
							(unsigned long long)ino,
							dip->i_dlm_mode,
							run_bp ? 1 : 0, crc);
					if (crc &&
					    n_defer >= MXFS_PUB_SEEN_DEFER_MAX) {
						/* guard full — stop this
						 * drain; the next publish
						 * retries the rest */
						xfs_irele(dip);
						break;
					}
				} else {
					spin_unlock(&dip->i_dlm_lock);
				}
				xfs_irele(dip);
			} else {
				/* evicted between pop and here: its updates
				 * are log-only — settle the platter image */
				mxfs_dlm_unpub_child_settle(mp, ino);
			}
			n++;
			continue;
		}
		{
			/*
			 * THE CLAIM IS THE PROOF, SO IT MUST BE INSTALLED
			 * (D-0937).  This arm used to ask the lock layer for no
			 * grant result at all, so nothing was ever offered to
			 * mxfs_dlm_authority_install — while the pop above had
			 * already cleared i_dlm_unpublished.  The inode came out
			 * of the publish holding a real, exclusive on-disk grant
			 * with its authority state still UNPUBLISHED_EX and its
			 * last install attempt reading "never attempted"; and
			 * because it is CACHED EX from here on, every later
			 * operation is served from the ilock_begin fast path and
			 * never descends into the lock layer again.  The tenure
			 * therefore never became provable, and every directory
			 * image it authorised shipped class NONE — enough for a
			 * foreign replayer to refuse the whole slice and
			 * quarantine the dead node's allocation groups.
			 *
			 * The justification for installing is the one the
			 * creator-baseline stamp below already rests on: we are
			 * inside a peer BAST on the PARENT, the peer is blocked
			 * on that lock and cannot have reached this child, so
			 * the claim we just took is this inode's first real
			 * grant.  The ICLUSTER arm above has snapshotted the gen
			 * and installed since; a directory is not routed
			 * there, which is the only reason this arm was left
			 * without it.
			 *
			 * The reference and the provenance snapshot are taken
			 * BEFORE the claim: `match` was valid only under
			 * m_mxfs_unpub_lock, and a gen sampled after the claim
			 * could not detect a relinquishment that raced it.
			 * INCORE means no disk I/O, and a NULL is a reclaimed
			 * inode — nothing to prove for and nothing to stamp.
			 */
			struct xfs_inode *bip = NULL;
			struct mxfs_grant_result dir_gres;
			uint64_t dir_gen_snap = MXFS_AUTH_GEN_NONE;

			if (xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0,
				     &bip) != 0)
				bip = NULL;
			if (bip) {
				spin_lock(&bip->i_dlm_lock);
				dir_gen_snap = bip->i_mxfs_auth_gen;
				spin_unlock(&bip->i_dlm_lock);
			}

			rc = mxfs_v5_dlm_inode_lock(dlm, ino, MXFS_LOCK_EX,
						    bip ? &dir_gres : NULL);
			if (rc)
				mxfs_pal_log(MXFS_LOG_WARN,
					"mxfs: deferred-publish CAW EX failed ino=%llu rc=%d",
					(unsigned long long)ino, rc);
			else if (bip) {
				spin_lock(&bip->i_dlm_lock);
				mxfs_dlm_authority_install(bip, &dir_gres,
							   dir_gen_snap, false,
							   MXFS_SITE);
				spin_unlock(&bip->i_dlm_lock);
				/* CREATOR BASELINE STAMP site 3 — the
				 * live path for a DIRECTORY. */
				mxfs_dlm_creator_baseline_query(bip, 3);
			}
			if (bip)
				xfs_irele(bip);
		}
		n++;
	}
	return n;
}

/* A/B: Wave-A publish pre-pass (writeback+single-force before the
 * per-child eager-demote batch).  1=on (drc 4-7s handoffs -> in-budget);
 * 0=off for fairness-regression bisection. */
int mxfs_pub_wave_a = 1;

/* A/B: 1 = live-holder eager-demote aborts CLAIM the cluster EX from
 * the drain worker (airtight exclusion, extra hot-cluster EX pressure);
 * 0 = relist-only (holder's armed ilock_end demote converges µs later). */
int mxfs_pub_defer_claim = 1;
module_param_named(pub_defer_claim, mxfs_pub_defer_claim, int, 0644);
module_param_named(pub_wave_a, mxfs_pub_wave_a, int, 0644);
MODULE_PARM_DESC(pub_wave_a, "publish Wave-A writeback pre-pass (1=on)");

static void
mxfs_dlm_publish_drain_work(
	struct work_struct	*work)
{
	struct mxfs_pub_drain_worker *w =
		container_of(work, struct mxfs_pub_drain_worker, work);
	struct mxfs_pub_drain_batch *b = w->batch;
	struct xfs_mount	*mp = w->mp;

	w->published = mxfs_dlm_publish_drain_loop(mp, w->parent_ino,
						   w->agno, w->seen_defer);
	if (atomic_dec_and_test(&b->pending))
		complete(&b->done);
	if (atomic_dec_and_test(&b->refs))
		kfree(b);
	atomic_dec(&mp->m_mxfs_pubdrain_active);
}

void
mxfs_dlm_publish_unpublished(
	struct xfs_mount	*mp,
	xfs_ino_t		parent_ino,
	xfs_agnumber_t		agno)
{
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	struct xfs_inode	*ip;
	unsigned int		n = 0, backlog = 0;
	u64			t0;

	if (!dlm)
		return;

	/* Fast bail without taking the lock in the common (empty) case. */
	if (list_empty(&mp->m_mxfs_unpub_list))
		return;


	/*
	 * v0.5.5: the drain used to claim slots
	 * one CAW round-trip (~2 ms) at a time.  A single mid-rsync peer
	 * BAST then serialized ~9000 unclaimed file slots through the
	 * ordered bast workqueue — an 18-30 s stall on one node (ftrace
	 * stack aggregation: 8845 mxfs_v5_dlm_inode_lock calls from
	 * mxfs_dlm_publish_unpublished in one run).  The claims are
	 * independent (distinct slots), so fan the backlog out over
	 * MXFS_PUB_DRAIN_WORKERS unbound workers and wait; the
	 * peer-is-blocked-until-we-return guarantee is preserved.
	 */
	/* v0.5.6: count only IN-SCOPE entries — the inline-vs-parallel
	 * decision is about how many slots THIS drain will claim. */
	spin_lock(&mp->m_mxfs_unpub_lock);
	list_for_each_entry(ip, &mp->m_mxfs_unpub_list, i_dlm_unpub_link) {
		if (!mxfs_dlm_unpub_in_scope(mp, ip, parent_ino, agno))
			continue;
		if (++backlog > MXFS_PUB_DRAIN_INLINE)
			break;
	}
	spin_unlock(&mp->m_mxfs_unpub_lock);

	if (!backlog)
		return;

	/*
	 * WAVE A (instrumented, P138-measured): the per-child eager-demote
	 * pipeline costs 5-9ms/child when each child pays its own first
	 * log_force (sa~1.5ms), dirty-page flush (sc~2-4ms) and durable
	 * section (sd~2ms) — x800 children = 4-7s dir handoffs (the drc
	 * budget killer).  Pre-pass: START async writeback for every
	 * in-scope routed child (parallel device IO from one thread), WAIT,
	 * then ONE synchronous log force covers every delalloc-conversion
	 * transaction the writebacks logged.  The per-child pipeline then
	 * finds pages clean (sc~0), the log pre-forced (sa~0), and shared
	 * cluster buffers coalesce in sd.
	 */
	{
		struct xfs_inode **wa;
		unsigned int nwa = 0, wi;

		wa = mxfs_pub_wave_a ?
			kmalloc_array(4096, sizeof(*wa), GFP_KERNEL) : NULL;
		if (wa) {
			xfs_ino_t *wains = (xfs_ino_t *)wa; /* reuse: pass 1 stores inos */

			spin_lock(&mp->m_mxfs_unpub_lock);
			list_for_each_entry(ip, &mp->m_mxfs_unpub_list,
					    i_dlm_unpub_link) {
				if (!mxfs_dlm_unpub_in_scope(mp, ip,
							     parent_ino, agno))
					continue;
				if (!mxfs_iclus_routed(ip))
					continue;
				if (ip->i_ino == 0)
					continue;
				wains[nwa++] = ip->i_ino;
				if (nwa == 4096)
					break;
			}
			spin_unlock(&mp->m_mxfs_unpub_lock);
			/* swap ino -> referenced ip in place (iget after the
			 * spinlock; INCORE lookup, no disk IO) */
			for (wi = 0; wi < nwa; wi++) {
				struct xfs_inode *wip = NULL;
				xfs_ino_t wino = wains[wi];

				if (xfs_iget(mp, NULL, wino, XFS_IGET_INCORE,
					     0, &wip) || !wip)
					wip = NULL;
				wa[wi] = wip;
			}
			for (wi = 0; wi < nwa; wi++)
				if (wa[wi] && VFS_I(wa[wi])->i_mapping)
					filemap_fdatawrite(
						VFS_I(wa[wi])->i_mapping);
			for (wi = 0; wi < nwa; wi++) {
				if (!wa[wi])
					continue;
				if (VFS_I(wa[wi])->i_mapping)
					filemap_fdatawait(
						VFS_I(wa[wi])->i_mapping);
				xfs_irele(wa[wi]);
			}
			if (nwa)
				xfs_log_force(mp, XFS_LOG_SYNC);
			kfree(wa);
		}
	}

	t0 = ktime_get_ns();
	{
		struct mxfs_pub_drain_batch *b;
		unsigned int i, nw;

		/* the INLINE small-backlog drain blocked the bast
		 * worker exactly like the parallel wait (each claim can
		 * remote-wait) — every backlog size now goes through the
		 * bounded-wait batch.  Worker count scales with backlog. */
		nw = min_t(unsigned int, backlog, MXFS_PUB_DRAIN_WORKERS);
		b = kzalloc(sizeof(*b), GFP_KERNEL);
		if (!b)
			goto report;	/* n=0; the next BAST's publish retries */
		b->nworkers = nw;
		init_completion(&b->done);
		atomic_set(&b->pending, nw);
		atomic_set(&b->refs, nw + 1);
		atomic_add(nw, &mp->m_mxfs_pubdrain_active);
		for (i = 0; i < nw; i++) {
			b->w[i].mp = mp;
			b->w[i].parent_ino = parent_ino;
			b->w[i].agno = agno;
			b->w[i].batch = b;
			INIT_WORK(&b->w[i].work, mxfs_dlm_publish_drain_work);
			queue_work(system_unbound_wq, &b->w[i].work);
		}
		if (wait_for_completion_timeout(&b->done,
				msecs_to_jiffies(MXFS_PUB_DRAIN_TIMEOUT_MS))) {
			for (i = 0; i < nw; i++)
				n += b->w[i].published;
		} else {
			static atomic_t ptmo_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&ptmo_n) <= 200)
				pr_warn("mxfs: P-PUB-DRAIN-TIMEOUT parent=%llu agno=%d backlog=%u — %ums publish window expired; handoff proceeds, claims land async (cross-node bast cycle broken)\n",
					(unsigned long long)parent_ino,
					agno == NULLAGNUMBER ? -1 : (int)agno,
					backlog,
					MXFS_PUB_DRAIN_TIMEOUT_MS);
		}
		if (atomic_dec_and_test(&b->refs))
			kfree(b);
	}
report:
	if (n) {
		/* P25-PUB probe (capped): drain size + wall per invocation.
		 * v0.5.6 adds the scope so a runaway (huge drained= with a
		 * non-zero scope) is visible in dmesg. */
		static atomic_t p25_pub_cap = ATOMIC_INIT(0);
		if (atomic_inc_return(&p25_pub_cap) <= 40)
			if (unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled))
				mxfs_probe("mxfs: P25-PUB drained=%u parallel=%d ms=%llu parent=%llu agno=%d\n",
					n, backlog > MXFS_PUB_DRAIN_INLINE,
					(unsigned long long)((ktime_get_ns() - t0) /
							     NSEC_PER_MSEC),
					(unsigned long long)parent_ino,
					agno == NULLAGNUMBER ? -1 : (int)agno);
	}
}

/*
 * v0.5.4 — background DIRECTORY publisher.
 *
 * Work fn for mp->m_mxfs_publish_work (queued on m_mxfs_inode_bast_wq by
 * xfs_create after each mkdir).  Claims the on-disk CAW slot for every
 * unpublished DIRECTORY on m_mxfs_unpub_list so the
 * unpublished-dir-EX backstop in mxfs_dlm_ilock_begin (a synchronous
 * ~1.5 ms CAW acquire + reload inside the dir's first pin-free EX op —
 * rsync's per-dir utimensat) finds the dir already published and
 * fast-paths.  Regular files are left on the list: they never hit the
 * backstop, and publishing all of them re-creates the v0.5.2 per-create
 * CAW cost this design removed.
 *
 * Ordering is ACQUIRE-then-CLEAR — the reverse of
 * mxfs_dlm_publish_unpublished.  That fn clears i_dlm_unpublished before
 * the CAW acquire, which is safe there only because its caller (a BAST)
 * guarantees the peer is blocked and cannot reach the inode.  Here there
 * is no such shield: clearing the flag first would let a local EX-modify
 * fast-path through ilock_begin during the in-flight acquire while a
 * peer might own the slot — the exact mutual-exclusion hole.
 * With acquire-first, the flag (and thus the backstop) stays armed until
 * the slot is provably ours.
 *
 * Races:
 *  - backstop / publish_unpublished concurrently acquiring the same ino:
 *    mxfs_dlm_caw_lock converges via its already-held path; the list
 *    re-scan below then simply finds the entry gone.  Coherent.
 *  - reclaim evicting the inode mid-acquire: mxfs_dlm_evict's
 *    unpublish_drop sees the flag still set and skips the on-disk
 *    release, briefly leaking the slot we just claimed; a peer's later
 *    acquire of that ino BASTs us and the no-inode orphan-release path
 *    frees it.  ip is never dereferenced outside m_mxfs_unpub_lock, so
 *    there is no UAF.
 */
void
mxfs_dlm_publish_dirs_work(
	struct work_struct	*work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_publish_work);
	struct mxfs_v5_dlm	*dlm = mp->m_mxfs_dlm;
	struct xfs_inode	*ip;
	uint64_t		ino;
	unsigned int		n = 0;
	int			rc;
	/* D-0937: provenance of this worker's claim (see the claim below). */
	struct xfs_inode	*pubip;
	struct mxfs_grant_result pub_gres;
	uint64_t		pub_gen_snap;

	/* P24 instrumented probe: confirm the worker runs and claims (capped). */
	{
		static atomic_t p24w_n = ATOMIC_INIT(0);
		if (atomic_inc_return(&p24w_n) <= 50)
			mxfs_probe("mxfs: P24-WORKER enter dlm=%d single=%d\n",
				dlm ? 1 : 0,
				dlm ? mxfs_v5_dlm_is_single_node(dlm) : -1);
	}
	/* 0.83.3 (D-0955) / 0.87.16: every mount publishes its unpublished
	 * inodes to the master (itself when alone) so a joining peer's acquire
	 * BASTs it and a replayer finds the grant behind its logged images. */
	if (!dlm)
		return;

	for (;;) {
		unsigned int sc_tot = 0, sc_zero = 0, sc_file = 0;
		uint32_t bep = 0, bgg = 0;	/* creator baseline */

		ino = 0;
		spin_lock(&mp->m_mxfs_unpub_lock);
		list_for_each_entry(ip, &mp->m_mxfs_unpub_list,
				    i_dlm_unpub_link) {
			sc_tot++;
			/* P24 instrumented probe: dump what the scan actually sees. */
			{
				static atomic_t p24e_n = ATOMIC_INIT(0);
				if (atomic_inc_return(&p24e_n) <= 30)
					mxfs_probe("mxfs: P24-SCAN ip=%px ino=%llu vmode=%o\n",
						ip,
						(unsigned long long)ip->i_ino,
						VFS_I(ip)->i_mode);
			}
			if (ip->i_ino == 0) {
				sc_zero++;
				continue;
			}
			if (!S_ISDIR(VFS_I(ip)->i_mode)) {
				sc_file++;
				continue;
			}
			/* v0.5.6: only REUSED-incarnation
			 * dirs need a pre-claimed slot — peers may still name
			 * their ino from stale dcache of the prior incarnation
			 * WITHOUT transiting a lock we hold, and the
			 * backstop that covers that costs a synchronous ~1.5 ms
			 * CAW acquire on the dir's first EX-modify.  FRESH
			 * creates are reachable only through locks we hold, so
			 * the scoped BAST-side publish covers them; pre-claiming
			 * them here only generated ~700 claims/node of FUA slot
			 * traffic per rsync (16n: ~11k cluster-wide, 2.3 s of
			 * caw_lock per node, LUN queue inflation on every op). */
			if (!ip->i_mxfs_reused_create)
				continue;
			ino = ip->i_ino;
			break;
		}
		spin_unlock(&mp->m_mxfs_unpub_lock);

		if (!ino) {
			/* P24 instrumented probe: why the scan came up empty. */
			static atomic_t p24s_n = ATOMIC_INIT(0);
			if (atomic_inc_return(&p24s_n) <= 50)
				mxfs_probe("mxfs: P24-WORKER scan-empty tot=%u zero=%u file=%u\n",
					sc_tot, sc_zero, sc_file);
			break;
		}

		/*
		 * THE CLAIM IS THE PROOF, SO IT MUST BE INSTALLED (D-0937) —
		 * the same hole the publish drain carried: a real exclusive
		 * on-disk grant taken with no grant result, so the delist below
		 * leaves the inode looking published while its authority state
		 * still reads UNPUBLISHED_EX and nothing ever retries.  The
		 * reference and the gen snapshot are taken before the claim; the
		 * install runs after the delist, because the installer refuses
		 * any inode still flagged unpublished, and outside
		 * m_mxfs_unpub_lock, because the established nesting is
		 * i_dlm_lock -> m_mxfs_unpub_lock and never the reverse.
		 */
		pubip = NULL;
		pub_gen_snap = MXFS_AUTH_GEN_NONE;
		if (xfs_iget(mp, NULL, ino, XFS_IGET_INCORE, 0, &pubip) != 0)
			pubip = NULL;
		if (pubip) {
			spin_lock(&pubip->i_dlm_lock);
			pub_gen_snap = pubip->i_mxfs_auth_gen;
			spin_unlock(&pubip->i_dlm_lock);
		}

		rc = mxfs_v5_dlm_inode_lock(dlm, ino, MXFS_LOCK_EX,
					    pubip ? &pub_gres : NULL);

		/* CREATOR BASELINE STAMP site 2 — read the post-claim
		 * baseline HERE, in sleepable context, BEFORE taking the list
		 * spinlock.  The stamp itself is two scalar stores and happens
		 * under the lock below; hoisting only the QUERY keeps the
		 * sleeping grant_meta mutex (dlm_caw.c:1120) out of atomic
		 * context, which is what made this site awkward in the
		 * design note.  We hold EX from the call above and do not
		 * release it, so no peer can advance either value in between. */
		if (rc == 0) {
			bep = mxfs_v5_dlm_inode_dir_epoch(dlm, ino);
			bgg = mxfs_v5_dlm_inode_grant_gen(dlm, ino);
		}

		spin_lock(&mp->m_mxfs_unpub_lock);
		list_for_each_entry(ip, &mp->m_mxfs_unpub_list,
				    i_dlm_unpub_link) {
			if (ip->i_ino != ino)
				continue;
			if (rc == 0) {
				list_del_init(&ip->i_dlm_unpub_link);
				ip->i_dlm_unpublished = false;
				mxfs_dlm_creator_baseline_apply(ip, bep, bgg, 2);
			}
			break;
		}
		spin_unlock(&mp->m_mxfs_unpub_lock);

		if (rc == 0 && pubip) {
			spin_lock(&pubip->i_dlm_lock);
			mxfs_dlm_authority_install(pubip, &pub_gres,
						   pub_gen_snap, false,
						   MXFS_SITE);
			spin_unlock(&pubip->i_dlm_lock);
		}
		if (pubip)
			xfs_irele(pubip);

		if (rc) {
			/* Leave it listed; the ilock_begin backstop retries
			 * synchronously on the next EX-modify. */
			mxfs_probe_ratelimited(
			    "mxfs: P24-ASYNC-PUBLISH-FAIL ino=%llu rc=%d (backstop will retry)\n",
				(unsigned long long)ino, rc);
			break;
		}
		n++;
	}
	/* P24 instrumented probe (capped): claims per drain. */
	{
		static atomic_t p24c_n = ATOMIC_INIT(0);
		if (n && atomic_inc_return(&p24c_n) <= 50)
			mxfs_probe("mxfs: P24-WORKER claimed=%u\n", n);
	}
}

/*
 * NEWARCH Phase 1.4 — publish-on-create.  Synchronously promote ONE
 * unpublished inode to a real on-disk CAW slot.  Called from xfs_create
 * after xfs_trans_commit and before namespace exposure.
 *
 * Atomically removes the inode from the unpub list (so a concurrent
 * publish_unpublished or a peer-BAST-driven publish can't race us) and
 * acquires the real on-disk EX slot.  After this returns, a peer
 * reaching the new inode by name will find a real slot, send us a
 * proper BAST, and we will drain+release coherently — closing the
 * "peer acquires empty slot cleanly, never BASTs" window.
 *
 * Best-effort: if mxfs_v5_dlm_inode_lock fails (CAW exhausted),
 * P109-PUBLISH-FAIL is logged and we fall back to the lazy
 * publish backstop in mxfs_dlm_ilock_begin — same correctness, slower.
 * Hot-path probe ratelimited.
 */
void
mxfs_dlm_publish_inode(
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct mxfs_v5_dlm	*dlm;
	bool			was_unpub;
	int			rc;
	uint64_t		pub_gen_snap;

	if (!mp)
		return;
	dlm = mp->m_mxfs_dlm;
	if (!dlm)
		return;

	/* No membership exemption (0.83.3 for a sole survivor, 0.87.16 for a
	 * mount that never had a peer): the grant this publish claims is what
	 * authorizes the inode's logged images at a replay after a death. */

	/* Already published?  Common-case fast bail without the list lock. */
	if (!ip->i_dlm_unpublished) {
		/*
		 * instrumented probe: publish-on-create called for a REUSED
		 * in-core inode (recycle / reset_inode_for_create) that kept
		 * the PRIOR incarnation's DLM state.  If the prior incarnation
		 * was published and then freed, xfs_inactive released the
		 * on-disk slot — this inode now holds a PHANTOM in-core EX with
		 * NO slot, peers' acquires grant clean (no BAST), and the new
		 * dinode is never flushed for them (cross_write_read size=0).
		 */
		mxfs_probe_ratelimited(
		    "mxfs: P128-PUBLISH-BAIL ino=%llu dlm_mode=%u dlm_state=%u — create on reused inode, unpub flag clear, NOT acquiring slot\n",
			(unsigned long long)ip->i_ino,
			ip->i_dlm_mode, ip->i_dlm_state);
		return;
	}

	/*
	 * THE CLAIM IS THE PROOF, SO IT MUST BE INSTALLED (D-0937).  This
	 * publish used to pass MXFS_AUTH_GEN_NONE, the sentinel reserved for
	 * probe and nudge callers that make no provenance claim — which turns
	 * mxfs_dlm_authority_install into a no-op.  But this IS a provenance
	 * claim: it delists the inode and then takes a real exclusive on-disk
	 * grant, and leaving the tenure unproven means every image it
	 * authorises ships class NONE and is refused on foreign replay.  Sample
	 * the gen before the delist, under i_dlm_lock and never inside
	 * m_mxfs_unpub_lock (the established nesting runs the other way), so a
	 * relinquishment racing the acquire still moves the counter and the
	 * install refuses.
	 */
	spin_lock(&ip->i_dlm_lock);
	pub_gen_snap = ip->i_mxfs_auth_gen;
	spin_unlock(&ip->i_dlm_lock);

	spin_lock(&mp->m_mxfs_unpub_lock);
	was_unpub = ip->i_dlm_unpublished;
	if (was_unpub) {
		list_del_init(&ip->i_dlm_unpub_link);
		ip->i_dlm_unpublished = false;
	}
	spin_unlock(&mp->m_mxfs_unpub_lock);

	if (!was_unpub)
		return;	/* racing publisher won; nothing to do. */

	rc = mxfs_dlm_inode_lock_routed(ip, MXFS_LOCK_EX, pub_gen_snap);
	if (rc) {
		mxfs_probe_ratelimited(
		    "mxfs: P109-PUBLISH-FAIL ino=%llu rc=%d (falling back to lazy backstop)\n",
			(unsigned long long)ip->i_ino, rc);
		return;
	}
	mxfs_idbg("mxfs: P109-PUBLISH-OK ino=%llu mode=EX (publish-on-create)\n",
		(unsigned long long)ip->i_ino);
	/* CREATOR BASELINE STAMP site 1 — sleepable, no lock held, and
	 * `ip` is the caller's referenced inode.  Reached only from the
	 * cross-dir rename/link force-publish and xfs_symlink; xfs_create's own
	 * publish-on-create call was removed for cost (xfs_inode.c:2682), so a
	 * plain mkdir does NOT come through here — expect this site to measure
	 * near zero and read that as routing, not as the stamp failing. */
	mxfs_dlm_creator_baseline_query(ip, 1);
}
