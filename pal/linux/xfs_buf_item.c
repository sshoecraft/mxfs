// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include "xfs_platform.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_mount.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_buf_item.h"
#include "xfs_inode.h"
#include "xfs_inode_item.h"
#include "xfs_quota.h"
#include "xfs_dquot_item.h"
#include "xfs_dquot.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_log_priv.h"
#include "xfs_error.h"
#include "xfs_ag.h"
/*
 * step 5.3(a): the v5 owner-bearing metadata headers.  Every
 * xfs_*_buf_ops symbol the owner ladder compares against is declared either by
 * xfs_shared.h (already included) or by xfs_dir2.h for the dir3 families.
 * Deliberately NOT pulling xfs_attr_remote.h / xfs_symlink.h / xfs_da_btree.h:
 * those declare functions over types this file has no forward declaration for
 * and emit incomplete-type warnings, while the buf_ops they would supply are
 * already visible via xfs_shared.h.
 */
#include "xfs_da_format.h"
#include "xfs_dir2.h"
#include "xfs_mxfs_dlm.h"
#include "xfs_mxfs_dirshard.h"	/* manifest-block owner derivation */
#include <mxfs/mxfs_dlm.h>	/* step 5.3: MXFS_LOCK_* modes */


struct kmem_cache	*xfs_buf_item_cache;

static inline struct xfs_buf_log_item *BUF_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_buf_log_item, bli_item);
}

static void
xfs_buf_item_get_format(
	struct xfs_buf_log_item	*bip,
	int			count)
{
	ASSERT(bip->bli_formats == NULL);
	bip->bli_format_count = count;

	if (count == 1) {
		bip->bli_formats = &bip->__bli_format;
		return;
	}

	bip->bli_formats = kzalloc(count * sizeof(struct xfs_buf_log_format),
				GFP_KERNEL | __GFP_NOFAIL);
}

static void
xfs_buf_item_free_format(
	struct xfs_buf_log_item	*bip)
{
	if (bip->bli_formats != &bip->__bli_format) {
		kfree(bip->bli_formats);
		bip->bli_formats = NULL;
	}
}

static void mxfs_bli_refuse_clear(struct xfs_buf_log_item *bip,
				  struct xfs_buf *bp);

static void
xfs_buf_item_free(
	struct xfs_buf_log_item	*bip)
{
	xfs_buf_item_free_format(bip);
	kvfree(bip->bli_item.li_lv_shadow);
	kmem_cache_free(xfs_buf_item_cache, bip);
}

/*
 * xfs_buf_item_relse() is called when the buf log item is no longer needed.
 */
static void
xfs_buf_item_relse(
	struct xfs_buf_log_item	*bip,
	const char		*why,
	enum xfs_bli_release_ctx ctx)
{
	struct xfs_buf		*bp = bip->bli_buf;

	trace_xfs_buf_item_relse(bp, _RET_IP_);

	ASSERT(!test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags));
	ASSERT(atomic_read(&bip->bli_refcount) == 0);

	/*
	 * instrumented probe for the f4truth GEN-OPEN-NOT-DIRTY residue
	 * (0.54.0 census: dir buffers with an open committed-never-submitted
	 * record, submit_gen=0, bli gone, clean, aborted=0): name the path
	 * that frees a DIRTY-committed bli without a home write.  Ratelimited;
	 * the first 200 carry the caller.
	 */
	if (bp->b_mxfs_f4_rec &&
	    bp->b_mxfs_f4_submit_gen < bp->b_mxfs_f4_committed_gen) {
		static atomic_t p_n = ATOMIC_INIT(0);

		if (atomic_inc_return(&p_n) <= 200)
			mxfs_probe("mxfs: P285-F4-BLI-FREED-OPEN daddr=%lld len=%u committed_gen=%llu submit_gen=%llu bli_flags=0x%x li_flags=0x%lx b_flags=0x%x pin=%d hold=%d stale=%d lseq=%llu wseq=%llu site=%u:%u caller=%pS\n",
				(long long)bp->b_maps[0].bm_bn, bp->b_length,
				(unsigned long long)bp->b_mxfs_f4_committed_gen,
				(unsigned long long)bp->b_mxfs_f4_submit_gen,
				bip->bli_flags, bip->bli_item.li_flags,
				bp->b_flags, atomic_read(&bp->b_pin_count),
				(int)bp->b_hold,
				!!(bp->b_flags & XBF_STALE),
				(unsigned long long)bp->b_mxfs_logged_seq,
				(unsigned long long)bp->b_mxfs_written_seq,
				MXFS_SITE_ARGS(bp->b_mxfs_done_site),
				__builtin_return_address(0));
	}
	/*
	 * (D-...-0924) INSTRUMENTED PROBE — DOES NOT CHANGE BEHAVIOUR.
	 *
	 * This function is the funnel every bli retirement path reaches, and it
	 * does not consult the AG-meta one-shot token.  Only two callers reclaim
	 * it: xfs_buf_item_finish_stale and the shutdown/abort branch of
	 * xfs_buf_item_release.  xfs_buf_item_put reaches here without either —
	 * and its own comment names the route, "a dirty BLI that isn't in the
	 * AIL ... if there's another bli reference (e.g. a btree cursor holds a
	 * clean reference) and it is released via xfs_trans_brelse()".
	 *
	 * That matches the only evidence we have of the leak happening: the
	 * mxfs_ag_meta_track tripwire fired once on 0.75.63 (s543a, uptime
	 * 21524) under xfs_btree_insert -> xfs_btree_make_block_unfull ->
	 * xfs_btree_split -> xfs_btree_log_recs -> xfs_trans_log_buf, i.e. a
	 * btree CURSOR's buffer, in the boot that then leaked six xfs_bufs to
	 * module unload.  A tracked bli freed here leaves the token at 1, so the
	 * buffer's next dirty epoch trips that tripwire and the hold + the AG's
	 * pending count are never returned.
	 *
	 * Measure it before changing it: name the buffer and the caller whenever
	 * a bli is retired with the token still outstanding.  If this fires, the
	 * path is proven and the repair belongs HERE, at the funnel, where
	 * mxfs_ag_meta_reclaim is a no-op on any buffer that has no hold.  If it
	 * never fires under a workload that exercises the tripwire's own stack,
	 * the leak is somewhere else and this probe has ruled a path out.
	 *
	 * THE IODONE CALLER IS NOT A LEAK, AND THE FIRST CUT OF THIS PROBE COULD
	 * NOT TELL.  __xfs_buf_ioend calls xfs_buf_item_done (which reaches here)
	 * at pal/linux/xfs_buf.c:3243 and only then calls bp->b_iodone at :3246,
	 * so on EVERY healthy write completion of a tracked AG-meta buffer the
	 * token is still 1 when this function runs and is consumed microseconds
	 * later.  Measured: 145 firings across three agmeta laps on 0.75.94, ALL
	 * of them caller=xfs_buf_item_done, with p3_max_us=0 and stuckmeta=0 in
	 * the same laps — i.e. every one benign.  So the caller has to be part of
	 * the condition.
	 *
	 * AND THE TAG WAS THE WRONG WAY TO ASK.  The condition was once
	 * `strcmp(why, "iodone")`, on the reading that "iodone" identified the
	 * write completion.  It does not: it identified xfs_buf_item_done, which
	 * the MXFS overlay also calls directly from retirement arms that perform
	 * no I/O, so those arms were silently exempted from the reclaim they
	 * needed — and __builtin_return_address(0) below cannot tell them apart
	 * either, because every one of them reaches this funnel through
	 * xfs_buf_item_done.  The completion continuation now declares itself
	 * (XFS_BLI_IODONE_FOLLOWS) and everything else is a reclaim site.
	 */
	if (atomic_read(&bp->b_mxfs_agmeta_hold) == 1 &&
	    ctx == XFS_BLI_NO_IODONE) {
		static atomic_t p_relse = ATOMIC_INIT(0);

		if (atomic_inc_return(&p_relse) <= 100)
			pr_warn("mxfs: P-AGMETA-RELSE-OUTSTANDING daddr=%lld len=%u ops=%s bli_flags=0x%x li_flags=0x%lx dirty=%d stale=%d aborted=%d inail=%d pin=%d hold=%d why=%s caller=%pS — a buf log item is being retired with its AG-meta track hold still outstanding; neither the write completion nor a reclaim consumed the token, so the hold and the AG's pending count leak from here\n",
				(long long)bp->b_maps[0].bm_bn, bp->b_length,
				(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
				bip->bli_flags, bip->bli_item.li_flags,
				!!(bip->bli_flags & XFS_BLI_DIRTY),
				!!(bip->bli_flags & XFS_BLI_STALE),
				!!test_bit(XFS_LI_ABORTED, &bip->bli_item.li_flags),
				!!test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags),
				atomic_read(&bp->b_pin_count), (int)bp->b_hold, why,
				__builtin_return_address(0));
	}

	/*
	 * 0.75.96 — CLOSE THE ONE UNCOVERED ROUTE THE AUDIT ABOVE FOUND.
	 *
	 * xfs_buf_item_free has exactly one caller, this function, so this is
	 * provably the only place a buf log item is freed.  Of the four call
	 * sites, three cannot leave the AG-meta token outstanding: "iodone" is
	 * followed immediately by the completion that consumes it, "stale"
	 * reclaims in xfs_buf_item_finish_stale before it gets here, and
	 * "release-clean" is only reached for a bli that was never dirtied and
	 * therefore never tracked (mxfs_ag_meta_track runs from
	 * xfs_trans_log_buf).  "put" is the exception: xfs_buf_item_put frees a
	 * dirty bli that is not in the AIL — which upstream permits once the log
	 * has shut down and a checkpoint aborted the item instead of inserting
	 * it — and nothing on that path returns the track hold.  The extra
	 * buffer reference then pins the buffer for the life of the module,
	 * which is what leaves objects in the mxfs_buf slab at unload.
	 *
	 * Reclaiming here is a no-op on every other route: the token is one-shot
	 * and the cmpxchg has already failed once someone else consumed it.  The
	 * probe above runs FIRST and is unconditional on the fix, so a route that
	 * needed this still announces itself instead of being silently repaired.
	 *
	 * THE EXEMPTION IS THE CALLER'S DECLARATION, NOT THE TAG.  It used to be
	 * `strcmp(why, "iodone")`, and "iodone" is stamped by xfs_buf_item_done —
	 * which the MXFS overlay calls directly from about a dozen release-drain
	 * and acquire-evict arms that retire a log item WITHOUT any I/O.  On those
	 * arms nothing runs b_iodone, so the string exemption dropped the log item
	 * and left the tracking token armed: the extra buffer reference is then
	 * held for the life of the module and the AG's pending count never
	 * returns.  Only the completion continuation may defer, and only it passes
	 * XFS_BLI_IODONE_FOLLOWS.
	 */
	if (ctx == XFS_BLI_NO_IODONE)
		mxfs_ag_meta_reclaim(bp, why);

	/* the overlay retire site is consumed by this free */
	bp->b_mxfs_done_site = 0;

	/* D-0487 (0.70.2): the retirement age of a refused item */
	if (bip->bli_mxfs_refuse_first)
		mxfs_bli_refuse_clear(bip, bp);

	bp->b_log_item = NULL;
	xfs_buf_rele(bp);
	xfs_buf_item_free(bip);
}

/* Is this log iovec plausibly large enough to contain the buffer log format? */
bool
xfs_buf_log_check_iovec(
	struct kvec			*iovec)
{
	struct xfs_buf_log_format	*blfp = iovec->iov_base;
	char				*bmp_end;
	char				*item_end;

	if (offsetof(struct xfs_buf_log_format, blf_data_map) > iovec->iov_len)
		return false;

	item_end = (char *)iovec->iov_base + iovec->iov_len;
	bmp_end = (char *)&blfp->blf_data_map[blfp->blf_map_size];
	return bmp_end <= item_end;
}

static inline int
xfs_buf_log_format_size(
	struct xfs_buf_log_format *blfp)
{
	return offsetof(struct xfs_buf_log_format, blf_data_map) +
			(blfp->blf_map_size * sizeof(blfp->blf_data_map[0]));
}

/*
 * authority token (step 3a): does this (non-stale) buf item emit
 * the mxfs_blf_authority trailer?  A pure function of the mount so the
 * size estimate and the format emission can never disagree (the trailer
 * is emitted with class NONE when no authority is known — presence must
 * be size-stable, content is resolved at format time).
 */
struct mxfs_v5_dlm;
extern bool mxfs_v5_dlm_is_single_node(struct mxfs_v5_dlm *);
extern int mxfs_v5_dlm_get_node_slot(struct mxfs_v5_dlm *);
/*
 * step 5.2: the emitting mount's identity, as ONE atomic-enough read
 * of three mount-lifetime constants (slot, node_id, incarnation).  Returns
 * false — with all three outputs zeroed — if any of them is unavailable, and
 * that is a token CAPTURE FAILURE, not a "no authority" answer: an image we
 * cannot bind to an emitting incarnation is not evidence about anything.
 * O(1), lock-free; the slot and the incarnation are fixed for the life of a
 * mount so the format path takes no lock.
 */
extern bool mxfs_v5_dlm_mount_identity(struct mxfs_v5_dlm *, uint32_t *slot,
				       uint32_t *node, uint64_t *epoch);

static inline bool
mxfs_buf_item_wants_authority(
	struct xfs_buf_log_item	*bip)
{
	struct xfs_mount	*mp = bip->bli_buf->b_mount;

	/*
	 * 0.41.0 (D-0354 candidate A): single-node mode now mints
	 * REAL durable grant epochs through the normal CAW grant state
	 * machine, so a lone node's images are tokened exactly like a
	 * cohort member's.  The former !is_single_node gate left every
	 * lone-era image untagged and therefore unreplayable by any
	 * successor (P227 untagged -> -117 -> quarantine).
	 */
	return mp && mp->m_mxfs_dlm;
}

/*
 * step 5.1(c): does the containing AG's EX grant actually AUTHORIZE
 * this buffer?
 *
 * The rule classified by xfs_daddr_to_agno(blf_blkno) ALONE, which is
 * wrong: a dir data block, da-node, attr block, symlink block or bmbt block
 * physically lives inside an AG but its authority is the *inode's* EX grant,
 * not the AG's.  Labelling those class=AG{containing agno} would let a future
 * exact-match gate "prove" the wrong resource and apply an image the victim
 * had already handed off — a false APPLY, strictly worse than today's taint.
 *
 * The discriminator is a CONJUNCTION, and b_ops must be primary:
 * XFS_BLFT_BTREE_BUF conflates the AG btrees with the per-inode bmbt, so BLFT
 * alone cannot tell them apart.  BLFT is required to agree as a second,
 * independent witness (it is set by xfs_trans_buf_set_type before format
 * time, so both halves are available here with no new plumbing).
 *
 * Anything not on this list => MXFS_AUTH_CLASS_NONE => recovery taints and
 * skips.  Fail closed.
 */
static bool
mxfs_buf_ag_authorized(
	const struct xfs_buf		*bp,
	struct xfs_buf_log_format	*blfp)
{
	const struct xfs_buf_ops	*ops = bp->b_ops;
	uint16_t			blft = xfs_blft_from_flags(blfp);

	if (!ops)
		return false;

	if (ops == &xfs_agf_buf_ops)
		return blft == XFS_BLFT_AGF_BUF;
	if (ops == &xfs_agi_buf_ops)
		return blft == XFS_BLFT_AGI_BUF;
	if (ops == &xfs_agfl_buf_ops)
		return blft == XFS_BLFT_AGFL_BUF;
	if (ops == &xfs_bnobt_buf_ops || ops == &xfs_cntbt_buf_ops ||
	    ops == &xfs_inobt_buf_ops || ops == &xfs_finobt_buf_ops ||
	    ops == &xfs_rmapbt_buf_ops || ops == &xfs_refcountbt_buf_ops)
		return blft == XFS_BLFT_BTREE_BUF;

	return false;
}

/*
 * (D-FOREIGN-SLICE-INTENTS-ABANDONED, design-consult ruling fix shape B —
 * ccmemory ccloop-c7ee71c6-sess467-GPT-ruling-intents-classless-images-fix-
 * shapes-A-B-Q3, Q2): the IUNLINK image of an inode-cluster buffer is
 * AG-authorized.
 *
 * Chain 93 (/467 attribution): every rm of a fragmented file by a node
 * that then dies leaves two len=32 DINODE_BUF images at one cluster daddr in
 * the victim's slice — the di_next_unlinked updates xfs_iunlink_log_dinode /
 * xfs_iunlink_update_dinode log through xfs_trans_inode_buf.  The owner
 * derivation has no arm for xfs_inode_buf_ops (NOOWNER by construction) and
 * mxfs_buf_ag_authorized() does not list it, so the image went out class NONE
 * st MISLABELLED, the replayer POLICY-REFUSED the whole transaction and the
 * cluster quarantined FSWIDE — on EVERY death with an unlink in flight.
 *
 * The ruling: the AG grant is the correct authority for exactly this image
 * and nothing else about an inode cluster.  The inode whose di_next_unlinked
 * changes, its cluster and the AGI whose unlinked bucket it threads all live
 * in one AG by construction, and the unlinked list is AG-owned state mutated
 * only under the AG's EX.  Producer conditions, every one required:
 *   - the buffer is an inode cluster (b_ops + BLFT DINO), logged in the
 *     xfs_trans_inode_buf form (XFS_BLI_INODE_BUF) and not stale in either
 *     sense (XFS_BLI_STALE, XFS_BLI_STALE_INODE) — recovery of the INODE_BUF
 *     form (xlog_recover_do_inode_buffer) applies ONLY di_next_unlinked, so
 *     the AG grant never vouches for an inode core;
 *
 * proven by instrument on the 2-node TCP rig: this predicate ALSO
 * excluded XFS_BLI_INODE_ALLOC_BUF, and that term made the whole shape dead
 * on arrival.  A producer probe counted 14 unauthorized inode-cluster images
 * and zero authorized ones, every one reading bli_flags=0x5a with comm=unlink
 * — DIRTY|LOGGED|INODE_ALLOC_BUF|INODE_BUF on an UNLINK.  The allocation flag
 * is set once by xfs_trans_inode_alloc_buf and is never cleared (the
 * formatter clears only XFS_BLI_INODE_BUF), so it is sticky on the cached
 * cluster buffer and disqualifies every later di_next_unlinked update to it —
 * which is the ordinary case, and is why a dead peer's slice was terminally
 * refused and its AGs quarantined on every death with an unlink in flight.
 *
 * The term also guarded a class that cannot exist here.  On v5 an allocating
 * transaction marks the cluster image ORDERED (xfs_ialloc_inode_init), so it
 * is never physically logged — only the logical xfs_icreate_log item is — and
 * the formatter sets the wire flag XFS_BLF_INODE_BUF unconditionally under
 * xfs_has_v3inodes(), so replay of any image reaching the wire from here
 * applies nothing but di_next_unlinked.  The in-core allocation flag carries
 * buffer-item ordering and lifetime semantics (unpin / AIL retention for a
 * newly initialised cluster), not the later image's recovery semantics;
 * reading it as an authority discriminator was a category error.  The feature
 * gate below is xfs_has_v3inodes() for the same reason: it must be the SAME
 * predicate the formatter uses to decide the wire flag.  Clearing the flag
 * after the allocating transaction commits was considered and rejected as
 * actively dangerous — the item is buffer-scoped and outlives the
 * transaction, and a durable commit record is not the ordered initialisation
 * reaching the platter.  (Design consult; ccmemory
 * trap-xfs-bli-inode-alloc-buf-is-sticky-so-a-later-unlink-on-that-cluster-
 * still-carries-the-allocation-flag.)
 *   - the first dinode's identity is verified (magic, v3, meta uuid, ino
 *     plausible) and maps this very buffer into this very AG;
 *   - the transaction holds that AG's AGI (joined by xfs_read_agi under the
 *     AG EX), the contemporaneous witness of the AG authority.
 * The caller still requires a nonzero durable AG grant epoch, exactly as for
 * an AGI/AGF/btree image.  Replay-side: the class-AG token is admitted by the
 * exact {resource, epoch, lineage} manifest match, the D-0517 cross-slice
 * buffer-LSN OVERRIDE covers the cluster's per-inode di_lsn stamps (written
 * by whichever node last flushed a sibling inode), and a reallocated slot is
 * excluded by the epoch: only the AG EX holder allocates or frees in the AG,
 * and an image from an earlier tenure carries that tenure's epoch.  The
 * replayer additionally refuses a class-AG DINODE image that lacks
 * XFS_BLF_INODE_BUF (mxfs_blf_parse_authority), so a whole-cluster image can
 * never ride this class.
 */
static bool
mxfs_buf_iunlink_ag_authorized(
	struct xfs_trans		*tp,
	struct xfs_buf_log_item		*bip,
	struct xfs_mount		*mp,
	xfs_agnumber_t			agno,
	uint16_t			blft)
{
	struct xfs_buf			*bp = bip->bli_buf;
	const struct xfs_dinode		*dip;
	struct xfs_log_item		*lip;
	xfs_ino_t			ino;
	xfs_agino_t			agino;

	if (!tp || !bp->b_ops || bp->b_ops != &xfs_inode_buf_ops ||
	    blft != XFS_BLFT_DINO_BUF)
		return false;
	if (!(bip->bli_flags & XFS_BLI_INODE_BUF) ||
	    (bip->bli_flags & (XFS_BLI_STALE | XFS_BLI_STALE_INODE)))
		return false;
	if (!xfs_has_v3inodes(mp) || BBTOB(bp->b_length) < sizeof(*dip))
		return false;
	dip = xfs_buf_offset(bp, 0);
	if (!dip || be16_to_cpu(dip->di_magic) != XFS_DINODE_MAGIC ||
	    dip->di_version < 3 ||
	    !uuid_equal(&dip->di_uuid, &mp->m_sb.sb_meta_uuid))
		return false;
	ino = be64_to_cpu(dip->di_ino);
	if (!xfs_verify_ino(mp, ino) || XFS_INO_TO_AGNO(mp, ino) != agno)
		return false;
	agino = XFS_INO_TO_AGINO(mp, ino);
	if (XFS_AGB_TO_DADDR(mp, agno, XFS_AGINO_TO_AGBNO(mp, agino)) !=
	    xfs_buf_daddr(bp))
		return false;

	list_for_each_entry(lip, &tp->t_items, li_trans) {
		struct xfs_buf_log_item	*abip;

		if (lip->li_type != XFS_LI_BUF)
			continue;
		abip = container_of(lip, struct xfs_buf_log_item, bli_item);
		if (!abip->bli_buf || abip->bli_buf->b_ops != &xfs_agi_buf_ops)
			continue;
		if (xfs_daddr_to_agno(mp, xfs_buf_daddr(abip->bli_buf)) == agno)
			return true;
	}
	return false;
}

/*
 * step 5.3(a) — OWNER DERIVATION.
 *
 * The population step 5.1 measured as "mislabel" (4770 of 16384 tokens on the
 * 0.11.427 rig, 100% directory blocks) is authorized by the owning INODE's EX
 * grant, not by the containing AG's.  To name that authority on the wire we
 * must first know WHICH inode owns the image, and the only in-band source is
 * the v5 metadata header the block already carries.
 *
 * The design-consult ruling is explicit about how this may be done:
 *
 *  - derive ONCE per logical buffer log item, from offset 0 (map 0), and reuse
 *    the cached answer for every segment.  Never derive per segment: all
 *    segments of a discontiguous buffer must carry identical token fields, and
 *    only map 0 holds the header.
 *  - the header is NOT trustable unconditionally.  Validate b_ops family,
 *    exact magic, header fits, UUID, and that the owner is a plausible inode.
 *  - for bmbt specifically, prove it is a LONG-format inode-owned bmap btree
 *    block and not an AG btree admitted through the generic XFS_BLFT_BTREE_BUF.
 *  - any failure is a NON-PROVING status, never a fallback to the containing
 *    AG's epoch.  That fallback is exactly how the 29% got mislabelled.
 *
 * One honest limit, recorded because 5.4 has to handle it: reading the owner
 * out of buffer MEMORY does not prove the owner field is inside the LOGGED
 * regions of this image.  If only a dirent range is logged, the header may name
 * an owner that no longer holds the block after reuse.  Inode authority alone
 * therefore cannot prove an old partial image still targets a block owned by
 * that inode — recovery must re-validate the owner against the replay target.
 */
struct mxfs_buf_owner {
	uint64_t	ino;		/* validated owning inode number */
	bool		valid;		/* false => OWNER_UNKNOWN, fail closed */
};

static bool
mxfs_owner_hdr_ok(
	struct xfs_mount	*mp,
	const void		*addr,
	size_t			blen,
	size_t			need,
	const uuid_t		*uuid,
	uint64_t		owner)
{
	if (need > blen)
		return false;			/* header does not fit */
	if (!uuid_equal(uuid, &mp->m_sb.sb_meta_uuid))
		return false;			/* another filesystem */
	if (!xfs_verify_ino(mp, (xfs_ino_t)owner))
		return false;			/* not a plausible inode */
	return true;
}

static void
mxfs_buf_derive_owner(
	struct xfs_buf			*bp,
	struct xfs_buf_log_format	*blfp,
	struct mxfs_buf_owner		*out)
{
	struct xfs_mount		*mp = bp->b_mount;
	const struct xfs_buf_ops	*ops = bp->b_ops;
	uint16_t			blft = xfs_blft_from_flags(blfp);
	const void			*addr;
	size_t				blen;
	uint64_t			owner;

	out->ino = 0;
	out->valid = false;

	/* Owners exist only in the v5/CRC metadata headers. */
	if (!ops || !mp || !xfs_has_crc(mp))
		return;

	/*
	 * Offset 0 of the LOGICAL buffer.  xfs_buf_offset() resolves this
	 * correctly for discontiguous (vmapped) buffers too, so map 0's header
	 * is reachable without knowing the mapping shape.
	 */
	addr = xfs_buf_offset(bp, 0);
	if (!addr)
		return;
	blen = BBTOB(bp->b_length);

	if (ops == &xfs_dir3_data_buf_ops || ops == &xfs_dir3_block_buf_ops ||
	    ops == &xfs_dir3_free_buf_ops) {
		const struct xfs_dir3_blk_hdr *h = addr;
		uint32_t magic;

		if (sizeof(*h) > blen)
			return;
		magic = be32_to_cpu(h->magic);
		/* magic must agree with BOTH b_ops and the BLFT */
		if (ops == &xfs_dir3_data_buf_ops) {
			if (magic != XFS_DIR3_DATA_MAGIC ||
			    blft != XFS_BLFT_DIR_DATA_BUF)
				return;
		} else if (ops == &xfs_dir3_block_buf_ops) {
			if (magic != XFS_DIR3_BLOCK_MAGIC ||
			    blft != XFS_BLFT_DIR_BLOCK_BUF)
				return;
		} else {
			if (magic != XFS_DIR3_FREE_MAGIC ||
			    blft != XFS_BLFT_DIR_FREE_BUF)
				return;
		}
		owner = be64_to_cpu(h->owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->uuid,
				       owner))
			return;
	} else if (ops == &xfs_dir3_leaf1_buf_ops ||
		   ops == &xfs_dir3_leafn_buf_ops ||
		   ops == &xfs_da3_node_buf_ops ||
		   ops == &xfs_attr3_leaf_buf_ops) {
		const struct xfs_da3_blkinfo *h = addr;
		uint16_t magic;

		if (sizeof(*h) > blen)
			return;
		magic = be16_to_cpu(h->hdr.magic);
		if (ops == &xfs_dir3_leaf1_buf_ops) {
			if (magic != XFS_DIR3_LEAF1_MAGIC ||
			    blft != XFS_BLFT_DIR_LEAF1_BUF)
				return;
		} else if (ops == &xfs_dir3_leafn_buf_ops) {
			if (magic != XFS_DIR3_LEAFN_MAGIC ||
			    blft != XFS_BLFT_DIR_LEAFN_BUF)
				return;
		} else if (ops == &xfs_da3_node_buf_ops) {
			/*
			 * xfs_da3_node_buf_ops verifies BOTH the da-node magic
			 * and (for a dir) the leafn magic, and both BLFTs are
			 * legitimate for it — accept the exact pairs only.
			 */
			if (!((magic == XFS_DA3_NODE_MAGIC &&
			       blft == XFS_BLFT_DA_NODE_BUF) ||
			      (magic == XFS_DIR3_LEAFN_MAGIC &&
			       blft == XFS_BLFT_DIR_LEAFN_BUF)))
				return;
		} else {
			if (magic != XFS_ATTR3_LEAF_MAGIC ||
			    blft != XFS_BLFT_ATTR_LEAF_BUF)
				return;
		}
		owner = be64_to_cpu(h->owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->uuid,
				       owner))
			return;
	} else if (ops == &xfs_attr3_rmt_buf_ops) {
		const struct xfs_attr3_rmt_hdr *h = addr;

		if (sizeof(*h) > blen ||
		    be32_to_cpu(h->rm_magic) != XFS_ATTR3_RMT_MAGIC ||
		    blft != XFS_BLFT_ATTR_RMT_BUF)
			return;
		owner = be64_to_cpu(h->rm_owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->rm_uuid,
				       owner))
			return;
	} else if (ops == &xfs_symlink_buf_ops) {
		const struct xfs_dsymlink_hdr *h = addr;

		if (sizeof(*h) > blen ||
		    be32_to_cpu(h->sl_magic) != XFS_SYMLINK_MAGIC ||
		    blft != XFS_BLFT_SYMLINK_BUF)
			return;
		owner = be64_to_cpu(h->sl_owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h), &h->sl_uuid,
				       owner))
			return;
	} else if (ops == &mxfs_dirshard_buf_ops) {
		/*
		 * (docs/dir-sharding.md): the manifest block is written
		 * only under the visible PARENT's inode EX — that is the
		 * authority its token must name, so the owner is blk->parent_ino.
		 * blk->owner (the holder inode) is bmap identity only.
		 */
		const struct mxfs_dirshard_blk *h = addr;

		if (sizeof(*h) > blen ||
		    be32_to_cpu(h->magic) != MXFS_DIRSHARD_BLK_MAGIC ||
		    blft != XFS_BLFT_MXFS_DIRSHARD_BUF)
			return;
		owner = be64_to_cpu(h->parent_ino);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, sizeof(*h),
				       (const uuid_t *)h->uuid, owner))
			return;
	} else if (ops == &xfs_bmbt_buf_ops) {
		const struct xfs_btree_block *h = addr;

		/*
		 * The ruling's specific trap: XFS_BLFT_BTREE_BUF is the generic
		 * btree type shared with every AG btree, so BLFT alone cannot
		 * prove this block is inode-owned.  b_ops == xfs_bmbt_buf_ops
		 * AND magic == BMA3 is the exact discriminator — BMA3 is only
		 * ever written to a LONG-format (inode-owned) bmap btree block,
		 * and only the long form has bb_u.l.bb_owner at all.  Demand
		 * the long-form CRC header length as well, so a short-form
		 * block can never be read through the long-form union arm.
		 */
		if (XFS_BTREE_LBLOCK_CRC_LEN > blen ||
		    be32_to_cpu(h->bb_magic) != XFS_BMAP_CRC_MAGIC ||
		    blft != XFS_BLFT_BTREE_BUF)
			return;
		owner = be64_to_cpu(h->bb_u.l.bb_owner);
		if (!mxfs_owner_hdr_ok(mp, addr, blen, XFS_BTREE_LBLOCK_CRC_LEN,
				       &h->bb_u.l.bb_uuid, owner))
			return;
	} else {
		return;			/* not an inode-owned buffer family */
	}

	out->ino = owner;
	out->valid = true;
}

/*
 * ─── step 5.3 — THE DECIDING MEASUREMENT ─────────────────────────
 *
 * measured 13153 inodes entering UNPUBLISHED_EX against 321 durable
 * tenures installed on one rsync_paired lap, and concluded a DURABLE_EX gate
 * would refuse ~97.6% of the images a create-heavy workload produces.  The
 * design-consult ruling rejected that inference: `unpublished_noted` counts
 * STATE ENTRIES, not IMAGES.  It cannot say how many logged images were
 * actually formatted while their owner was unpublished, nor which image types,
 * nor whether the allocating AG tenure was still live.  The 13153-vs-321
 * comparison therefore does not establish the refusal rate at all.
 *
 * This is the measurement that does: for every inode-owned buffer image (the
 * population step 5.1 counts as `mislabel` + `unknown`), resolve the OWNING
 * inode from the block's own v5 header and record the owner's authority state
 * AT FORMAT TIME.  That single joint distribution decides the design fork the
 * ruling laid out:
 *
 *   durable dominates  -> the per-inode certificate is the right gate and the
 *                         producer just needs wiring;
 *   unpub dominates    -> the ruling's "durable unpublished-child delegation
 *                         minted under the AG grant" is required, because
 *                         these are LATER modifications of an unpublished
 *                         object, not initial creation, and an AG-derived
 *                         birth certificate cannot reach them;
 *   uncached/stale     -> the owner is not resolvable at format time and the
 *                         capture has to move to the dirty/join seam (the
 *                         ruling item (b) that is still owed).
 *
 * The BLFT histogram is kept only for the NON-durable outcomes: that is the
 * population that would be refused, and its type mix is the ruling's "image
 * relationship" axis (DINO_BUF = initial cluster init, bmbt/dir/attr = later
 * modification of an existing object).
 *
 * HONEST LIMITS, recorded because the design must not over-read this:
 *   - the authority fields are read WITHOUT i_dlm_lock.  Taking it at CIL
 *     format time would invert the established lock order, so this is a
 *     sampled read: a state that changes concurrently may be attributed to
 *     either side.  It measures a distribution, and must never become the
 *     gate's own test.
 *   - it counts per SEGMENT, so a discontiguous buffer contributes once per
 *     segment.  Every segment of one buffer derives the same owner (map 0),
 *     so the distribution is unaffected; only the absolute total is inflated.
 *   - reading the owner out of buffer MEMORY does not prove the owner field
 *     lies inside the LOGGED regions of this image (the limit).
 */
enum {
	MXFS_OWNAUTH_NOOWNER = 0,	/* header gave no trustworthy owner */
	MXFS_OWNAUTH_BADAG,		/* owner ino outside the AG range */
	MXFS_OWNAUTH_NOPAG,		/* perag unavailable */
	MXFS_OWNAUTH_UNCACHED,		/* owner not in the inode cache */
	MXFS_OWNAUTH_STALE,		/* found, but reclaiming or reused */
	MXFS_OWNAUTH_NONE,		/* MXFS_AUTH_NONE */
	MXFS_OWNAUTH_UNPUB,		/* MXFS_AUTH_UNPUBLISHED_EX */
	MXFS_OWNAUTH_RELEASING,		/* MXFS_AUTH_RELEASING */
	MXFS_OWNAUTH_DURABLE,		/* DURABLE_EX with a real epoch */
	MXFS_OWNAUTH_DURABLE_NOEP,	/* DURABLE_EX, epoch 0 — plumbing hole */
	MXFS_OWNAUTH_MAX
};

static atomic64_t	mxfs_ownauth_n[MXFS_OWNAUTH_MAX];
static atomic64_t	mxfs_ownauth_blft[XFS_BLFT_MAX_BUF];

/*
 * P240-AUTHCAP — the capture-point instrument the ruling demanded.
 *
 * Everything here is counted at the FIRST PROTECTED DIRTY, not at format
 * time, so it describes the tenure that authorized the mutation.
 *
 *   mxfs_authcap_mode[oc]  of the images with outcome `oc`, how many were
 *                          dirtied while this node held mode >= PW on the
 *                          derived owner.  This is the cross-tab that
 *                          separates "the recorder is broken" from "the
 *                          modification was genuinely unauthorized" (P3).
 *   win                    capture windows opened (one per bli per trans).
 *   relog                  re-logs of an already-captured buffer inside the
 *                          same window that were re-resolved and verified.
 *   mismatch               ... of which resolved to a DIFFERENT authority
 *                          object or epoch.  The ruling's "one buffer, two
 *                          authorities" case: never silently overwritten,
 *                          the image is downgraded to MIXED.
 *   noblft                 captures taken before xfs_trans_buf_set_type ran,
 *                          so owner derivation had no BLFT witness.
 *   blftchg                the BLFT changed between capture and format —
 *                          the capture described a different image kind and
 *                          cannot be serialized as proof.
 *   nocap                  formatted with NO capture at all (a dirty path
 *                          that bypasses xfs_trans_dirty_buf).  Must be 0;
 *                          any nonzero value is a plumbing hole.
 */
static atomic64_t	mxfs_authcap_mode[MXFS_OWNAUTH_MAX];
static atomic64_t	mxfs_authcap_win;
static atomic64_t	mxfs_authcap_relog;
static atomic64_t	mxfs_authcap_mismatch;
static atomic64_t	mxfs_authcap_noblft;
static atomic64_t	mxfs_authcap_blftchg;
static atomic64_t	mxfs_authcap_nocap;
/*
 * D-DIR-SF-TO-BLOCK-RETYPE-VOIDS-AUTHORITY-TOKEN-SLICE-REFUSED-0512
 * (design-consult ruling A′): a BLFT change after the capture used to void the token
 * at serialize time (blftchg above) — and xfs_dir2_sf_to_block ALWAYS does
 * that (xfs_dir3_data_init logs the block as DIR_DATA, xfs_dir3_block_init
 * re-types it DIR_BLOCK), so every shortform->block directory conversion
 * produced an unprovable image and the slice holding it was refused on
 * foreign replay.  Now the type change marks the capture PENDING and the
 * NEXT protected dirty re-proves it under the new type: the same complete
 * proof identity -> the witness is updated (retype_ok); a different proven
 * authority -> MIXED (retype_mixed); no proof -> the old proof is NOT kept
 * (retype_unproven); no dirty at all before commit -> void (retype_nodirty).
 */
static atomic64_t	mxfs_authcap_retype_ok;
static atomic64_t	mxfs_authcap_retype_mixed;
static atomic64_t	mxfs_authcap_retype_unproven;
static atomic64_t	mxfs_authcap_retype_nodirty;
/*
 * TEST ONLY negative arms for the ruling's required refusal tests:
 *   1 = a successful re-proof is recorded as MIXED (a proof change);
 *   2 = the pending re-proof is skipped (a re-type never re-dirtied).
 * Both must make the foreign replayer REFUSE the slice.
 */
int mxfs_authcap_inject;
module_param_named(authcap_inject, mxfs_authcap_inject, int, 0644);
MODULE_PARM_DESC(authcap_inject,
		 "TEST ONLY: 1 = record a successful BLFT re-proof as MIXED, "
		 "2 = skip the re-proof so the token is voided at commit");

/*
 * P241-AUTHTRY — the decisive instrument the design-consult ruling asked for.
 *
 * The cross-tab established that every NONE image was dirtied while
 * this node held a WRITING mode, i.e. the authority RECORD is incomplete
 * rather than the modification unauthorized.  It could not say WHY, because
 * `i_mxfs_auth_line` names the last SUCCESSFUL transition (the revoke that
 * established NONE) and a failed install does not transition at all.
 *
 * So the owner's last install ATTEMPT is carried out of the same i_flags_lock
 * section as the state, and histogrammed at exactly the images that matter:
 * the NONE-at-writing-mode population.  Reading the ruling's table:
 *
 *   try == never                  no install was ever attempted — a MISSING
 *                                 CALL: this acquire path does not install
 *   try_gen < gen                 an attempt happened, then a revoke, and
 *                                 nothing retried — MISSING POST-REVOKE EVENT
 *   try == st:write_zero_epoch    the slot had a writing mode and no epoch —
 *                                 EPOCH PUBLICATION/RESTART GAP
 *   try == st:nonwrite_mode       installed against a READ grant and never
 *                                 retried at the conversion that made it a
 *                                 write grant — the ruling's leading
 *                                 hypothesis for this population
 *   try == install/advance        authority WAS installed and something
 *                                 revoked it since — a release-side defect
 */
struct mxfs_ownauth_snap {
	uint64_t	epoch;
	uint64_t	res;
	uint64_t	lineage;
	uint64_t	gen;
	uint64_t	try_gen;
	uint64_t	try_epoch;
	uint32_t	auth_line;
	uint32_t	try_line;
	uint8_t		dlm_mode;
	uint8_t		try;
	uint8_t		try_mode;
	uint8_t		unpublished;
};

static atomic64_t	mxfs_authtry_none[MXFS_AUTH_TRY_MAX];
static atomic64_t	mxfs_authtry_stale;	/* of those, try_gen < gen */
static atomic64_t	mxfs_authtry_samegen;	/* of those, try_gen == gen */

static int
mxfs_buf_owner_authority(
	struct xfs_mount	*mp,
	uint64_t		ino,
	struct mxfs_ownauth_snap *sn)
{
	struct xfs_perag	*pag;
	struct xfs_inode	*ip;
	xfs_agnumber_t		agno;
	int			out;

	memset(sn, 0, sizeof(*sn));

	agno = XFS_INO_TO_AGNO(mp, ino);
	if (agno >= mp->m_sb.sb_agcount)
		return MXFS_OWNAUTH_BADAG;
	pag = xfs_perag_get(mp, agno);
	if (!pag)
		return MXFS_OWNAUTH_NOPAG;

	/*
	 * RCU lookup only — never an iget.  The ruling forbids taking a
	 * reference from the formatter (it can recurse into reclaim and into
	 * the very transaction being formatted); the ruling names this
	 * exact shape instead: rcu_read_lock across lookup, validate identity
	 * and reclaim state under i_flags_lock, copy out, drop.
	 */
	rcu_read_lock();
	ip = radix_tree_lookup(&pag->pag_ici_root, XFS_INO_TO_AGINO(mp, ino));
	if (!ip) {
		out = MXFS_OWNAUTH_UNCACHED;
	} else {
		spin_lock(&ip->i_flags_lock);
		if (ip->i_ino != ino ||
		    (ip->i_flags & (XFS_IRECLAIM | XFS_IRECLAIMABLE))) {
			out = MXFS_OWNAUTH_STALE;
		} else {
			uint8_t  st;
			uint64_t ep, res = 0, lin = 0;
			unsigned seq;

			/*
			 * (fix shape A review, STOP-SHIP 2): the tuple
			 * is written under i_dlm_lock, which this RCU/i_flags_lock
			 * section does not hold — read it through the seqcount
			 * so {state, epoch, resource, lineage} come from ONE
			 * writer's publication, never a torn mix of two tenures.
			 */
			do {
				seq = read_seqcount_begin(&ip->i_mxfs_auth_seq);
				st = READ_ONCE(ip->i_mxfs_auth_state);
				ep = READ_ONCE(ip->i_mxfs_auth_epoch);
				if (st == MXFS_AUTH_DURABLE_EX) {
					res = READ_ONCE(ip->i_mxfs_auth_resource);
					lin = READ_ONCE(ip->i_mxfs_auth_lineage);
				}
			} while (read_seqcount_retry(&ip->i_mxfs_auth_seq, seq));

			/*
			 * the ruling's decisive cross-tab is
			 * outcome x (dlm_mode >= PW), and it must be taken
			 * under the SAME i_flags_lock section as the state —
			 * a mode read outside it can describe a different
			 * instant and would make "NONE at mode>=PW" (broken
			 * recorder) indistinguishable from "NONE at mode<PW"
			 * (genuinely unauthorized modification).
			 *
			 * the last install ATTEMPT rides out of the
			 * same section, for the same reason — the whole point
			 * is to pair it with the state it failed to reach.
			 */
			sn->gen = READ_ONCE(ip->i_mxfs_auth_gen);
			sn->dlm_mode = READ_ONCE(ip->i_dlm_mode);
			sn->auth_line = READ_ONCE(ip->i_mxfs_auth_line);
			sn->try = READ_ONCE(ip->i_mxfs_auth_try);
			sn->try_mode = READ_ONCE(ip->i_mxfs_auth_try_mode);
			sn->try_line = READ_ONCE(ip->i_mxfs_auth_try_line);
			sn->try_epoch = READ_ONCE(ip->i_mxfs_auth_try_epoch);
			sn->try_gen = READ_ONCE(ip->i_mxfs_auth_try_gen);
			sn->unpublished = READ_ONCE(ip->i_dlm_unpublished);

			switch (st) {
			case MXFS_AUTH_UNPUBLISHED_EX:
				out = MXFS_OWNAUTH_UNPUB;
				break;
			case MXFS_AUTH_RELEASING:
				out = MXFS_OWNAUTH_RELEASING;
				break;
			case MXFS_AUTH_DURABLE_EX:
				if (ep) {
					out = MXFS_OWNAUTH_DURABLE;
					sn->epoch = ep;
					sn->res = res;
					sn->lineage = lin;
				} else {
					out = MXFS_OWNAUTH_DURABLE_NOEP;
				}
				break;
			default:
				out = MXFS_OWNAUTH_NONE;
				break;
			}
		}
		spin_unlock(&ip->i_flags_lock);
	}
	rcu_read_unlock();
	xfs_perag_put(pag);
	return out;
}

/*
 * Resolve the INODE arm of the ladder for one image and record it in the
 * P239-OWNAUTH histogram.  Called only from the capture point (sess103): the
 * histogram used to be taken at CIL format time, where — per the sess102
 * ruling — neither `durable` nor `none` means what it appears to mean,
 * because authority may have been acquired or released between the mutation
 * and the format.  Taken at first dirty, the same buckets DO describe the
 * grant that authorized the mutation.
 */
static int
mxfs_ownauth_measure(
	struct xfs_buf			*bp,
	struct xfs_buf_log_format	*blfp,
	struct xfs_mount		*mp,
	struct mxfs_bli_auth		*out)
{
	struct mxfs_buf_owner		own;
	struct mxfs_ownauth_snap	sn;
	uint8_t				mode;
	int				oc;

	mxfs_buf_derive_owner(bp, blfp, &own);
	if (!own.valid) {
		memset(&sn, 0, sizeof(sn));
		oc = MXFS_OWNAUTH_NOOWNER;
	} else {
		oc = mxfs_buf_owner_authority(mp, own.ino, &sn);
	}
	mode = sn.dlm_mode;
	atomic64_inc(&mxfs_ownauth_n[oc]);
	/*
	 * The ruling's decisive cross-tab: of each outcome, how many were
	 * taken while this node held a WRITING mode on the owner.
	 *   DURABLE + writing  -> expected
	 *   NONE    + writing  -> the RECORDER is broken (state-machine gap)
	 *   NONE    + !writing -> a genuinely UNAUTHORIZED modification, a
	 *                         live coherency defect worse than replay
	 */
	if (mxfs_mode_can_write(mode)) {
		atomic64_inc(&mxfs_authcap_mode[oc]);
		/*
		 * P241: the NONE-at-writing-mode population is the one
		 * proved is a recorder gap.  Classify it by the
		 * owner's last install ATTEMPT — that is what names the
		 * missing event.
		 */
		if (oc == MXFS_OWNAUTH_NONE) {
			uint8_t t = sn.try < MXFS_AUTH_TRY_MAX ?
				    sn.try : MXFS_AUTH_TRY_NONE;

			atomic64_inc(&mxfs_authtry_none[t]);
			if (sn.try_gen < sn.gen)
				atomic64_inc(&mxfs_authtry_stale);
			else
				atomic64_inc(&mxfs_authtry_samegen);
			if (printk_ratelimit())
				mxfs_probe("mxfs: P241-AUTHTRY ino=%llu mode=%u try=%u try_mode=%u try_ep=%llu try_line=%u:%u try_gen=%llu gen=%llu line=%u:%u unpub=%u\n",
					(unsigned long long)own.ino,
					(unsigned)mode, (unsigned)sn.try,
					(unsigned)sn.try_mode,
					(unsigned long long)sn.try_epoch,
					MXFS_SITE_ARGS(sn.try_line),
					(unsigned long long)sn.try_gen,
					(unsigned long long)sn.gen,
					MXFS_SITE_ARGS(sn.auth_line),
					(unsigned)sn.unpublished);
		}
	}
	if (oc != MXFS_OWNAUTH_DURABLE) {
		static atomic_t	nondur_n[MXFS_OWNAUTH_MAX];
		uint16_t	bt = xfs_blft_from_flags(blfp);

		if (bt < XFS_BLFT_MAX_BUF)
			atomic64_inc(&mxfs_ownauth_blft[bt]);
		/*
		 * (D-FOREIGN-SLICE-INTENTS-ABANDONED, instrumented): the
		 * wire token flattens every non-durable inode-arm outcome to
		 * MISLABELLED, so the replayer cannot say WHY an image is
		 * classless.  Name each one here, on the producer, bounded
		 * per outcome so a create-heavy lap's UNPUB population cannot
		 * crowd out the rarer outcomes.  The comm attributes the
		 * capture to its path (inodegc worker = inactivation).
		 */
		if (oc < MXFS_OWNAUTH_MAX &&
		    atomic_inc_return(&nondur_n[oc]) <= 48)
			mxfs_probe("mxfs: P239-OWNAUTH-NONDUR blkno=%lld len=%u blft=%u outcome=%d ino=%llu mode=%u unpub=%u gen=%llu try=%u comm=%s\n",
				(long long)xfs_buf_daddr(bp),
				(unsigned)bp->b_length, (unsigned)bt, oc,
				(unsigned long long)(own.valid ? own.ino : 0),
				(unsigned)mode, (unsigned)sn.unpublished,
				(unsigned long long)sn.gen, (unsigned)sn.try,
				current->comm);
	}

	out->mba_owner_ino = own.valid ? own.ino : 0;
	out->mba_dlm_mode = mode;
	out->mba_outcome = (uint8_t)oc;

	/*
	 * Only a DURABLE tenure with a real epoch proves anything.  Every
	 * other outcome maps to the specific non-proving status the sess95
	 * ruling reserved for it — they must not collapse into one bucket,
	 * because recovery has to fail closed DIFFERENTLY per reason.
	 */
	switch (oc) {
	case MXFS_OWNAUTH_DURABLE:
		out->mba_class = MXFS_AUTH_CLASS_INODE;
		out->mba_resource = sn.res;
		out->mba_epoch = sn.epoch;
		out->mba_lineage = sn.lineage;
		out->mba_auth_gen = sn.gen;
		out->mba_status = MXFS_AUTH_ST_VALID;
		break;
	case MXFS_OWNAUTH_NOOWNER:
	case MXFS_OWNAUTH_BADAG:
		out->mba_status = MXFS_AUTH_ST_OWNER_UNKNOWN;
		break;
	case MXFS_OWNAUTH_NOPAG:
		out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
		break;
	case MXFS_OWNAUTH_UNCACHED:
	case MXFS_OWNAUTH_STALE:
		out->mba_status = MXFS_AUTH_ST_AUTH_NOT_CACHED;
		break;
	case MXFS_OWNAUTH_NONE:
	case MXFS_OWNAUTH_UNPUB:
	case MXFS_OWNAUTH_RELEASING:
		out->mba_status = MXFS_AUTH_ST_AUTH_NOT_HELD;
		break;
	case MXFS_OWNAUTH_DURABLE_NOEP:
		out->mba_status = MXFS_AUTH_ST_EPOCH_UNAVAIL;
		break;
	default:
		out->mba_status = MXFS_AUTH_ST_UNPROVEN;
		break;
	}
	return oc;
}

/*
 * step 5.1(d): direct measurement of the false-APPLY exposure the
 * Design-consult ruling predicted from code reading alone.  MISLABEL counts buffers
 * the OLD rule would have stamped class=AG but which are not AG-authorized at
 * all; NOEPOCH counts genuinely AG-authorized buffers that now stamp NONE
 * because the grant-state lifecycle says we do not positively hold the grant.
 * The BLFT histogram is only touched on the mislabel path — that is the
 * population under study.
 */
static atomic64_t	mxfs_tokcls_n;
static atomic64_t	mxfs_tokcls_ag;
static atomic64_t	mxfs_tokcls_sb;
static atomic64_t	mxfs_tokcls_mislabel;
static atomic64_t	mxfs_tokcls_noepoch;
/*
 * step 5.2: two populations v1 could not name.  UNKNOWN is the image
 * whose authority is neither the containing AG nor the superblock — a dir
 * data block, da-node, attr block, symlink or bmbt block, whose real
 * authority is the INODE's EX grant.  That is the population step 5.3 has to
 * capture, and it is the population whose false-SKIP makes this defect
 * critical, so measuring its size is the point of the counter.  INCOMPLETE
 * is a capture failure (no mount identity, or no perag) and must never be
 * normalized into "no authority".
 */
static atomic64_t	mxfs_tokcls_unknown;
static atomic64_t	mxfs_tokcls_incomplete;
static atomic64_t	mxfs_tokcls_blft[XFS_BLFT_MAX_BUF];
/* fix shape B: iunlink DINODE images classified AG (counted inside ag=) */
static atomic64_t	mxfs_tokcls_iunlink_ag;

static const char * const mxfs_ownauth_name[MXFS_OWNAUTH_MAX] = {
	"noowner", "badag", "nopag", "uncached", "stale",
	"none", "unpub", "releasing", "durable", "durnoep",
};

/* Names for the P241 last-install-attempt histogram.  Sparse by design: the
 * MXFS_AUTH_TRY_STATUS_BASE range mirrors enum mxfs_grant_auth_status. */
static const char * const mxfs_authtry_name[MXFS_AUTH_TRY_MAX] = {
	[MXFS_AUTH_TRY_NONE]		= "never",
	[MXFS_AUTH_TRY_INSTALL]		= "install",
	[MXFS_AUTH_TRY_ADVANCE]		= "advance",
	[MXFS_AUTH_TRY_SAMETENURE]	= "sametenure",
	[MXFS_AUTH_TRY_NOGRES]		= "nogres",
	[MXFS_AUTH_TRY_STALEGEN]	= "stalegen",
	[MXFS_AUTH_TRY_RELEASING]	= "releasing",
	[MXFS_AUTH_TRY_UNPUB]		= "unpub",
	[MXFS_AUTH_TRY_ROUTING]		= "routing",
	[MXFS_AUTH_TRY_RECLAIM]		= "reclaim",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_UNSET]		= "st_unset",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_WRITE_EPOCH]	= "st_wrep",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_NONWRITE_MODE]	= "st_nonwr",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_WRITE_ZERO_EPOCH] = "st_wrzero",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_NO_RESOURCE]	= "st_nores",
	[MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_SINGLE_NODE]	= "st_single",
};

/*
 * Two lines, so neither can be truncated by the other: the outcome
 * distribution, then the BLFT mix of everything that was NOT durable.
 */
static void
mxfs_ownauth_report(void)
{
	char	buf[240];
	int	len = 0;
	int	i;
	long long tot = 0;

	for (i = 0; i < MXFS_OWNAUTH_MAX; i++) {
		long long v = atomic64_read(&mxfs_ownauth_n[i]);

		tot += v;
		if (len < (int)sizeof(buf) - 24)
			len += scnprintf(buf + len, sizeof(buf) - len,
					 " %s=%lld", mxfs_ownauth_name[i], v);
	}
	buf[len] = '\0';
	mxfs_probe("mxfs: P239-OWNAUTH n=%lld%s\n", tot, buf);

	len = 0;
	for (i = 0; i < XFS_BLFT_MAX_BUF; i++) {
		long long v = atomic64_read(&mxfs_ownauth_blft[i]);

		if (!v || len >= (int)sizeof(buf) - 24)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " t%d=%lld",
				 i, v);
	}
	buf[len] = '\0';
	mxfs_probe("mxfs: P239-OWNAUTH-NONDURABLE-blft:%s\n", len ? buf : " none");
}

static void mxfs_authcap_report(void);

static void
mxfs_tokcls_report(void)
{
	extern void mxfs_inact_cert_report(void);
	char	buf[160];
	int	len = 0;
	int	i;

	/* fix shape A census rides beside the token-class census */
	mxfs_inact_cert_report();

	for (i = 0; i < XFS_BLFT_MAX_BUF; i++) {
		long long v = atomic64_read(&mxfs_tokcls_blft[i]);

		if (!v || len >= (int)sizeof(buf) - 24)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " t%d=%lld",
				 i, v);
	}
	buf[len] = '\0';
	mxfs_probe("mxfs: P228-TOKCLASS n=%lld ag=%lld iunlink_ag=%lld sb=%lld mislabel=%lld noepoch=%lld unknown=%lld incomplete=%lld mis_blft:%s\n",
		(long long)atomic64_read(&mxfs_tokcls_n),
		(long long)atomic64_read(&mxfs_tokcls_ag),
		(long long)atomic64_read(&mxfs_tokcls_iunlink_ag),
		(long long)atomic64_read(&mxfs_tokcls_sb),
		(long long)atomic64_read(&mxfs_tokcls_mislabel),
		(long long)atomic64_read(&mxfs_tokcls_noepoch),
		(long long)atomic64_read(&mxfs_tokcls_unknown),
		(long long)atomic64_read(&mxfs_tokcls_incomplete),
		len ? buf : " none");
	mxfs_ownauth_report();
	mxfs_authcap_report();
}

/*
 * ─── step 5.3, ruling P0/P1: CAPTURE AT FIRST PROTECTED DIRTY ───
 *
 * Runs the whole classification ladder ONCE, at the seam where the mutation
 * becomes attributable to a tenure, and writes the answer into the buf log
 * item.  xfs_buf_item_format_segment then only SERIALIZES it.
 *
 * Ladder (unchanged in substance from the format-time version it replaces —
 * only the instant it is evaluated at has changed, which is the entire fix):
 *   superblock            -> CLASS_SB, UNPROVEN (no grant epoch to name)
 *   AG-authorized + epoch -> CLASS_AG, VALID
 *   AG-authorized, no epoch -> UNPROVEN (we do not positively hold the grant)
 *   holds an AG grant that is not this buffer's authority -> MISLABELLED,
 *                            then resolved on the INODE arm
 *   neither               -> the inode-authority population, INODE arm
 *
 * The mount identity is captured here too: a record that cannot be bound to
 * an emitting incarnation is not evidence about any victim, so an identity
 * failure DOMINATES every classification above it.
 */
static void
mxfs_auth_classify(
	struct xfs_trans		*tp,
	struct xfs_buf_log_item		*bip,
	struct xfs_mount		*mp,
	struct mxfs_bli_auth		*out)
{
	struct xfs_buf			*bp = bip->bli_buf;
	/*
	 * The BLFT lives in __bli_format for EVERY buffer — xfs_trans_buf_
	 * set_type writes only there, and format_segment copies it into each
	 * segment.  blf_blkno does NOT: for a discontiguous buffer the
	 * per-map array holds the real block numbers and __bli_format is left
	 * zeroed, so the AG must come from map 0 (which is also the only map
	 * whose header the owner derivation reads).
	 */
	struct xfs_buf_log_format	*blfp = &bip->__bli_format;
	xfs_daddr_t			blkno = bip->bli_formats[0].blf_blkno;
	xfs_agnumber_t			agno;
	uint16_t			blft = xfs_blft_from_flags(blfp);

	memset(out, 0, sizeof(*out));
	out->mba_class = MXFS_AUTH_CLASS_NONE;
	out->mba_status = MXFS_AUTH_ST_UNPROVEN;
	out->mba_blft = blft;
	out->mba_outcome = MXFS_OWNAUTH_MAX;	/* "inode arm not taken" */

	/*
	 * The BLFT is the second, independent witness both mxfs_buf_ag_
	 * authorized() and the owner derivation require.  If the type has not
	 * been set yet, no derivation this build trusts can succeed, and a
	 * capture that silently proceeds would manufacture OWNER_UNKNOWN for a
	 * perfectly ordinary buffer.  Count it and fail closed.
	 */
	if (blft <= XFS_BLFT_UNKNOWN_BUF || blft >= XFS_BLFT_MAX_BUF) {
		atomic64_inc(&mxfs_authcap_noblft);
		out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
		return;
	}

	atomic64_inc(&mxfs_tokcls_n);

	if (bp->b_ops == &xfs_sb_buf_ops) {
		out->mba_class = MXFS_AUTH_CLASS_SB;
		out->mba_status = MXFS_AUTH_ST_UNPROVEN;
		atomic64_inc(&mxfs_tokcls_sb);
		goto identity;
	}

	agno = xfs_daddr_to_agno(mp, blkno);
	if (agno >= mp->m_sb.sb_agcount) {
		out->mba_status = MXFS_AUTH_ST_UNPROVEN;
		atomic64_inc(&mxfs_tokcls_unknown);
		goto identity;
	}

	{
		struct xfs_perag	*apag = xfs_perag_get(mp, agno);
		uint64_t		ge;
		bool			auth;

		if (!apag) {
			out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
			atomic64_inc(&mxfs_tokcls_incomplete);
			goto identity;
		}
		ge = READ_ONCE(apag->pag_mxfs_grant_epoch);
		auth = mxfs_buf_ag_authorized(bp, blfp);
		/*
		 * fix shape B: the iunlink form of an inode-cluster
		 * image is AG-authorized (see mxfs_buf_iunlink_ag_authorized).
		 * Only with a durable epoch — the same "we positively hold the
		 * grant" rule as every other AG image; without one it stays
		 * NOEPOCH/UNPROVEN rather than falling to the inode arm, which
		 * has no owner for it anyway.
		 */
		if (!auth && ge &&
		    mxfs_buf_iunlink_ag_authorized(tp, bip, mp, agno, blft)) {
			static atomic_t iunl_n = ATOMIC_INIT(0);

			auth = true;
			atomic64_inc(&mxfs_tokcls_iunlink_ag);
			if (atomic_inc_return(&iunl_n) <= 24)
				mxfs_probe("mxfs: P-IUNLINK-AGCLASS blkno=%lld len=%u ag=%u epoch=%llu ino0=%llu comm=%s — di_next_unlinked image classified under the AG grant (fix shape B)\n",
					(long long)blkno, (unsigned)bp->b_length,
					(unsigned)agno, (unsigned long long)ge,
					(unsigned long long)be64_to_cpu(
					    ((const struct xfs_dinode *)
					     xfs_buf_offset(bp, 0))->di_ino),
					current->comm);
		}

		/*
		 * An inode-cluster image that reaches here unauthorized is the
		 * population a foreign replay refuses: the inode arm cannot
		 * derive an owner for it, so it goes out classless and one
		 * ATOMIC-SKIP abandons the whole committed transaction.  Name
		 * the discriminators the AG arm above tested — which logging
		 * form the buffer is in, whether we hold the AG's grant epoch,
		 * and which ops it carries — so the refusal is attributed to a
		 * producer condition here rather than inferred from the token
		 * the replayer finally sees.  Bounded; diagnostic only.
		 */
		if (!auth && blft == XFS_BLFT_DINO_BUF) {
			static atomic_t dinona_n = ATOMIC_INIT(0);

			if (atomic_inc_return(&dinona_n) <= 48)
				mxfs_probe("mxfs: P239-DINO-NOAUTH blkno=%lld len=%u ag=%u ge=%llu bli_flags=0x%x blf_flags=0x%x inode_ops=%d comm=%s — inode-cluster image is not AG-authorized and the inode arm has no owner for it\n",
					(long long)blkno, (unsigned)bp->b_length,
					(unsigned)agno, (unsigned long long)ge,
					(unsigned)bip->bli_flags,
					(unsigned)blfp->blf_flags,
					bp->b_ops == &xfs_inode_buf_ops ? 1 : 0,
					current->comm);
		}

		if (auth && ge) {
			out->mba_class = MXFS_AUTH_CLASS_AG;
			out->mba_resource = agno;
			out->mba_epoch = ge;
			out->mba_lineage =
				READ_ONCE(apag->pag_mxfs_grant_lineage);
			out->mba_status = MXFS_AUTH_ST_VALID;
			atomic64_inc(&mxfs_tokcls_ag);
		} else if (!auth && ge) {
			atomic64_inc(&mxfs_tokcls_mislabel);
			if (blft < XFS_BLFT_MAX_BUF)
				atomic64_inc(&mxfs_tokcls_blft[blft]);
			mxfs_ownauth_measure(bp, blfp, mp, out);
			/*
			 * 0.75.82: keep the reason the inode arm gave.  This
			 * arm used to overwrite every non-VALID answer with
			 * MISLABELLED, which is the coarsest of the five and
			 * says only "we held an AG grant that is not this
			 * buffer's authority" — a fact the arm itself already
			 * states.  The ruling reserved a distinct status
			 * per outcome precisely because recovery has to fail
			 * closed DIFFERENTLY per reason, and P239-OWNAUTH-NONDUR
			 * exists on the producer only because the wire token had
			 * lost it.  A producer's log does not survive the death
			 * that makes the token matter: measured 2026-09-09, a
			 * slice was refused over 'P227-TOKEN blft=13 class=0
			 * st=4' and 'blft=11 class=0 st=4' with the victim's
			 * journal already gone with its VM
			 * (tests/evidence/20260909T153444Z_ghost_s571a), so the
			 * whole AG was quarantined on a reason nobody could
			 * name.  MISLABELLED now means what it says: the inode
			 * arm had nothing more specific to add.
			 *
			 * Nothing about admission changes.  mxfs_auth_st_proves
			 * is VALID and nothing else, the replayer's gate refuses
			 * on `status != VALID`, and every status below is
			 * already inside the fixed wire contract (< _MAX) and
			 * already emitted by this same helper on the arm one
			 * branch down.
			 */
			if (out->mba_status == MXFS_AUTH_ST_UNPROVEN)
				out->mba_status = MXFS_AUTH_ST_MISLABELLED;
		} else if (auth) {
			out->mba_status = MXFS_AUTH_ST_UNPROVEN;
			atomic64_inc(&mxfs_tokcls_noepoch);
		} else {
			atomic64_inc(&mxfs_tokcls_unknown);
			mxfs_ownauth_measure(bp, blfp, mp, out);
		}
		xfs_perag_put(apag);
	}

identity:
	{
		uint32_t oslot = 0, onode = 0;
		uint64_t oepoch = 0;

		if (!mxfs_v5_dlm_mount_identity(mp->m_mxfs_dlm, &oslot, &onode,
						&oepoch)) {
			out->mba_class = MXFS_AUTH_CLASS_NONE;
			out->mba_resource = 0;
			out->mba_epoch = 0;
			out->mba_status = MXFS_AUTH_ST_INCOMPLETE;
			atomic64_inc(&mxfs_tokcls_incomplete);
		}
	}
}

/*
 * Do two classifications describe the SAME authority?  Compared on the
 * proving fields only — the diagnostic ones (outcome, dlm_mode) are allowed
 * to differ between two instants without the proof being contradicted.
 */
static bool
mxfs_auth_same(
	const struct mxfs_bli_auth	*a,
	const struct mxfs_bli_auth	*b)
{
	return a->mba_class == b->mba_class &&
	       a->mba_status == b->mba_status &&
	       a->mba_resource == b->mba_resource &&
	       a->mba_epoch == b->mba_epoch &&
	       a->mba_lineage == b->mba_lineage &&
	       a->mba_owner_ino == b->mba_owner_ino &&
	       a->mba_auth_gen == b->mba_auth_gen;
}

/*
 * (CANCEL authority tokens, design-consult verification bar — the NEGATIVE
 * tests): forge the proof captured for a CANCEL record so foreign replay
 * must REFUSE the freeing transaction, keep its cancel entries OUT of the
 * pass-1 table, and leave the block's earlier admitted image unsuppressed.
 *   dbg_cancel_token_forge=1  skew the grant epoch (+1): replay stale_epoch
 *   dbg_cancel_token_forge=2  mis-target the resource (+1): replay not_held /
 *                             wrong_lineage — authority for ANOTHER object
 * Sticky while set (the arm resets it by module reload); never in production.
 */
int mxfs_dbg_cancel_token_forge;
module_param_named(dbg_cancel_token_forge, mxfs_dbg_cancel_token_forge, int, 0644);
MODULE_PARM_DESC(dbg_cancel_token_forge,
	"DEBUG: forge the authority proof of every CANCEL record captured at xfs_trans_binval: 1=skew grant epoch, 2=mis-target resource (sess476 negative arms)");
static atomic64_t mxfs_dbg_cancel_forged = ATOMIC64_INIT(0);

void
mxfs_dbg_cancel_token_forge_apply(
	struct xfs_buf		*bp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct mxfs_bli_auth	*cap;
	int			mode = READ_ONCE(mxfs_dbg_cancel_token_forge);

	if (likely(!mode) || !bip)
		return;
	cap = &bip->bli_mxfs_auth;
	if (!cap->mba_capseq || cap->mba_status != MXFS_AUTH_ST_VALID)
		return;		/* nothing proven to forge: leave it as-is */
	if (mode == 1)
		cap->mba_epoch += 1;
	else
		cap->mba_resource += 1;
	if (atomic64_inc_return(&mxfs_dbg_cancel_forged) <= 400)
		mxfs_probe("mxfs: P-DBG-CANCEL-FORGE mode=%d blkno=%lld len=%u blft=%u class=%u res=%llu epoch=%llu owner_ino=%llu comm=%s — INJECTED: CANCEL proof forged\n",
			mode, (long long)bip->bli_formats[0].blf_blkno,
			(unsigned)bip->bli_formats[0].blf_len,
			(unsigned)cap->mba_blft, (unsigned)cap->mba_class,
			(unsigned long long)cap->mba_resource,
			(unsigned long long)cap->mba_epoch,
			(unsigned long long)cap->mba_owner_ino, current->comm);
}

/*
 * Capture the authority proof for `bp` in `tp`'s window.  Called from
 * xfs_trans_dirty_buf — the single seam every buffer passes through to become
 * dirty in a transaction, and the earliest point at which the mutation is
 * attributable to a tenure.
 *
 * Idempotent within a window: the FIRST capture is immutable.  A re-log in
 * the same window is re-resolved and compared, because the ruling requires
 * that "one buffer, two authorities" be DETECTED rather than silently
 * resolved to whichever tenure happened to be current last.
 */
void
mxfs_bli_auth_capture(
	struct xfs_trans	*tp,
	struct xfs_buf		*bp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct mxfs_bli_auth	*cap;
	struct xfs_mount	*mp;
	uint64_t		seq;

	if (!bip || !tp)
		return;
	mp = bp->b_mount;
	if (!mp || !mxfs_buf_item_wants_authority(bip))
		return;

	/*
	 * An already-stale buffer logs nothing but its cancel record, whose
	 * proof was captured by xfs_trans_binval BEFORE the stale conversion
	 * a later call here would describe a type-less image and
	 * must not disturb that proof.
	 */
	if (bip->bli_flags & XFS_BLI_STALE)
		return;

	/*
	 * Window key.  Lazily assigned so no edit to the transaction alloc
	 * paths is needed; a transaction is owned by exactly one thread, so
	 * the read-modify-write needs no lock.  See t_mxfs_capseq.
	 */
	seq = tp->t_mxfs_capseq;
	if (!seq) {
		static atomic64_t next = ATOMIC64_INIT(0);

		seq = (uint64_t)atomic64_inc_return(&next);
		tp->t_mxfs_capseq = seq;
	}

	cap = &bip->bli_mxfs_auth;
	if (cap->mba_capseq == seq && cap->mba_retype_pending) {
		struct mxfs_bli_auth	now;

		/*
		 * A′: first protected dirty under the NEW type.  The
		 * image is initialised for that type now (the re-typing path
		 * writes its header before it logs), so the owner derivation
		 * is trustworthy here and nowhere earlier.  The original proof
		 * is compared, never replaced: only the witness may move.
		 */
		if (mxfs_authcap_inject == 2) {
			mxfs_probe_ratelimited("mxfs: P-AUTHCAP-INJECT mode=2 blkno=%lld — leaving the re-type PENDING (token will be voided at commit)\n",
				(long long)bip->bli_formats[0].blf_blkno);
			return;
		}
		mxfs_auth_classify(tp, bip, mp, &now);
		if (now.mba_status == MXFS_AUTH_ST_VALID &&
		    mxfs_auth_same(cap, &now) && mxfs_authcap_inject != 1) {
			cap->mba_blft = now.mba_blft;
			cap->mba_outcome = now.mba_outcome;
			cap->mba_dlm_mode = now.mba_dlm_mode;
			cap->mba_retype_pending = 0;
			atomic64_inc(&mxfs_authcap_retype_ok);
			{
				static atomic_t ok_n = ATOMIC_INIT(0);

				if (atomic_inc_return(&ok_n) <= 50)
					mxfs_probe("mxfs: P-AUTHCAP-RETYPE-OK blkno=%lld len=%u blft_now=%u class=%u res=%llu epoch=%llu owner_ino=%llu comm=%s\n",
						(long long)bip->bli_formats[0].blf_blkno,
						(unsigned)bip->bli_formats[0].blf_len,
						(unsigned)now.mba_blft,
						(unsigned)cap->mba_class,
						(unsigned long long)cap->mba_resource,
						(unsigned long long)cap->mba_epoch,
						(unsigned long long)cap->mba_owner_ino,
						current->comm);
			}
		} else if (now.mba_status == MXFS_AUTH_ST_VALID) {
			/* proves a DIFFERENT authority (or the injected one) */
			if (mxfs_authcap_inject == 1)
				mxfs_probe_ratelimited("mxfs: P-AUTHCAP-INJECT mode=1 blkno=%lld — recording the re-proof as MIXED\n",
					(long long)bip->bli_formats[0].blf_blkno);
			cap->mba_blft = now.mba_blft;
			cap->mba_status = MXFS_AUTH_ST_MIXED;
			cap->mba_retype_pending = 0;
			atomic64_inc(&mxfs_authcap_retype_mixed);
			mxfs_probe_ratelimited("mxfs: P-AUTHCAP-RETYPE-MIXED blkno=%lld blft=%u class_cap=%u res_cap=%llu class_now=%u res_now=%llu comm=%s\n",
				(long long)bip->bli_formats[0].blf_blkno,
				(unsigned)now.mba_blft, (unsigned)cap->mba_class,
				(unsigned long long)cap->mba_resource,
				(unsigned)now.mba_class,
				(unsigned long long)now.mba_resource,
				current->comm);
		} else {
			/* cannot prove under the new type: the old proof is
			 * not evidence about this image any more */
			uint64_t capseq = cap->mba_capseq;

			*cap = now;
			cap->mba_capseq = capseq;
			cap->mba_retype_pending = 0;
			atomic64_inc(&mxfs_authcap_retype_unproven);
			pr_warn_ratelimited("mxfs: P-AUTHCAP-VOID why=retype_unproven blkno=%lld len=%u blft=%u st=%u outcome=%u owner_ino=%llu comm=%s\n",
				(long long)bip->bli_formats[0].blf_blkno,
				(unsigned)bip->bli_formats[0].blf_len,
				(unsigned)now.mba_blft, (unsigned)now.mba_status,
				(unsigned)now.mba_outcome,
				(unsigned long long)now.mba_owner_ino,
				current->comm);
		}
		return;
	}
	if (cap->mba_capseq == seq) {
		struct mxfs_bli_auth	now;

		atomic64_inc(&mxfs_authcap_relog);
		mxfs_auth_classify(tp, bip, mp, &now);
		if (!mxfs_auth_same(cap, &now)) {
			/*
			 * Two provenances in one whole-buffer image.  A single
			 * token cannot represent it, and picking either one
			 * would be a fabricated proof — MIXED says so, and
			 * MIXED does not prove (mxfs_auth_st_proves).
			 */
			atomic64_inc(&mxfs_authcap_mismatch);
			cap->mba_status = MXFS_AUTH_ST_MIXED;
		}
		return;
	}

	{
		long long w = atomic64_inc_return(&mxfs_authcap_win);

		mxfs_auth_classify(tp, bip, mp, cap);
		cap->mba_capseq = seq;
		cap->mba_retype_pending = 0;
		/*
		 * Report from the CAPTURE path, not the format path: the
		 * trap note measured that the old (tn & 8191) trigger
		 * advanced only ONE node of 32 past a boundary across a whole
		 * 8-criterion dir-heavy chunk, so the sample was one node's,
		 * not the fleet's.  1023 gives 8x the resolution at the same
		 * cost per report.
		 */
		if ((w & 1023) == 0)
			mxfs_tokcls_report();
	}
}

/*
 * A′: xfs_trans_buf_set_type changed the BLFT of a buffer that may
 * already hold a capture in this transaction window.  NEVER classify here —
 * the re-typing path has not written the new format's header yet (STOP-SHIP
 * 1 of the ruling); only mark the capture pending so the next protected
 * dirty re-proves it, and so a commit without one voids it.  Several
 * re-types before the next dirty collapse to whatever type is current then.
 */
void
mxfs_bli_auth_note_retype(
	struct xfs_trans	*tp,
	struct xfs_buf		*bp,
	uint16_t		new_blft)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	struct mxfs_bli_auth	*cap;

	if (!bip || !tp || !bp->b_mount || !mxfs_buf_item_wants_authority(bip))
		return;
	cap = &bip->bli_mxfs_auth;
	if (!cap->mba_capseq || cap->mba_capseq != tp->t_mxfs_capseq)
		return;			/* no capture in this window yet */
	cap->mba_retype_pending = (new_blft != cap->mba_blft) ? 1 : 0;
}

static void
mxfs_authcap_report(void)
{
	char	buf[280];
	int	len = 0;
	int	i;

	for (i = 0; i < MXFS_OWNAUTH_MAX; i++) {
		long long v = atomic64_read(&mxfs_authcap_mode[i]);

		if (!v || len >= (int)sizeof(buf) - 28)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " %s=%lld",
				 mxfs_ownauth_name[i], v);
	}
	buf[len] = '\0';
	mxfs_probe("mxfs: P240-AUTHCAP win=%lld relog=%lld mismatch=%lld noblft=%lld blftchg=%lld nocap=%lld retype_ok=%lld retype_mixed=%lld retype_unproven=%lld retype_nodirty=%lld pw_by_outcome:%s\n",
		(long long)atomic64_read(&mxfs_authcap_win),
		(long long)atomic64_read(&mxfs_authcap_relog),
		(long long)atomic64_read(&mxfs_authcap_mismatch),
		(long long)atomic64_read(&mxfs_authcap_noblft),
		(long long)atomic64_read(&mxfs_authcap_blftchg),
		(long long)atomic64_read(&mxfs_authcap_nocap),
		(long long)atomic64_read(&mxfs_authcap_retype_ok),
		(long long)atomic64_read(&mxfs_authcap_retype_mixed),
		(long long)atomic64_read(&mxfs_authcap_retype_unproven),
		(long long)atomic64_read(&mxfs_authcap_retype_nodirty),
		len ? buf : " none");

	/*
	 * P241 — the same population, classified by the owner's last install
	 * ATTEMPT.  This is the line that names the missing event.
	 */
	len = 0;
	for (i = 0; i < MXFS_AUTH_TRY_MAX; i++) {
		long long v = atomic64_read(&mxfs_authtry_none[i]);

		if (!v || len >= (int)sizeof(buf) - 28)
			continue;
		len += scnprintf(buf + len, sizeof(buf) - len, " %s=%lld",
				 mxfs_authtry_name[i] ? mxfs_authtry_name[i] :
				 "?", v);
	}
	buf[len] = '\0';
	mxfs_probe("mxfs: P241-AUTHTRY nonewr_samegen=%lld nonewr_stalegen=%lld by_try:%s\n",
		(long long)atomic64_read(&mxfs_authtry_samegen),
		(long long)atomic64_read(&mxfs_authtry_stale),
		len ? buf : " none");
}

/*
 * Return the number of log iovecs and space needed to log the given buf log
 * item segment.
 *
 * It calculates this as 1 iovec for the buf log format structure and 1 for each
 * stretch of non-contiguous chunks to be logged.  Contiguous chunks are logged
 * in a single iovec.
 */
STATIC void
xfs_buf_item_size_segment(
	struct xfs_buf_log_item		*bip,
	struct xfs_buf_log_format	*blfp,
	uint				offset,
	int				*nvecs,
	int				*nbytes)
{
	int				first_bit;
	int				nbits;

	first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size, 0);
	if (first_bit == -1)
		return;

	(*nvecs)++;
	*nbytes += xfs_buf_log_format_size(blfp);
	/*
	 * authority token (step 3a): multi-node buf format regions
	 * carry a fixed-size trailer, MXFS_BLF_AUTHORITY_SIZE bytes — 48 as
	 * of the v3 wire (see mxfs_blf_authority_v3).  MUST mirror
	 * the emission condition in xfs_buf_item_format_segment exactly —
	 * an underestimate here overruns the CIL shadow buffer.  Stale
	 * items never reach this function (handled in xfs_buf_item_size,
	 * which reserves the same trailer for the CANCEL record —).
	 */
	if (mxfs_buf_item_wants_authority(bip))
		*nbytes += MXFS_BLF_AUTHORITY_SIZE;

	do {
		nbits = xfs_contig_bits(blfp->blf_data_map,
					blfp->blf_map_size, first_bit);
		ASSERT(nbits > 0);
		(*nvecs)++;
		*nbytes += nbits * XFS_BLF_CHUNK;

		/*
		 * This takes the bit number to start looking from and
		 * returns the next set bit from there.  It returns -1
		 * if there are no more bits set or the start bit is
		 * beyond the end of the bitmap.
		 */
		first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size,
					(uint)first_bit + nbits + 1);
	} while (first_bit != -1);

	return;
}

/*
 * Compute the worst case log item overhead for an invalidated buffer with the
 * given map count and block size.
 */
unsigned int
xfs_buf_inval_log_space(
	unsigned int	map_count,
	unsigned int	blocksize)
{
	unsigned int	chunks = DIV_ROUND_UP(blocksize, XFS_BLF_CHUNK);
	unsigned int	bitmap_size = DIV_ROUND_UP(chunks, NBWORD);
	unsigned int	ret =
		offsetof(struct xfs_buf_log_format, blf_data_map) +
			(bitmap_size * sizeof_field(struct xfs_buf_log_format,
						    blf_data_map[0]));

	return ret * map_count;
}

/*
 * Return the number of log iovecs and space needed to log the given buf log
 * item.
 *
 * Discontiguous buffers need a format structure per region that is being
 * logged. This makes the changes in the buffer appear to log recovery as though
 * they came from separate buffers, just like would occur if multiple buffers
 * were used instead of a single discontiguous buffer. This enables
 * discontiguous buffers to be in-memory constructs, completely transparent to
 * what ends up on disk.
 *
 * If the XFS_BLI_STALE flag has been set, then log nothing but the buf log
 * format structures. If the item has previously been logged and has dirty
 * regions, we do not relog them in stale buffers. This has the effect of
 * reducing the size of the relogged item by the amount of dirty data tracked
 * by the log item. This can result in the committing transaction reducing the
 * amount of space being consumed by the CIL.
 */
STATIC void
xfs_buf_item_size(
	struct xfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	int			i;
	int			bytes;
	uint			offset = 0;

	ASSERT(atomic_read(&bip->bli_refcount) > 0);
	if (bip->bli_flags & XFS_BLI_STALE) {
		/*
		 * The buffer is stale, so all we need to log is the buf log
		 * format structure with the cancel flag in it as we are never
		 * going to replay the changes tracked in the log item.
		 */
		trace_xfs_buf_item_size_stale(bip);
		ASSERT(bip->__bli_format.blf_flags & XFS_BLF_CANCEL);
		*nvecs += bip->bli_format_count;
		for (i = 0; i < bip->bli_format_count; i++) {
			*nbytes += xfs_buf_log_format_size(&bip->bli_formats[i]);
			/*
			 * a CANCEL record carries the authority
			 * trailer too (captured at xfs_trans_binval).  MUST
			 * mirror xfs_buf_item_format_segment's emission
			 * condition exactly — an underestimate overruns the
			 * CIL shadow buffer.
			 */
			if (mxfs_buf_item_wants_authority(bip))
				*nbytes += MXFS_BLF_AUTHORITY_SIZE;
		}
		return;
	}

	ASSERT(bip->bli_flags & XFS_BLI_LOGGED);

	if (bip->bli_flags & XFS_BLI_ORDERED) {
		/*
		 * The buffer has been logged just to order it. It is not being
		 * included in the transaction commit, so no vectors are used at
		 * all.
		 */
		trace_xfs_buf_item_size_ordered(bip);
		*nvecs = XFS_LOG_VEC_ORDERED;
		return;
	}

	/*
	 * The vector count is based on the number of buffer vectors we have
	 * dirty bits in. This will only be greater than one when we have a
	 * compound buffer with more than one segment dirty. Hence for compound
	 * buffers we need to track which segment the dirty bits correspond to,
	 * and when we move from one segment to the next increment the vector
	 * count for the extra buf log format structure that will need to be
	 * written.
	 */
	bytes = 0;
	for (i = 0; i < bip->bli_format_count; i++) {
		xfs_buf_item_size_segment(bip, &bip->bli_formats[i], offset,
					  nvecs, &bytes);
		offset += BBTOB(bp->b_maps[i].bm_len);
	}

	/*
	 * Round up the buffer size required to minimise the number of memory
	 * allocations that need to be done as this item grows when relogged by
	 * repeated modifications.
	 */
	*nbytes = round_up(bytes, 512);
	trace_xfs_buf_item_size(bip);
}

static inline void *
xfs_buf_item_copy_iovec(
	struct xlog_format_buf	*lfb,
	struct xfs_buf		*bp,
	uint			offset,
	int			first_bit,
	uint			nbits)
{
	offset += first_bit * XFS_BLF_CHUNK;
	return xlog_format_copy(lfb, XLOG_REG_TYPE_BCHUNK,
			xfs_buf_offset(bp, offset), nbits * XFS_BLF_CHUNK);
}

/*
 * TEST-ONLY — EXERCISE THE INODE-BUFFER REPLAY GUARD BY SUBSTITUTING AT THE
 * DURABLE WRITE RATHER THAN AT THE CHECK.
 *
 * xlog_recover_do_inode_buffer refuses a logged inode-cluster image whose
 * di_next_unlinked is not an agino of the image's own AG, and one whose daddr
 * and length straddle an AG boundary.  Both fire only on a value this build
 * will never write, so running the code cannot reach either of them and the
 * guard would ship unexercised.  The substitution therefore happens HERE, at
 * the point the image becomes durable: the bytes copied into the log vector
 * are changed and the buffer that goes to the platter is not, so the log
 * carries exactly what a corrupt or foreign producer could have written while
 * every check between here and the refusal is left intact.
 *
 * Each knob is cleared ONLY when its substitution actually lands.  An arming
 * that finds no inode-buffer image stays armed and says so, because a lap that
 * reported a refusal it never provoked would be measuring nothing.
 */
int mxfs_dbg_recov_inject_agino;
int mxfs_dbg_recov_inject_straddle;

static void
mxfs_dbg_inject_logged_blf(
	struct xfs_buf			*bp,
	struct xfs_buf_log_format	*blfp)
{
	struct xfs_mount	*mp = bp->b_mount;
	xfs_agnumber_t		agno;
	xfs_daddr_t		boundary;

	if (!(blfp->blf_flags & XFS_BLF_INODE_BUF) ||
	    (blfp->blf_flags & XFS_BLF_CANCEL) || !mp) {
		/*
		 * 0.89.42 — THE SILENT RETURN WAS THE WHOLE MEASUREMENT.
		 *
		 * This arm's contract, stated above, is that an arming which
		 * finds no inode-buffer image stays armed AND SAYS SO.  It did
		 * not: this test — the one every image that is not an inode
		 * buffer fails — returned without a word, so a lap could not
		 * tell "the injector was never called" from "it was called on
		 * every image and rejected them all".  Measured on 0.89.41:
		 * both arms aborted with fired=0 AND declined=0, which named
		 * neither case.  Rate-limited because every dirty buffer in
		 * the window reaches here, and one line per reason is the
		 * evidence; a flood is not.
		 */
		pr_err_ratelimited("mxfs: P-INJ-LOGGED-BLF-DECLINED daddr=%lld flags=0x%x mp=%d — not an inode-buffer image (or a cancel record); the knob stays armed\n",
				   (long long)blfp->blf_blkno,
				   (unsigned int)blfp->blf_flags, mp ? 1 : 0);
		return;
	}
	if (blfp->blf_len < 2) {
		pr_err("mxfs: P-INJ-LOGGED-BLF-DECLINED daddr=%lld len=%u — a one-block image cannot straddle anything; the knob stays armed\n",
		       (long long)blfp->blf_blkno, blfp->blf_len);
		return;
	}

	agno = xfs_daddr_to_agno(mp, blfp->blf_blkno);
	if (agno + 1 >= mp->m_sb.sb_agcount) {
		pr_err("mxfs: P-INJ-LOGGED-BLF-DECLINED daddr=%lld agno=%u agcount=%u — the image sits in the last AG, so no daddr below it crosses a boundary; the knob stays armed\n",
		       (long long)blfp->blf_blkno, agno, mp->m_sb.sb_agcount);
		return;
	}
	boundary = XFS_AGB_TO_DADDR(mp, agno + 1, 0);
	pr_err("mxfs: P-INJ-LOGGED-BLF straddle daddr=%lld -> %lld len=%u agno=%u boundary=%lld — TEST: the LOG image now names an inode cluster that crosses an AG boundary; the buffer written to the platter is unchanged\n",
	       (long long)blfp->blf_blkno, (long long)(boundary - 1),
	       blfp->blf_len, agno, (long long)boundary);
	blfp->blf_blkno = boundary - 1;
	mxfs_dbg_recov_inject_straddle = 0;
}

static void
mxfs_dbg_inject_logged_agino(
	struct xfs_buf			*bp,
	struct xfs_buf_log_format	*blfp,
	void				*dst,
	uint				offset,
	int				first_bit,
	uint				nbits)
{
	struct xfs_mount	*mp = bp->b_mount;
	uint			isize, seg_start, seg_end, nu, i, ninodes;
	__be32			*p;

	if (!dst || !mp || !(blfp->blf_flags & XFS_BLF_INODE_BUF) ||
	    (blfp->blf_flags & XFS_BLF_CANCEL)) {
		/* see the companion note in mxfs_dbg_inject_logged_blf */
		pr_err_ratelimited("mxfs: P-INJ-LOGGED-AGINO-DECLINED daddr=%lld flags=0x%x dst=%d mp=%d — not an inode-buffer image (or a cancel record); the knob stays armed\n",
				   (long long)blfp->blf_blkno,
				   (unsigned int)blfp->blf_flags,
				   dst ? 1 : 0, mp ? 1 : 0);
		return;
	}

	isize = mp->m_sb.sb_inodesize;
	if (!isize) {
		pr_err_ratelimited("mxfs: P-INJ-LOGGED-AGINO-DECLINED daddr=%lld — the mount reports inode size 0; the knob stays armed\n",
				   (long long)blfp->blf_blkno);
		return;
	}
	seg_start = offset + (uint)first_bit * XFS_BLF_CHUNK;
	seg_end = seg_start + nbits * XFS_BLF_CHUNK;
	ninodes = BBTOB(bp->b_length) / isize;

	for (i = 0; i < ninodes; i++) {
		nu = i * isize + offsetof(struct xfs_dinode, di_next_unlinked);
		if (nu < seg_start)
			continue;
		if (nu + sizeof(__be32) > seg_end)
			break;
		p = (__be32 *)((char *)dst + (nu - seg_start));
		pr_err("mxfs: P-INJ-LOGGED-AGINO daddr=%lld inode=%u di_next_unlinked 0x%x -> 0x%x — TEST: the LOG image now carries an agino no AG of this filesystem contains; the buffer written to the platter is unchanged\n",
		       (long long)blfp->blf_blkno, i, be32_to_cpu(*p),
		       (unsigned int)mxfs_dbg_recov_inject_agino);
		*p = cpu_to_be32((uint32_t)mxfs_dbg_recov_inject_agino);
		mxfs_dbg_recov_inject_agino = 0;
		return;
	}
	/*
	 * An inode-buffer image whose logged range holds no di_next_unlinked
	 * at all — the third way this arm used to fail without saying so.
	 * The range is printed because it is what decides the answer.
	 */
	pr_err_ratelimited("mxfs: P-INJ-LOGGED-AGINO-DECLINED daddr=%lld seg=[%u,%u) ninodes=%u isize=%u — an inode-buffer image, but its logged range carries no di_next_unlinked; the knob stays armed\n",
			   (long long)blfp->blf_blkno, seg_start, seg_end,
			   ninodes, isize);
}

static void
xfs_buf_item_format_segment(
	struct xfs_buf_log_item	*bip,
	struct xlog_format_buf	*lfb,
	uint			offset,
	struct xfs_buf_log_format *blfp)
{
	struct xfs_buf		*bp = bip->bli_buf;
	uint			base_size;
	int			first_bit;
	uint			nbits;

	/* copy the flags across from the base format item */
	blfp->blf_flags = bip->__bli_format.blf_flags;

	/*
	 * Base size is the actual size of the ondisk structure - it reflects
	 * the actual size of the dirty bitmap rather than the size of the in
	 * memory structure.
	 */
	base_size = xfs_buf_log_format_size(blfp);

	first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size, 0);
	if (!(bip->bli_flags & XFS_BLI_STALE) && first_bit == -1) {
		/*
		 * If the map is not be dirty in the transaction, mark
		 * the size as zero and do not advance the vector pointer.
		 */
		return;
	}

	/*
	 * the STALE exclusion is gone — a CANCEL record is serialized
	 * WITH its trailer (captured at xfs_trans_binval before the stale
	 * conversion), so foreign replay can authorize the free.  The stale
	 * early-return below still emits nothing but the (now tokened) format.
	 */
	if (mxfs_buf_item_wants_authority(bip)) {
		/*
		 * authority token (step 3a): emit the format struct
		 * with the mxfs_blf_authority trailer appended in the SAME
		 * region (a separate iovec would shift the chunk indexing
		 * recovery walks by blf_size).  Build the pair in a local
		 * buffer; the returned pointer into the emitted copy keeps
		 * the blf_size++ mutations below working.  Size side already
		 * reserved the extra bytes (xfs_buf_item_size_segment) — the
		 * conditions MUST match.
		 *
		 * ruling item (b) / P0+P1 — DONE.  Token
		 * content is NO LONGER resolved here.  It is captured at the
		 * first protected dirtying (mxfs_bli_auth_capture, called
		 * from xfs_trans_dirty_buf) and this site only SERIALIZES it,
		 * because a format-time lookup can only ever report the grant
		 * installed when the CIL ran, not the grant that authorized
		 * the mutation.  See struct mxfs_bli_auth for the full
		 * argument and the invariants.
		 *
		 * step 5.2: the wire was v2.  the wire is v3
		 * (v2 + resource lineage), still report-only — old parsers
		 * classify it MALFORMED, which the sweep verified is
		 * purely observational on every replay path.
		 */
		struct {
			char blf[sizeof(struct xfs_buf_log_format)];
			struct mxfs_blf_authority_v3 tok;
		} lbuf;
		struct mxfs_blf_authority_v3 *tok;
		struct xfs_mount *mp = bp->b_mount;
		const struct mxfs_bli_auth *cap = &bip->bli_mxfs_auth;
		uint32_t oslot = 0, onode = 0;
		uint64_t oepoch = 0, res, gepoch, lineage;
		uint16_t cls;
		uint8_t  st;
		bool ident;

		BUILD_BUG_ON(sizeof(lbuf.blf) < sizeof(*blfp));
		memcpy(lbuf.blf, blfp, base_size);
		((struct xfs_buf_log_format *)lbuf.blf)->blf_flags |=
						XFS_BLF_MXFS_AUTHORITY;
		tok = (struct mxfs_blf_authority_v3 *)(lbuf.blf + base_size);
		memset(tok, 0, sizeof(*tok));
		{
			/*
			 * SERIALIZE ONLY.  Three things can still invalidate a
			 * capture between the dirty and here, and each of them
			 * must void the proof rather than be papered over:
			 *
			 *  1. no capture at all — a dirty path that bypasses
			 *     xfs_trans_dirty_buf.  Must not happen; counted so
			 *     the claim is measured rather than assumed.
			 *  2. the BLFT changed after capture, so the capture
			 *     described a different image kind than the one
			 *     being emitted.
			 *  3. the emitting mount identity is unavailable — an
			 *     image that cannot be bound to an incarnation is
			 *     not evidence about any victim, so this DOMINATES
			 *     whatever the capture concluded.
			 */
			cls = cap->mba_class;
			st = cap->mba_status;
			res = cap->mba_resource;
			gepoch = cap->mba_epoch;
			lineage = cap->mba_lineage;

			if (!cap->mba_capseq) {
				atomic64_inc(&mxfs_authcap_nocap);
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				lineage = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
				/*
				 * (chain 35 point 13, 0.51.0): a create
				 * transaction carried ONE class=NONE/INCOMPLETE image
				 * (AG 24 agbno 9, len 8) and the elected replayer
				 * refused the whole slice — terminal verdict, the
				 * whole-cluster bootstrap REFUSED.  The producer's
				 * counters name the reason only in aggregate; this
				 * line names the BUFFER (type, blkno) and which void
				 * path produced it, so the next occurrence is
				 * attributable without the dead node's log.
				 */
				mxfs_probe_ratelimited("mxfs: P-AUTHCAP-VOID why=nocap blkno=%lld len=%u blft=%u flags=0x%x owner_ino=%llu outcome=%u comm=%s\n",
					(long long)bip->bli_formats[0].blf_blkno,
					(unsigned)bip->bli_formats[0].blf_len,
					(unsigned)xfs_blft_from_flags(&bip->__bli_format),
					(unsigned)bip->__bli_format.blf_flags,
					(unsigned long long)cap->mba_owner_ino,
					(unsigned)cap->mba_outcome, current->comm);
			} else if (cap->mba_retype_pending) {
				/* A′: re-typed, never re-dirtied — the
				 * proof was established for another format */
				atomic64_inc(&mxfs_authcap_retype_nodirty);
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				lineage = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
				mxfs_probe_ratelimited("mxfs: P-AUTHCAP-VOID why=retype_nodirty blkno=%lld len=%u blft_cap=%u blft_now=%u class_cap=%u comm=%s\n",
					(long long)bip->bli_formats[0].blf_blkno,
					(unsigned)bip->bli_formats[0].blf_len,
					(unsigned)cap->mba_blft,
					(unsigned)xfs_blft_from_flags(&bip->__bli_format),
					(unsigned)cap->mba_class, current->comm);
			} else if (cap->mba_blft !=
				   xfs_blft_from_flags(&bip->__bli_format) &&
				   !((bip->bli_flags & XFS_BLI_STALE) &&
				     (bip->__bli_format.blf_flags & XFS_BLF_CANCEL) &&
				     xfs_blft_from_flags(&bip->__bli_format) == 0)) {
				/*
				 * the ONE tolerated type change is the
				 * stale conversion itself — xfs_trans_binval
				 * captured under the original BLFT, then cleared
				 * the BLFT mask and set CANCEL.  Any other change
				 * still voids the proof (the ruling: never disable
				 * the check for stale items wholesale).
				 */
				atomic64_inc(&mxfs_authcap_blftchg);
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				lineage = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
				mxfs_probe_ratelimited("mxfs: P-AUTHCAP-VOID why=blftchg blkno=%lld len=%u blft_cap=%u blft_now=%u flags=0x%x class_cap=%u st_cap=%u owner_ino=%llu outcome=%u comm=%s\n",
					(long long)bip->bli_formats[0].blf_blkno,
					(unsigned)bip->bli_formats[0].blf_len,
					(unsigned)cap->mba_blft,
					(unsigned)xfs_blft_from_flags(&bip->__bli_format),
					(unsigned)bip->__bli_format.blf_flags,
					(unsigned)cap->mba_class,
					(unsigned)cap->mba_status,
					(unsigned long long)cap->mba_owner_ino,
					(unsigned)cap->mba_outcome, current->comm);
			}

			ident = mxfs_v5_dlm_mount_identity(mp->m_mxfs_dlm,
						&oslot, &onode, &oepoch);
			if (!ident) {
				cls = MXFS_AUTH_CLASS_NONE;
				res = 0;
				gepoch = 0;
				lineage = 0;
				oslot = 0;
				onode = 0;
				oepoch = 0;
				st = MXFS_AUTH_ST_INCOMPLETE;
				atomic64_inc(&mxfs_tokcls_incomplete);
			}
		}
		tok->mba_version = cpu_to_be16(MXFS_BLF_AUTHORITY_V3);
		tok->mba_class = cpu_to_be16(cls);
		/* reserved bits (8-31) stay zero — a parser rejects them */
		tok->mba_flags =
			cpu_to_be32((uint32_t)st & MXFS_AUTH_FLAG_STATUS_MASK);
		tok->mba_resource = cpu_to_be64(res);
		tok->mba_grant_epoch = cpu_to_be64(gepoch);
		tok->mba_owner_epoch = cpu_to_be64(oepoch);
		tok->mba_owner_slot = cpu_to_be32(oslot);
		tok->mba_owner_node = cpu_to_be32(onode);
		tok->mba_lineage = cpu_to_be64(lineage);

		blfp = xlog_format_copy(lfb, XLOG_REG_TYPE_BFORMAT, &lbuf,
					base_size +
					(uint)MXFS_BLF_AUTHORITY_SIZE);
		blfp->blf_size = 1;
	} else {
		blfp = xlog_format_copy(lfb, XLOG_REG_TYPE_BFORMAT, blfp,
					base_size);
		blfp->blf_size = 1;
	}

	/*
	 * blfp now points into the emitted copy, so what is changed here goes
	 * to the log and nowhere else.  The data map, the map size and blf_size
	 * are read below and are deliberately untouched.
	 */
	if (unlikely(mxfs_dbg_recov_inject_straddle))
		mxfs_dbg_inject_logged_blf(bp, blfp);

	if (bip->bli_flags & XFS_BLI_STALE) {
		/*
		 * The buffer is stale, so all we need to log
		 * is the buf log format structure with the
		 * cancel flag in it.
		 */
		trace_xfs_buf_item_format_stale(bip);
		ASSERT(blfp->blf_flags & XFS_BLF_CANCEL);
		return;
	}


	/*
	 * Fill in an iovec for each set of contiguous chunks.
	 */
	do {
		void *dst;

		ASSERT(first_bit >= 0);
		nbits = xfs_contig_bits(blfp->blf_data_map,
					blfp->blf_map_size, first_bit);
		ASSERT(nbits > 0);
		dst = xfs_buf_item_copy_iovec(lfb, bp, offset, first_bit,
					      nbits);
		if (unlikely(mxfs_dbg_recov_inject_agino))
			mxfs_dbg_inject_logged_agino(bp, blfp, dst, offset,
						     first_bit, nbits);
		blfp->blf_size++;

		/*
		 * This takes the bit number to start looking from and
		 * returns the next set bit from there.  It returns -1
		 * if there are no more bits set or the start bit is
		 * beyond the end of the bitmap.
		 */
		first_bit = xfs_next_bit(blfp->blf_data_map, blfp->blf_map_size,
					(uint)first_bit + nbits + 1);
	} while (first_bit != -1);

	return;
}

/*
 * This is called to fill in the vector of log iovecs for the
 * given log buf item.  It fills the first entry with a buf log
 * format structure, and the rest point to contiguous chunks
 * within the buffer.
 */
STATIC void
xfs_buf_item_format(
	struct xfs_log_item	*lip,
	struct xlog_format_buf	*lfb)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	uint			offset = 0;
	int			i;

	ASSERT(atomic_read(&bip->bli_refcount) > 0);
	ASSERT((bip->bli_flags & XFS_BLI_LOGGED) ||
	       (bip->bli_flags & XFS_BLI_STALE));
	ASSERT((bip->bli_flags & XFS_BLI_STALE) ||
	       (xfs_blft_from_flags(&bip->__bli_format) > XFS_BLFT_UNKNOWN_BUF
	        && xfs_blft_from_flags(&bip->__bli_format) < XFS_BLFT_MAX_BUF));
	ASSERT(!(bip->bli_flags & XFS_BLI_ORDERED) ||
	       (bip->bli_flags & XFS_BLI_STALE));


	/*
	 * If it is an inode buffer, transfer the in-memory state to the
	 * format flags and clear the in-memory state.
	 *
	 * For buffer based inode allocation, we do not transfer
	 * this state if the inode buffer allocation has not yet been committed
	 * to the log as setting the XFS_BLI_INODE_BUF flag will prevent
	 * correct replay of the inode allocation.
	 *
	 * For icreate item based inode allocation, the buffers aren't written
	 * to the journal during allocation, and hence we should always tag the
	 * buffer as an inode buffer so that the correct unlinked list replay
	 * occurs during recovery.
	 */
	if (bip->bli_flags & XFS_BLI_INODE_BUF) {
		if (xfs_has_v3inodes(lip->li_log->l_mp) ||
		    !((bip->bli_flags & XFS_BLI_INODE_ALLOC_BUF) &&
		      xfs_log_item_in_current_chkpt(lip)))
			bip->__bli_format.blf_flags |= XFS_BLF_INODE_BUF;
		bip->bli_flags &= ~XFS_BLI_INODE_BUF;
	}

	for (i = 0; i < bip->bli_format_count; i++) {
		xfs_buf_item_format_segment(bip, lfb, offset,
					    &bip->bli_formats[i]);
		offset += BBTOB(bp->b_maps[i].bm_len);
	}

	/*
	 * Check to make sure everything is consistent.
	 */
	trace_xfs_buf_item_format(bip);
}

/*
 * This is called to pin the buffer associated with the buf log item in memory
 * so it cannot be written out.
 *
 * We take a reference to the buffer log item here so that the BLI life cycle
 * extends at least until the buffer is unpinned via xfs_buf_item_unpin() and
 * inserted into the AIL.
 *
 * We also need to take a reference to the buffer itself as the BLI unpin
 * processing requires accessing the buffer after the BLI has dropped the final
 * BLI reference. See xfs_buf_item_unpin() for an explanation.
 * If unpins race to drop the final BLI reference and only the
 * BLI owns a reference to the buffer, then the loser of the race can have the
 * buffer fgreed from under it (e.g. on shutdown). Taking a buffer reference per
 * pin count ensures the life cycle of the buffer extends for as
 * long as we hold the buffer pin reference in xfs_buf_item_unpin().
 */
STATIC void
xfs_buf_item_pin(
	struct xfs_log_item	*lip)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);

	ASSERT(atomic_read(&bip->bli_refcount) > 0);
	ASSERT((bip->bli_flags & XFS_BLI_LOGGED) ||
	       (bip->bli_flags & XFS_BLI_ORDERED) ||
	       (bip->bli_flags & XFS_BLI_STALE));

	trace_xfs_buf_item_pin(bip);

	xfs_buf_hold(bip->bli_buf);
	atomic_inc(&bip->bli_refcount);
	atomic_inc(&bip->bli_buf->b_pin_count);
}

/*
 * For a stale BLI, process all the necessary completions that must be
 * performed when the final BLI reference goes away. The buffer will be
 * referenced and locked here - we return to the caller with the buffer still
 * referenced and locked for them to finalise processing of the buffer.
 */
static void
xfs_buf_item_finish_stale(
	struct xfs_buf_log_item	*bip)
{
	struct xfs_buf		*bp = bip->bli_buf;
	struct xfs_log_item	*lip = &bip->bli_item;

	ASSERT(bip->bli_flags & XFS_BLI_STALE);
	ASSERT(xfs_buf_islocked(bp));
	ASSERT(bp->b_flags & XBF_STALE);
	ASSERT(bip->__bli_format.blf_flags & XFS_BLF_CANCEL);
	ASSERT(list_empty(&lip->li_trans));
	ASSERT(!bp->b_transp);

	/* F4: committed XFS_BLF_CANCEL — the only non-shutdown
	 * cancel point for a committed-never-submitted obligation. */
	mxfs_f4_cancel(bp, MXFS_F4_CANCEL_STALE);

	/*
	 * 0.75.62: a stale buffer never writes back, so bp->b_iodone
	 * (mxfs_dlm_ag_meta_iodone) never fires for it.  An AG-metadata btree
	 * block freed after being logged in this dirty epoch (xfs_trans_binval
	 * on a leaf merge or a root collapse) otherwise keeps the track hold
	 * and the per-AG pending count taken by mxfs_ag_meta_track for the life
	 * of the mount, and every later release of that AG spins to the Phase-3
	 * 2 s bound while the peer's request deadline expires.  Return them
	 * here, while our caller still holds its own reference; the one-shot
	 * token makes this a no-op for any buffer that was never tracked.
	 */
	mxfs_ag_meta_reclaim(bp, "stale");

	if (bip->bli_flags & XFS_BLI_STALE_INODE) {
		xfs_buf_item_done(bp, XFS_BLI_NO_IODONE);
		xfs_buf_inode_iodone(bp);
		ASSERT(list_empty(&bp->b_li_list));
		return;
	}

	/*
	 * We may or may not be on the AIL here, xfs_trans_ail_delete() will do
	 * the right thing regardless of the situation in which we are called.
	 */
	xfs_trans_ail_delete(lip, SHUTDOWN_LOG_IO_ERROR);
	xfs_buf_item_relse(bip, "stale", XFS_BLI_NO_IODONE);
	ASSERT(bp->b_log_item == NULL);

	/*
	 * 0.75.64: at this point exactly ONE reference should remain — the
	 * caller's, which it releases right after we return — and a freed
	 * AG-metadata btree block then leaves the buffer cache for good.
	 * Six such buffers survived to module unload on test1 (2026-09-08,
	 * "Slab cache still has objects" from xfs_destroy_caches) after the
	 * 0.75.62 stale reclaim returned the track hold, so a second, unnamed
	 * reference is being kept somewhere.  Name the count here so the leak
	 * is attributed at the completion that should have ended the buffer.
	 */
	if (mxfs_buf_is_ag_metadata(bp)) {
		int hold = bp->b_hold;

		if (hold != 1)
			pr_warn_ratelimited("mxfs: P-STALE-FIN daddr=%lld ops=%s hold=%d pin=%d flags=0x%x agmeta_hold=%d — stale AG-meta completion leaves more than the caller's reference (leak source)\n",
				(long long)bp->b_maps[0].bm_bn,
				(bp->b_ops && bp->b_ops->name) ? bp->b_ops->name : "?",
				hold, atomic_read(&bp->b_pin_count), bp->b_flags,
				atomic_read(&bp->b_mxfs_agmeta_hold));
	}
}

/*
 * This is called to unpin the buffer associated with the buf log item which was
 * previously pinned with a call to xfs_buf_item_pin().  We enter this function
 * with a buffer pin count, a buffer reference and a BLI reference.
 *
 * We must drop the BLI reference before we unpin the buffer because the AIL
 * doesn't acquire a BLI reference whenever it accesses it. Therefore if the
 * refcount drops to zero, the bli could still be AIL resident and the buffer
 * submitted for I/O at any point before we return. This can result in IO
 * completion freeing the buffer while we are still trying to access it here.
 * This race condition can also occur in shutdown situations where we abort and
 * unpin buffers from contexts other that journal IO completion.
 *
 * Hence we have to hold a buffer reference per pin count to ensure that the
 * buffer cannot be freed until we have finished processing the unpin operation.
 * The reference is taken in xfs_buf_item_pin(), and we must hold it until we
 * are done processing the buffer state. In the case of an abort (remove =
 * true) then we re-use the current pin reference as the IO reference we hand
 * off to IO failure handling.
 */
STATIC void
xfs_buf_item_unpin(
	struct xfs_log_item	*lip,
	int			remove)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	int			stale = bip->bli_flags & XFS_BLI_STALE;
	int			freed;

	ASSERT(bp->b_log_item == bip);
	ASSERT(atomic_read(&bip->bli_refcount) > 0);

	trace_xfs_buf_item_unpin(bip);

	freed = atomic_dec_and_test(&bip->bli_refcount);
	if (atomic_dec_and_test(&bp->b_pin_count))
		wake_up_all(&bp->b_waiters);

	/*
	 * Nothing to do but drop the buffer pin reference if the BLI is
	 * still active.
	 */
	if (!freed) {
		xfs_buf_rele(bp);
		return;
	}

	if (stale) {
		trace_xfs_buf_item_unpin_stale(bip);

		/*
		 * The buffer has been locked and referenced since it was marked
		 * stale so we own both lock and reference exclusively here. We
		 * do not need the pin reference any more, so drop it now so
		 * that we only have one reference to drop once item completion
		 * processing is complete.
		 */
		xfs_buf_rele(bp);
		xfs_buf_item_finish_stale(bip);
		xfs_buf_relse(bp);
		return;
	}

	if (remove) {
		/*
		 * We need to simulate an async IO failures here to ensure that
		 * the correct error completion is run on this buffer. This
		 * requires a reference to the buffer and for the buffer to be
		 * locked. We can safely pass ownership of the pin reference to
		 * the IO to ensure that nothing can free the buffer while we
		 * wait for the lock and then run the IO failure completion.
		 */
		xfs_buf_lock(bp);
		bp->b_flags |= XBF_ASYNC;
		/* audited no-I/O completion (post log-error remove) */
		xfs_buf_ioend_fail_unsubmitted(bp);
		return;
	}

	/*
	 * BLI has no more active references - it will be moved to the AIL to
	 * manage the remaining BLI/buffer life cycle. There is nothing left for
	 * us to do here so drop the pin reference to the buffer.
	 */
	xfs_buf_rele(bp);
}

/*
 * D-0487: grace period, in ms, between xfsaild's first coherent refusal of a
 * committed image whose grant this node does not hold and the fail-stop.
 * The only legitimate reason the refusal predicate is transiently true is a
 * lock-free read across an acquire's publication (the epoch, holders and the
 * cached hint are written back to back under pag_dlm_lock), which lasts
 * microseconds; xfsaild's own retry interval when it backs off is 50 ms; no
 * actor ever re-acquires a grant on a refused item's behalf.  Ten seconds is
 * therefore four orders above the transient and well inside every budget
 * the refusal can hang (the 90 s coherency rows, the 240 s mass unmount).
 * The alert lands at the grace period plus one xfsaild retry.
 */
unsigned int mxfs_ailpin_grace_ms = 10000;
module_param_named(ailpin_grace_ms, mxfs_ailpin_grace_ms, uint, 0644);
MODULE_PARM_DESC(ailpin_grace_ms,
		 "ms a committed AG-metadata/bmbt image may sit refused by xfsaild "
		 "(grant not held) before the mount fails stop; default 10000");

/*
 * 0.70.2: a refused item that clears (is written home once the grant is
 * back, or is failed by a shutdown) is reported by name when it took at
 * least this long from its first coherent refusal.  The steady-state
 * producer of refusals is the AG handoff itself — xfsaild meets the
 * committed image in the gap between the release commit and the drain that
 * writes it — and those clear in the drain, i.e. in milliseconds.  Anything
 * slower is a refusal the grace period could turn into a fail-stop, and the
 * census (debugfs ailpin_stats) is what says how much margin the grace has.
 */
unsigned int mxfs_ailpin_clear_report_ms = 1000;
module_param_named(ailpin_clear_report_ms, mxfs_ailpin_clear_report_ms,
		   uint, 0644);
MODULE_PARM_DESC(ailpin_clear_report_ms,
		 "report by name a refused AG-metadata/bmbt image that took at "
		 "least this many ms to clear; default 1000");

static const char *
mxfs_agmeta_ops_name(
	const struct xfs_buf	*bp)
{
	if (!bp->b_ops)
		return "null";
	return (bp->b_ops == &xfs_bnobt_buf_ops) ? "bnobt" :
	       (bp->b_ops == &xfs_cntbt_buf_ops) ? "cntbt" :
	       (bp->b_ops == &xfs_agf_buf_ops)   ? "agf"   :
	       (bp->b_ops == &xfs_agfl_buf_ops)  ? "agfl"  :
	       (bp->b_ops == &xfs_agi_buf_ops)   ? "agi"   :
	       (bp->b_ops == &xfs_inobt_buf_ops) ? "inobt" :
	       (bp->b_ops == &xfs_finobt_buf_ops)? "finobt":
	       (bp->b_ops == &xfs_bmbt_buf_ops)  ? "bmbt"  :
	       bp->b_ops->name ? bp->b_ops->name : "?";
}

/*
 * D-0487: account one xfsaild refusal of `bip` and say whether the item has
 * now been refused for longer than the grace period.  Called under ail_lock
 * with the buffer locked, so it must not sleep; it prints (rate-limited per
 * mount) the identity the old P126 line lacked — the item's LSN, its
 * captured authority (class/status/epoch/window), the AG's current epoch
 * and hold state, its age and refusal count — and, once per item, the
 * PINNED alert with the same identity.  It never changes the item.
 *
 * `agno` is the AG the arm derived the item to belong to (the buffer's perag
 * for AG metadata, the owner inode's AG for a bmbt leaf); `owner` is the
 * bmbt owner inode or 0.
 */
static bool
mxfs_bli_refuse_account(
	struct xfs_buf_log_item	*bip,
	struct xfs_buf		*bp,
	const char		*arm,
	xfs_agnumber_t		agno,
	uint64_t		owner,
	uint64_t		cur_epoch,
	bool			cached,
	int			holders)
{
	struct xfs_log_item	*lip = &bip->bli_item;
	struct mxfs_bli_auth	*cap = &bip->bli_mxfs_auth;
	unsigned long		now = jiffies;
	unsigned int		age_ms;
	bool			pinned;

	if (!bip->bli_mxfs_refuse_first) {
		bip->bli_mxfs_refuse_first = now | 1;
		bip->bli_mxfs_refuse_lsn = lip->li_lsn;
		bip->bli_mxfs_refuse_count = 1;
		if (bp->b_mount)
			atomic64_inc(&bp->b_mount->m_mxfs_ailpin_refused_n);
		pr_warn_ratelimited("mxfs: P126-XFSAILD-REFUSE arm=%s agno=%u daddr=%lld ops=%s lsn=0x%llx owner=%llu cap_class=%u cap_st=%u cap_epoch=%llu cap_win=%llu cur_epoch=%llu cached=%d holders=%d in_ail=%d dirty=%d pin=%d — committed image for a grant this node does not hold; not written\n",
			arm, agno, (long long)bp->b_maps[0].bm_bn,
			mxfs_agmeta_ops_name(bp),
			(unsigned long long)lip->li_lsn,
			(unsigned long long)owner,
			(unsigned)cap->mba_class, (unsigned)cap->mba_status,
			(unsigned long long)cap->mba_epoch,
			(unsigned long long)cap->mba_capseq,
			(unsigned long long)cur_epoch, cached ? 1 : 0, holders,
			test_bit(XFS_LI_IN_AIL, &lip->li_flags) ? 1 : 0,
			(bip->bli_flags & XFS_BLI_DIRTY) ? 1 : 0,
			xfs_buf_ispinned(bp) ? 1 : 0);
		return false;
	}
	if (bip->bli_mxfs_refuse_count < UINT_MAX)
		bip->bli_mxfs_refuse_count++;
	if (lip->li_lsn != bip->bli_mxfs_refuse_lsn) {
		/*
		 * Re-logged while refused: a second unauthorized mutation of
		 * the same image.  Visible, and NOT a restart of the clock.
		 */
		pr_warn_ratelimited("mxfs: P126-XFSAILD-REFUSE-RELOG arm=%s agno=%u daddr=%lld lsn_first=0x%llx lsn_now=0x%llx count=%u\n",
			arm, agno, (long long)bp->b_maps[0].bm_bn,
			(unsigned long long)bip->bli_mxfs_refuse_lsn,
			(unsigned long long)lip->li_lsn,
			bip->bli_mxfs_refuse_count);
		bip->bli_mxfs_refuse_lsn = lip->li_lsn;
	}
	age_ms = jiffies_to_msecs(now - (bip->bli_mxfs_refuse_first & ~1UL));
	pinned = age_ms >= READ_ONCE(mxfs_ailpin_grace_ms);
	if (pinned && !bip->bli_mxfs_refuse_reported) {
		struct xfs_mount	*mp = bp->b_mount;

		bip->bli_mxfs_refuse_reported = 1;
		pr_alert("mxfs: P126-AIL-PINNED arm=%s agno=%u daddr=%lld ops=%s lsn=0x%llx owner=%llu cap_class=%u cap_st=%u cap_epoch=%llu cap_win=%llu cur_epoch=%llu cached=%d holders=%d age_ms=%u count=%u — this node committed a change to metadata it holds no grant for: writing it would clobber the holder, dropping it would lose a committed change, and nothing will ever make it writable\n",
			arm, agno, (long long)bp->b_maps[0].bm_bn,
			mxfs_agmeta_ops_name(bp),
			(unsigned long long)lip->li_lsn,
			(unsigned long long)owner,
			(unsigned)cap->mba_class, (unsigned)cap->mba_status,
			(unsigned long long)cap->mba_epoch,
			(unsigned long long)cap->mba_capseq,
			(unsigned long long)cur_epoch, cached ? 1 : 0, holders,
			age_ms, bip->bli_mxfs_refuse_count);
		if (mp && mp->m_mxfs_dlm &&
		    atomic_cmpxchg(&mp->m_mxfs_ailpin_fired, 0, 1) == 0) {
			mp->m_mxfs_ailpin_arm = arm;
			mp->m_mxfs_ailpin_ops = mxfs_agmeta_ops_name(bp);
			mp->m_mxfs_ailpin_daddr = bp->b_maps[0].bm_bn;
			mp->m_mxfs_ailpin_lsn = lip->li_lsn;
			mp->m_mxfs_ailpin_agno = agno;
			mp->m_mxfs_ailpin_count = bip->bli_mxfs_refuse_count;
			mp->m_mxfs_ailpin_age_ms = age_ms;
			queue_work(system_unbound_wq, &mp->m_mxfs_ailpin_work);
		}
	}
	return pinned;
}

/*
 * D-0487 (0.70.2): a refused item is being freed — retired by its home
 * write after the grant came back (the healthy case: the release drain
 * writes it milliseconds after the refusal) or by the failed submit that
 * follows a shutdown.  Record its age from the first coherent refusal in
 * the mount census and name it if it was slow.  Called from
 * xfs_buf_item_relse, which every retirement path funnels through; the item
 * is already off the AIL and unreferenced, so nothing here can race the
 * push's accounting on the same item.
 */
static void
mxfs_bli_refuse_clear(
	struct xfs_buf_log_item	*bip,
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	unsigned int		age_ms;
	bool			shutdown;
	int			old;

	age_ms = jiffies_to_msecs(jiffies - (bip->bli_mxfs_refuse_first & ~1UL));
	shutdown = mp && mp->m_log && xlog_is_shutdown(mp->m_log);
	if (mp) {
		atomic64_inc(&mp->m_mxfs_ailpin_clear_n);
		atomic64_add(age_ms, &mp->m_mxfs_ailpin_clear_sum_ms);
		if (shutdown)
			atomic64_inc(&mp->m_mxfs_ailpin_clear_shutdown_n);
		if (age_ms >= READ_ONCE(mxfs_ailpin_clear_report_ms))
			atomic64_inc(&mp->m_mxfs_ailpin_clear_slow_n);
		old = atomic_read(&mp->m_mxfs_ailpin_clear_max_ms);
		while ((unsigned int)old < age_ms) {
			int seen = atomic_cmpxchg(&mp->m_mxfs_ailpin_clear_max_ms,
						  old, (int)age_ms);
			if (seen == old)
				break;
			old = seen;
		}
	}
	if (age_ms >= READ_ONCE(mxfs_ailpin_clear_report_ms) ||
	    bip->bli_mxfs_refuse_reported)
		pr_warn_ratelimited("mxfs: P126-REFUSE-CLEARED daddr=%lld ops=%s lsn_first=0x%llx lsn_last=0x%llx age_ms=%u count=%u pinned_reported=%u shutdown=%d ioerr=%d — a refused image was retired\n",
			(long long)bp->b_maps[0].bm_bn,
			mxfs_agmeta_ops_name(bp),
			(unsigned long long)bip->bli_mxfs_refuse_lsn,
			(unsigned long long)bip->bli_item.li_lsn,
			age_ms, bip->bli_mxfs_refuse_count,
			bip->bli_mxfs_refuse_reported, shutdown ? 1 : 0,
			bp->b_error);
}

/*
 * The mount-level response to a pinned item, in process context (the push
 * that found it runs under ail_lock and cannot force a shutdown itself).
 * 0.70.0: the fail-stop.  The item is a committed change to metadata this
 * node holds no grant for; it can be neither written nor dropped, and left
 * alone it pins the log tail until unmount hangs on it (D-0486) and, on the
 * pre-0.69.3 ordering, took the whole cluster with it (D-0487 convoy).  A
 * named shutdown is the only honest terminal state; the same policy the
 * acquire-time preflight already applies to the same condition
 * (P131-INVAL-REFUSED).  After the shutdown the refused push falls through
 * and the failed submit retires the item, so the pending AIL wait returns.
 */
void
mxfs_ailpin_work_fn(
	struct work_struct	*work)
{
	struct xfs_mount	*mp = container_of(work, struct xfs_mount,
						   m_mxfs_ailpin_work);

	xfs_alert(mp,
	"mxfs: P126-AIL-PINNED-MOUNT arm=%s agno=%u daddr=%lld ops=%s lsn=0x%llx age_ms=%u count=%u — this node committed a change to metadata it holds no grant for and xfsaild has refused it past the grace period; it can be neither written (clobbers the holder) nor dropped (loses a committed change); shutting down so the log tail is released and the slice goes to recovery",
		mp->m_mxfs_ailpin_arm ? mp->m_mxfs_ailpin_arm : "?",
		mp->m_mxfs_ailpin_agno, (long long)mp->m_mxfs_ailpin_daddr,
		mp->m_mxfs_ailpin_ops ? mp->m_mxfs_ailpin_ops : "?",
		(unsigned long long)mp->m_mxfs_ailpin_lsn,
		mp->m_mxfs_ailpin_age_ms, mp->m_mxfs_ailpin_count);
	xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
}

STATIC uint
xfs_buf_item_push(
	struct xfs_log_item	*lip,
	struct list_head	*buffer_list)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	uint			rval = XFS_ITEM_SUCCESS;

	if (xfs_buf_ispinned(bp))
		return XFS_ITEM_PINNED;
	if (!xfs_buf_trylock(bp)) {
		/*
		 * If we have just raced with a buffer being pinned and it has
		 * been marked stale, we could end up stalling until someone else
		 * issues a log force to unpin the stale buffer. Check for the
		 * race condition here so xfsaild recognizes the buffer is pinned
		 * and queues a log force to move it along.
		 */
		if (xfs_buf_ispinned(bp))
			return XFS_ITEM_PINNED;
		return XFS_ITEM_LOCKED;
	}

	ASSERT(!(bip->bli_flags & XFS_BLI_STALE));

	/*
	 * xfsaild AG-meta writeback interlock.  If
	 * this is an AG-allocation-metadata buffer for an AG we do NOT currently
	 * hold (a peer owns it), our cached image is a stale prior-tenure log-
	 * tail artifact; writing it would revert the peer's durable free-space
	 * btree change (the held=1 P93/P124 clobber, whose push is decided HERE
	 * while held=0 even though xfs_buf_submit later samples held=1) and
	 * poison our own allocator into an `ltbno+ltlen>bno` in-core double-free.
	 * Invariant #1 made every legitimate this-node AG-meta change durable
	 * before release, so the BLI carries nothing we still need.  Stale it
	 * (removes the BLI from the AIL with no I/O) and report SUCCESS so
	 * xfsaild advances the log tail and the peer's allocation stands.  When
	 * we DO hold the AG the predicate is false and the normal write below
	 * runs (so single-node / uncontended mounts are unaffected).
	 */
	if (mxfs_buf_xfsaild_skip_agmeta_write(bp)) {
		struct xfs_perag	*pag = bp->b_pag;
		uint64_t		e0 = READ_ONCE(pag->pag_mxfs_grant_epoch);
		bool			cached = READ_ONCE(pag->pag_dlm_cached);
		int			holders = READ_ONCE(pag->pag_dlm_holders);
		uint64_t		e1 = READ_ONCE(pag->pag_mxfs_grant_epoch);

		/*
		 * D-0487 (0.70.0): REFUSE, do not stale, do not report success.
		 * The item is this node's committed change to metadata it holds
		 * no grant for.  Writing it would clobber the holder's newer
		 * image (the clobber); dropping it from the AIL would lose
		 * a committed change, and nothing at push time can prove the
		 * image durable; staling it (0.69.6 and before) left the item in
		 * the AIL anyway — xfs_buf_stale sets flags and nothing more —
		 * and then let a later cache lookup reuse the buffer with b_ops
		 * cleared and the item still attached, so the next push wrote
		 * whatever the buffer then held.  So the item stays as it is,
		 * unlocked, reported as LOCKED (retained, retried, no I/O),
		 * which xfsaild already treats as stuck and backs off from.
		 *
		 * Only a COHERENT "not held" snapshot — the epoch read unchanged
		 * around the hint and the holder count, and zero, which is what
		 * every release-commit point publishes before its on-disk unlock
		 * — is accounted; a snapshot taken across an acquire's
		 * publication is a transient and starts no clock.  Past the grace
		 * period the accounting queues the fail-stop (mxfs_ailpin_work_fn):
		 * the only producers of such an item are exclusion defects, and
		 * the honest terminal state is a named shutdown, not a quiet
		 * skip that pins the log tail forever.
		 *
		 * Once the log is shut down the item is retired the ordinary way:
		 * fall through, the submit fails without I/O and the completion
		 * deletes the item, so xfs_ail_push_all_sync returns.
		 */
		if (!xlog_is_shutdown(bp->b_mount->m_log)) {
			if (e0 == e1 && e0 == 0 && !cached && holders == 0)
				mxfs_bli_refuse_account(bip, bp, "agmeta",
							pag_agno(pag), 0, e0,
							cached, holders);
			else
				pr_warn_ratelimited("mxfs: P126-XFSAILD-REFUSE-TRANSIENT agno=%u daddr=%lld ops=%s epoch=%llu/%llu cached=%d holders=%d — not held at the predicate, hold state in motion; retained, not written\n",
					pag_agno(pag),
					(long long)bp->b_maps[0].bm_bn,
					mxfs_agmeta_ops_name(bp),
					(unsigned long long)e0,
					(unsigned long long)e1,
					cached ? 1 : 0, holders);
			xfs_buf_unlock(bp);
			return XFS_ITEM_LOCKED;
		}
	} else if (bp->b_pag && bip->bli_mxfs_auth.mba_class == MXFS_AUTH_CLASS_AG &&
		   bip->bli_mxfs_auth.mba_status == MXFS_AUTH_ST_VALID &&
		   bip->bli_mxfs_auth.mba_epoch &&
		   mxfs_buf_is_ag_metadata(bp)) {
		/*
		 * D-0487 (0.70.0) DIAGNOSTIC ONLY: the node holds the AG, but
		 * this image was captured under a different tenure's epoch and
		 * was never re-logged under this one.  A correct release drains
		 * every such item before the on-disk unlock, so this line
		 * should never print; it is measured before it is enforced.
		 */
		uint64_t	ge = READ_ONCE(bp->b_pag->pag_mxfs_grant_epoch);

		if (ge && ge != bip->bli_mxfs_auth.mba_epoch)
			mxfs_probe_ratelimited("mxfs: P126-EPOCH-MISMATCH agno=%u daddr=%lld ops=%s lsn=0x%llx cap_epoch=%llu cur_epoch=%llu cap_win=%llu — held now, but the image was committed under an earlier tenure and never re-logged; written as before, counted here\n",
				pag_agno(bp->b_pag),
				(long long)bp->b_maps[0].bm_bn,
				mxfs_agmeta_ops_name(bp),
				(unsigned long long)bip->bli_item.li_lsn,
				(unsigned long long)bip->bli_mxfs_auth.mba_epoch,
				(unsigned long long)ge,
				(unsigned long long)bip->bli_mxfs_auth.mba_capseq);
	}

	/*
	 * (instrumented, zero_silent_loss residual): the bmbt analogue of the
	 * AG-meta interlock above.  A bmbt extent-map block whose owner dir we
	 * have released (i_dlm_mode==NL) must NOT be written from our lingering
	 * prior-tenure BLI — that reverts a peer's newer leaf records and is the
	 * proven `ir.loaded != if_nextents` (loaded < if_nextents) leaf-lag.
	 * Invariant #1 made our legitimate bmbt changes durable before NL, so
	 * the BLI here carries only a superseded image; stale it (drop from AIL,
	 * no I/O) so the peer's leaf stands.  Scoped to in-core released dirs
	 * only — files and held dirs fall through to the normal write.
	 */
	if (mxfs_buf_xfsaild_skip_bmbt_write(bp)) {
		uint64_t	owner = be64_to_cpu(((struct xfs_btree_block *)
					bp->b_addr)->bb_u.l.bb_owner);

		/*
		 * D-0487 (0.70.0): the same terminal shape as the AG-metadata
		 * arm — retained unwritten and unstaled, LOCKED, fail-stop past
		 * the grace period.  The predicate reads the owner's mode under
		 * pag_ici_lock, so every refusal here is a coherent one.  (This
		 * arm has not fired in any captured run since the release drain
		 * was rebuilt; the shape is kept identical so that if it does,
		 * it is named and bounded rather than quietly pinned.)
		 */
		if (!xlog_is_shutdown(bp->b_mount->m_log)) {
			mxfs_bli_refuse_account(bip, bp, "bmbt",
						XFS_INO_TO_AGNO(bp->b_mount, owner),
						owner, 0, false, 0);
			xfs_buf_unlock(bp);
			return XFS_ITEM_LOCKED;
		}
	}

	/*
	 * DEFER a background xfsaild destage of a
	 * multi-node dir DATA/LEAF block while we hold the owner dir's EX and a
	 * peer BAST is pending (contended).  Keep the BLI in the AIL with NO I/O
	 * (return XFS_ITEM_LOCKED) so the block's on-disk image changes ONLY via
	 * the synchronous release-drain (Invariant #1) — never via a background
	 * write that could clobber a peer's dirent (the dir_reuse_coherency
	 * readdir=799 root, PROVEN dataclobber=1 detect run).  Self-clears
	 * the instant we release EX (mode->NL), so no permanent AIL stall; an
	 * uncontended hold (no BAST) falls through and destages normally.
	 */
	if (mxfs_dir_ail_push_defer(bp)) {
		xfs_buf_unlock(bp);
		return XFS_ITEM_LOCKED;
	}

	/*
	 * (design review consult #2, PROVEN root): LAST-LINE
	 * guard for the dir_reuse readdir=799 durable dirent loss.  A
	 * coherency-invalidated (XBF_DONE clear), clean, DESTAGED, in-AIL dir
	 * DATA buffer is a "zombie": its content is on disk (destaged) but stale
	 * (a peer superseded it during our NL window), and re-flushing it reverts
	 * the peer's durable add.  Stale it (drops the BLI from the AIL with NO
	 * I/O — same proven pattern as P126/P60 above) and report SUCCESS so
	 * xfsaild advances the log tail (no starvation).  Loss-safe: a legit
	 * write is DONE=1 or undestaged and never matches (see predicate).
	 */
	if (mxfs_dir_zombie_push_retire(bp)) {
		mxfs_probe_ratelimited("mxfs: P33-PUSH-RETIRE daddr=%lld in_ail=%d dirty=%d pin=%d — staling DONE=0 destaged zombie dir buffer instead of reflushing stale over peer add\n",
			(long long)bp->b_maps[0].bm_bn,
			test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags) ? 1 : 0,
			(bip->bli_flags & XFS_BLI_DIRTY) ? 1 : 0,
			xfs_buf_ispinned(bp) ? 1 : 0);
		xfs_buf_stale(bp);
		xfs_buf_unlock(bp);
		return XFS_ITEM_SUCCESS;
	}

	trace_xfs_buf_item_push(bip);

	/* has a previous flush failed due to IO errors? */
	if (bp->b_flags & XBF_WRITE_FAIL) {
		xfs_buf_alert_ratelimited(bp, "XFS: Failing async write",
	    "Failing async write on buffer block 0x%llx. Retrying async write.",
					  (long long)xfs_buf_daddr(bp));
	}

	if (!xfs_buf_delwri_queue(bp, buffer_list))
		rval = XFS_ITEM_FLUSHING;
	xfs_buf_unlock(bp);
	return rval;
}

/*
 * Drop the buffer log item refcount and take appropriate action. This helper
 * determines whether the bli must be freed or not, since a decrement to zero
 * does not necessarily mean the bli is unused.
 */
void
xfs_buf_item_put(
	struct xfs_buf_log_item	*bip)
{

	ASSERT(xfs_buf_islocked(bip->bli_buf));

	/* drop the bli ref and return if it wasn't the last one */
	if (!atomic_dec_and_test(&bip->bli_refcount))
		return;

	/* If the BLI is in the AIL, then it is still dirty and in use */
	if (test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)) {
		ASSERT(bip->bli_flags & XFS_BLI_DIRTY);
		return;
	}

	/*
	 * In shutdown conditions, we can be asked to free a dirty BLI that
	 * isn't in the AIL. This can occur due to a checkpoint aborting a BLI
	 * instead of inserting it into the AIL at checkpoint IO completion. If
	 * there's another bli reference (e.g. a btree cursor holds a clean
	 * reference) and it is released via xfs_trans_brelse(), we can get here
	 * with that aborted, dirty BLI. In this case, it is safe to free the
	 * dirty BLI immediately, as it is not in the AIL and there are no
	 * other references to it.
	 *
	 * We should never get here with a stale BLI via that path as
	 * xfs_trans_brelse() specifically holds onto stale buffers rather than
	 * releasing them.
	 */
	ASSERT(!(bip->bli_flags & XFS_BLI_DIRTY) ||
			test_bit(XFS_LI_ABORTED, &bip->bli_item.li_flags));
	ASSERT(!(bip->bli_flags & XFS_BLI_STALE));
	xfs_buf_item_relse(bip, "put", XFS_BLI_NO_IODONE);
}

/*
 * Release the buffer associated with the buf log item.  If there is no dirty
 * logged data associated with the buffer recorded in the buf log item, then
 * free the buf log item and remove the reference to it in the buffer.
 *
 * This call ignores the recursion count.  It is only called when the buffer
 * should REALLY be unlocked, regardless of the recursion count.
 *
 * We unconditionally drop the transaction's reference to the log item. If the
 * item was logged, then another reference was taken when it was pinned, so we
 * can safely drop the transaction reference now.  This also allows us to avoid
 * potential races with the unpin code freeing the bli by not referencing the
 * bli after we've dropped the reference count.
 *
 * If the XFS_BLI_HOLD flag is set in the buf log item, then free the log item
 * if necessary but do not unlock the buffer.  This is for support of
 * xfs_trans_bhold(). Make sure the XFS_BLI_HOLD field is cleared if we don't
 * free the item.
 *
 * If the XFS_BLI_STALE flag is set, the last reference to the BLI *must*
 * perform a completion abort of any objects attached to the buffer for IO
 * tracking purposes. This generally only happens in shutdown situations,
 * normally xfs_buf_item_unpin() will drop the last BLI reference and perform
 * completion processing. However, because transaction completion can race with
 * checkpoint completion during a shutdown, this release context may end up
 * being the last active reference to the BLI and so needs to perform this
 * cleanup.
 */
STATIC void
xfs_buf_item_release(
	struct xfs_log_item	*lip)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	bool			hold = bip->bli_flags & XFS_BLI_HOLD;
	bool			stale = bip->bli_flags & XFS_BLI_STALE;
	bool			aborted = test_bit(XFS_LI_ABORTED,
						   &lip->li_flags);
	bool			dirty = bip->bli_flags & XFS_BLI_DIRTY;
#if defined(DEBUG) || defined(XFS_WARN)
	bool			ordered = bip->bli_flags & XFS_BLI_ORDERED;
#endif

	trace_xfs_buf_item_release(bip);

	ASSERT(xfs_buf_islocked(bp));

	/*
	 * The bli dirty state should match whether the blf has logged segments
	 * except for ordered buffers, where only the bli should be dirty.
	 */
	ASSERT((!ordered && dirty == xfs_buf_item_dirty_format(bip)) ||
	       (ordered && dirty && !xfs_buf_item_dirty_format(bip)));
	ASSERT(!stale || (bip->__bli_format.blf_flags & XFS_BLF_CANCEL));

	/*
	 * Clear the buffer's association with this transaction and
	 * per-transaction state from the bli, which has been copied above.
	 */
	bp->b_transp = NULL;
	bip->bli_flags &= ~(XFS_BLI_LOGGED | XFS_BLI_HOLD | XFS_BLI_ORDERED);

	/* If there are other references, then we have nothing to do. */
	if (!atomic_dec_and_test(&bip->bli_refcount))
		goto out_release;

	/*
	 * Stale buffer completion frees the BLI, unlocks and releases the
	 * buffer. Neither the BLI or buffer are safe to reference after this
	 * call, so there's nothing more we need to do here.
	 *
	 * If we get here with a stale buffer and references to the BLI remain,
	 * we must not unlock the buffer as the last BLI reference owns lock
	 * context, not us.
	 */
	if (stale) {
		xfs_buf_item_finish_stale(bip);
		xfs_buf_relse(bp);
		ASSERT(!hold);
		return;
	}

	/*
	 * Dirty or clean, aborted items are done and need to be removed from
	 * the AIL and released. This frees the BLI, but leaves the buffer
	 * locked and referenced.
	 */
	if (aborted || xlog_is_shutdown(lip->li_log)) {
		ASSERT(list_empty(&bip->bli_buf->b_li_list));
		/*
		 * sess-pve: this bli detaches WITHOUT writeback (xfs_buf_item_done
		 * runs no ioend, so bp->b_iodone never fires) — reclaim any
		 * outstanding mxfs_ag_meta_track hold here or it leaks and wedges
		 * xfs_buftarg_drain at unmount (agi/inobt/finobt stuck at b_hold=2).
		 */
		mxfs_ag_meta_reclaim(bp, "shutdown/abort");
		/* F4: shutdown is the only terminal cancel; a plain
		 * abort keeps the obligation open + probes (ruling item 3). */
		mxfs_f4_cancel(bp, xlog_is_shutdown(lip->li_log) ?
				MXFS_F4_CANCEL_SHUTDOWN : MXFS_F4_CANCEL_ABORT);
		xfs_buf_item_done(bp, XFS_BLI_NO_IODONE);
		goto out_release;
	}

	/*
	 * Clean, unreferenced BLIs can be immediately freed, leaving the buffer
	 * locked and referenced.
	 *
	 * Dirty, unreferenced BLIs *must* be in the AIL awaiting writeback.
	 */
	if (!dirty)
		xfs_buf_item_relse(bip, "release-clean", XFS_BLI_NO_IODONE);
	else
		ASSERT(test_bit(XFS_LI_IN_AIL, &lip->li_flags));

	/* Not safe to reference the BLI from here */
out_release:
	/*
	 * If we get here with a stale buffer, we must not unlock the
	 * buffer as the last BLI reference owns lock context, not us.
	 */
	if (stale || hold)
		return;
	xfs_buf_relse(bp);
}

STATIC void
xfs_buf_item_committing(
	struct xfs_log_item	*lip,
	xfs_csn_t		seq)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);

	/* F4: open/advance the committed-never-submitted obligation
	 * while bli_flags still carry LOGGED/ORDERED — xfs_buf_item_release
	 * clears them.  Buffer is still locked (bli owns b_sema here). */
	mxfs_f4_commit(bip->bli_buf, bip->bli_flags);
	return xfs_buf_item_release(lip);
}

/*
 * This is called to find out where the oldest active copy of the
 * buf log item in the on disk log resides now that the last log
 * write of it completed at the given lsn.
 * We always re-log all the dirty data in a buffer, so usually the
 * latest copy in the on disk log is the only one that matters.  For
 * those cases we simply return the given lsn.
 *
 * The one exception to this is for buffers full of newly allocated
 * inodes.  These buffers are only relogged with the XFS_BLI_INODE_BUF
 * flag set, indicating that only the di_next_unlinked fields from the
 * inodes in the buffers will be replayed during recovery.  If the
 * original newly allocated inode images have not yet been flushed
 * when the buffer is so relogged, then we need to make sure that we
 * keep the old images in the 'active' portion of the log.  We do this
 * by returning the original lsn of that transaction here rather than
 * the current one.
 */
STATIC xfs_lsn_t
xfs_buf_item_committed(
	struct xfs_log_item	*lip,
	xfs_lsn_t		lsn)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);

	trace_xfs_buf_item_committed(bip);

	if ((bip->bli_flags & XFS_BLI_INODE_ALLOC_BUF) && lip->li_lsn != 0)
		return lip->li_lsn;
	return lsn;
}

#ifdef DEBUG_EXPENSIVE
static int
xfs_buf_item_precommit(
	struct xfs_trans	*tp,
	struct xfs_log_item	*lip)
{
	struct xfs_buf_log_item	*bip = BUF_ITEM(lip);
	struct xfs_buf		*bp = bip->bli_buf;
	struct xfs_mount	*mp = bp->b_mount;
	xfs_failaddr_t		fa;

	if (!bp->b_ops || !bp->b_ops->verify_struct)
		return 0;
	if (bip->bli_flags & XFS_BLI_STALE)
		return 0;

	fa = bp->b_ops->verify_struct(bp);
	if (fa) {
		xfs_buf_verifier_error(bp, -EFSCORRUPTED, bp->b_ops->name,
				bp->b_addr, BBTOB(bp->b_length), fa);
		xfs_force_shutdown(mp, SHUTDOWN_CORRUPT_INCORE);
		ASSERT(fa == NULL);
	}

	return 0;
}
#else
# define xfs_buf_item_precommit	NULL
#endif

static const struct xfs_item_ops xfs_buf_item_ops = {
	.iop_size	= xfs_buf_item_size,
	.iop_precommit	= xfs_buf_item_precommit,
	.iop_format	= xfs_buf_item_format,
	.iop_pin	= xfs_buf_item_pin,
	.iop_unpin	= xfs_buf_item_unpin,
	.iop_release	= xfs_buf_item_release,
	.iop_committing	= xfs_buf_item_committing,
	.iop_committed	= xfs_buf_item_committed,
	.iop_push	= xfs_buf_item_push,
};

/*
 * Allocate a new buf log item to go with the given buffer.
 * Set the buffer's b_log_item field to point to the new
 * buf log item.
 */
int
xfs_buf_item_init(
	struct xfs_buf	*bp,
	struct xfs_mount *mp)
{
	struct xfs_buf_log_item	*bip = bp->b_log_item;
	int			chunks;
	int			map_size;
	int			i;

	/*
	 * Check to see if there is already a buf log item for
	 * this buffer. If we do already have one, there is
	 * nothing to do here so return.
	 */
	ASSERT(bp->b_mount == mp);
	if (bip) {
		ASSERT(bip->bli_item.li_type == XFS_LI_BUF);
		ASSERT(!bp->b_transp);
		ASSERT(bip->bli_buf == bp);
		return 0;
	}

	bip = kmem_cache_zalloc(xfs_buf_item_cache, GFP_KERNEL | __GFP_NOFAIL);
	xfs_log_item_init(mp, &bip->bli_item, XFS_LI_BUF, &xfs_buf_item_ops);
	bip->bli_buf = bp;

	/*
	 * chunks is the number of XFS_BLF_CHUNK size pieces the buffer
	 * can be divided into. Make sure not to truncate any pieces.
	 * map_size is the size of the bitmap needed to describe the
	 * chunks of the buffer.
	 *
	 * Discontiguous buffer support follows the layout of the underlying
	 * buffer. This makes the implementation as simple as possible.
	 */
	xfs_buf_item_get_format(bip, bp->b_map_count);

	for (i = 0; i < bip->bli_format_count; i++) {
		chunks = DIV_ROUND_UP(BBTOB(bp->b_maps[i].bm_len),
				      XFS_BLF_CHUNK);
		map_size = DIV_ROUND_UP(chunks, NBWORD);

		if (map_size > XFS_BLF_DATAMAP_SIZE) {
			xfs_buf_item_free_format(bip);
			kmem_cache_free(xfs_buf_item_cache, bip);
			xfs_err(mp,
	"buffer item dirty bitmap (%u uints) too small to reflect %u bytes!",
					map_size,
					BBTOB(bp->b_maps[i].bm_len));
			return -EFSCORRUPTED;
		}

		bip->bli_formats[i].blf_type = XFS_LI_BUF;
		bip->bli_formats[i].blf_blkno = bp->b_maps[i].bm_bn;
		bip->bli_formats[i].blf_len = bp->b_maps[i].bm_len;
		bip->bli_formats[i].blf_map_size = map_size;
	}

	bp->b_log_item = bip;
	xfs_buf_hold(bp);
	return 0;
}


/*
 * Mark bytes first through last inclusive as dirty in the buf
 * item's bitmap.
 */
static void
xfs_buf_item_log_segment(
	uint			first,
	uint			last,
	uint			*map)
{
	uint		first_bit;
	uint		last_bit;
	uint		bits_to_set;
	uint		bits_set;
	uint		word_num;
	uint		*wordp;
	uint		bit;
	uint		end_bit;
	uint		mask;

	ASSERT(first < XFS_BLF_DATAMAP_SIZE * XFS_BLF_CHUNK * NBWORD);
	ASSERT(last < XFS_BLF_DATAMAP_SIZE * XFS_BLF_CHUNK * NBWORD);

	/*
	 * Convert byte offsets to bit numbers.
	 */
	first_bit = first >> XFS_BLF_SHIFT;
	last_bit = last >> XFS_BLF_SHIFT;

	/*
	 * Calculate the total number of bits to be set.
	 */
	bits_to_set = last_bit - first_bit + 1;

	/*
	 * Get a pointer to the first word in the bitmap
	 * to set a bit in.
	 */
	word_num = first_bit >> BIT_TO_WORD_SHIFT;
	wordp = &map[word_num];

	/*
	 * Calculate the starting bit in the first word.
	 */
	bit = first_bit & (uint)(NBWORD - 1);

	/*
	 * First set any bits in the first word of our range.
	 * If it starts at bit 0 of the word, it will be
	 * set below rather than here.  That is what the variable
	 * bit tells us. The variable bits_set tracks the number
	 * of bits that have been set so far.  End_bit is the number
	 * of the last bit to be set in this word plus one.
	 */
	if (bit) {
		end_bit = min(bit + bits_to_set, (uint)NBWORD);
		mask = ((1U << (end_bit - bit)) - 1) << bit;
		*wordp |= mask;
		wordp++;
		bits_set = end_bit - bit;
	} else {
		bits_set = 0;
	}

	/*
	 * Now set bits a whole word at a time that are between
	 * first_bit and last_bit.
	 */
	while ((bits_to_set - bits_set) >= NBWORD) {
		*wordp = 0xffffffff;
		bits_set += NBWORD;
		wordp++;
	}

	/*
	 * Finally, set any bits left to be set in one last partial word.
	 */
	end_bit = bits_to_set - bits_set;
	if (end_bit) {
		mask = (1U << end_bit) - 1;
		*wordp |= mask;
	}
}

/*
 * Mark bytes first through last inclusive as dirty in the buf
 * item's bitmap.
 */
void
xfs_buf_item_log(
	struct xfs_buf_log_item	*bip,
	uint			first,
	uint			last)
{
	int			i;
	uint			start;
	uint			end;
	struct xfs_buf		*bp = bip->bli_buf;

	/*
	 * walk each buffer segment and mark them dirty appropriately.
	 */
	start = 0;
	for (i = 0; i < bip->bli_format_count; i++) {
		if (start > last)
			break;
		end = start + BBTOB(bp->b_maps[i].bm_len) - 1;

		/* skip to the map that includes the first byte to log */
		if (first > end) {
			start += BBTOB(bp->b_maps[i].bm_len);
			continue;
		}

		/*
		 * Trim the range to this segment and mark it in the bitmap.
		 * Note that we must convert buffer offsets to segment relative
		 * offsets (e.g., the first byte of each segment is byte 0 of
		 * that segment).
		 */
		if (first < start)
			first = start;
		if (end > last)
			end = last;
		xfs_buf_item_log_segment(first - start, end - start,
					 &bip->bli_formats[i].blf_data_map[0]);

		start += BBTOB(bp->b_maps[i].bm_len);
	}
}


/*
 * Return true if the buffer has any ranges logged/dirtied by a transaction,
 * false otherwise.
 */
bool
xfs_buf_item_dirty_format(
	struct xfs_buf_log_item	*bip)
{
	int			i;

	for (i = 0; i < bip->bli_format_count; i++) {
		if (!xfs_bitmap_empty(bip->bli_formats[i].blf_data_map,
			     bip->bli_formats[i].blf_map_size))
			return true;
	}

	return false;
}

void
xfs_buf_item_done(
	struct xfs_buf		*bp,
	enum xfs_bli_release_ctx ctx)
{
	/*
	 * — atomically CLAIM the BLI.  The stock code read
	 * bp->b_log_item twice (once for ail_delete, once for relse); two
	 * concurrent callers — reachable when a b_sema-poisoned buffer lets a
	 * completion and a retire (or two completions of a double submit) run
	 * simultaneously — both passed the caller's non-NULL check, the loser
	 * re-read NULL after the winner's relse and oopsed in
	 * xfs_buf_item_relse (PROVEN: test1 r17 validate2 015913Z, xfsaild
	 * NULL deref at xfs_buf_item_relse+0xf; the loser's ail_delete of the
	 * already-removed item also fired the spurious not-in-AIL
	 * SHUTDOWN_CORRUPT_INCORE that killed the FS moments earlier).  xchg
	 * guarantees exactly one caller retires the BLI; the loser logs loudly
	 * — this is containment + detection, NOT a mask: the poisoning source
	 * is tracked by P-SEMA-OVERUP/P-SEMA-DUALLOCK and stays a bug.
	 */
	struct xfs_buf_log_item	*bip = xchg(&bp->b_log_item, NULL);

	if (unlikely(!bip)) {
		static atomic_t pbdd_n = ATOMIC_INIT(0);
		int n = atomic_inc_return(&pbdd_n);

		if (n <= 200) {
			pr_warn("mxfs: P-BLI-DOUBLEDONE daddr=%lld ops=%s flags=0x%x comm=%s — concurrent xfs_buf_item_done lost the claim race (double completion/retire on one buffer)\n",
			    (long long)bp->b_maps[0].bm_bn,
			    bp->b_ops && bp->b_ops->name ? bp->b_ops->name : "?",
			    (unsigned int)bp->b_flags, current->comm);
			if (n <= 8)
				dump_stack();
		}
		/*
		 * No log item to retire, and on a no-I/O retirement nothing will
		 * run b_iodone either — so if this buffer is still carrying an
		 * AG-metadata tracking token, this is its last chance to return
		 * it.  The reclaim may drop the final reference, so touch nothing
		 * on bp afterwards.
		 */
		if (ctx == XFS_BLI_NO_IODONE)
			mxfs_ag_meta_reclaim(bp, "retire-no-bli");
		return;
	}

	/*
	 * If we are forcibly shutting down, this may well be off the AIL
	 * already. That's because we simulate the log-committed callbacks to
	 * unpin these buffers. Or we may never have put this item on AIL
	 * because of the transaction was aborted forcibly.
	 * xfs_trans_ail_delete() takes care of these.
	 *
	 * Either way, AIL is useless if we're forcing a shutdown.
	 *
	 * Note that log recovery writes might have buffer items that are not on
	 * the AIL even when the file system is not shut down.
	 *
	 * 513B review item 1: foreign-replay buffers carry the same
	 * "not-in-AIL is normal" property but the swapext owner-change family
	 * (bmbt blocks via xfs_btree_block_change_owner) never gets
	 * _XBF_LOGRECOVERY — a live bli attached to such a buffer must not
	 * let the not-in-AIL delete shut down the SURVIVOR's mount, so the
	 * provenance suppresses the shutdown type exactly like the flag.
	 * (__xfs_buf_ioend clears the provenance only after this runs.)
	 */
	xfs_trans_ail_delete(&bip->bli_item,
			     ((bp->b_flags & _XBF_LOGRECOVERY) ||
			      bp->b_mxfs_foreign_recovery) ? 0 :
			     SHUTDOWN_CORRUPT_INCORE);
	xfs_buf_item_relse(bip,
			   ctx == XFS_BLI_IODONE_FOLLOWS ? "iodone"
							 : "retire-noio",
			   ctx);
}
