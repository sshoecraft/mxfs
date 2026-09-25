// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS -- the F4 obligation registry, inode-cluster writes and the obligation freeze
 */
#define MXFS_TU_ID 15	/* igrab/iput call-site file id */
#include "xfs_mxfs_dlm_priv.h"

/*
 * — F4 OBLIGATION REGISTRY (D-FOREIGN-REPLAY-UNGATED-IMAGES hard
 * barrier F4: dir-class COMMITTED-NEVER-SUBMITTED).
 *
 * The F1 tripwire (oblig_cas) sees a commit racing the flush→unlock window;
 * what nothing saw until now is a dir-class buffer whose modification was
 * COMMITTED (iop_committing ran — the change is in the CIL/log and will
 * replay) but whose covering write was never even SUBMITTED before the dir
 * grant is handed to a peer.  The peer then cold-reads the stale platter
 * image with full authority, and our committed change lands later from
 * xfsaild with none — the exact publish-without-authority shape P219
 * counts downstream.
 *
 * One ENUMERABLE record per such buffer (design-consult ruling item 1 — a
 * count cannot repair the (f) fence-suppressed permanent-wedge shape; a
 * {ino,daddr,length,gen} descriptor can re-drive the exact buffer).  No bp
 * hold: a leaked hold would wedge xfs_buftarg_drain at unmount; a leaked
 * DESCRIPTOR is loud (P286) and harmless.  Lifecycle, all under b_sema:
 *   commit  (xfs_buf_item_committing, dirty|ordered, !stale, dir-class)
 *           → open record / bump f4_committed_gen (own u64 gen — NOT
 *             b_mxfs_logged_seq, which ORDERED buffers dirty without
 *             advancing; ruling item 2)
 *   submit  (xfs_buf_submit_bio, XBF_WRITE) → f4_submit_gen = committed_gen
 *   ioend   (success, !fence_skipped, submit_gen >= committed_gen) → RETIRE
 *   finish_stale (committed XFS_BLF_CANCEL) → STALE-CANCEL
 *   abort under xlog_is_shutdown → SHUTDOWN-CANCEL
 *   abort without shutdown → KEEP OPEN + P284 (ruling item 3: a later
 *             aborting txn must not erase an older committed obligation)
 *   fence-suppressed "success" → KEEP OPEN + P287 (nothing reached the LUN)
 *   buffer freed with record open → ORPHAN (record kept, buffer_gone) + P286
 * Owner ino comes from the buffer's own v5 header (magic-validated per
 * class); owner==0/invalid lands in the unknown poison bucket, which the
 * release proof treats as open-for-EVERY-dir (fail closed).
 * Conservation at quiesce: opens == retires + stale_cancels +
 * shutdown_cancels + open-now.
 *
 * ENFORCEMENT (mxfs_f4_gate=1) IS BLOCKED by ruling items 4+5 (records
 * need tenure tagging or drain-at-enable; the proof-vs-new-commit race
 * needs the linearized close protocol).  Default 0 = telemetry: the P285
 * census fires when a dir release proof walks clean while F4 records for
 * that dir are open — that occurrence IS the defect made visible.
 */
int mxfs_f4_gate;
module_param_named(f4_gate, mxfs_f4_gate, int, 0644);
MODULE_PARM_DESC(f4_gate,
		 "F4 committed-never-submitted obligations block the dir "
		 "release proof (0=telemetry only default; 1=extra durable "
		 "passes + defer while open — NOT yet sound for enforcement, "
		 "see ruling items 4-5)");

static atomic64_t mxfs_f4_genctr;	/* global monotonic commit generation */

static inline struct hlist_head *
mxfs_f4_bucket(struct mxfs_f4_registry *reg, uint64_t ino)
{
	return &reg->f4_hash[hash_64(ino, 8)];	/* 2^8 == MXFS_F4_HASH_BUCKETS */
}

static bool
mxfs_f4_class(struct xfs_buf *bp)
{
	/*
	 * Same class set as the dir writeback-completion barrier at
	 * xfs_buf_submit_bio: every buffer type a peer consults through the
	 * dir handoff.  bmbt included per ruling item 9 (counting non-dir
	 * bmbt too is conservative — only dir release consults by owner).
	 */
	return bp->b_ops == &xfs_dir3_data_buf_ops ||
	       bp->b_ops == &xfs_dir3_block_buf_ops ||
	       bp->b_ops == &xfs_dir3_leaf1_buf_ops ||
	       bp->b_ops == &xfs_dir3_leafn_buf_ops ||
	       bp->b_ops == &xfs_dir3_free_buf_ops ||
	       bp->b_ops == &xfs_da3_node_buf_ops ||
	       bp->b_ops == &xfs_bmbt_buf_ops;
}

/*
 * Decode the owner ino from the buffer's own v5 header, validating the
 * magic so the field offset is never guessed (ruling item 8).  Returns 0
 * for anything unrecognized — the caller files it under the unknown
 * poison bucket, which fails closed.
 */
static uint64_t
mxfs_f4_owner_decode(struct xfs_buf *bp)
{
	void			*blk = bp->b_addr;
	uint32_t		magic32;

	if (!blk || BBTOB(bp->b_length) < sizeof(struct xfs_dir3_blk_hdr))
		return 0;
	magic32 = be32_to_cpu(*(__be32 *)blk);
	switch (magic32) {
	case XFS_DIR3_BLOCK_MAGIC:
	case XFS_DIR3_DATA_MAGIC:
		return be64_to_cpu(((struct xfs_dir3_blk_hdr *)blk)->owner);
	case XFS_DIR3_FREE_MAGIC:
		return be64_to_cpu(((struct xfs_dir3_free_hdr *)blk)->hdr.owner);
	case XFS_BMAP_CRC_MAGIC:
		return be64_to_cpu(((struct xfs_btree_block *)blk)->bb_u.l.bb_owner);
	}
	switch (be16_to_cpu(((struct xfs_da_blkinfo *)blk)->magic)) {
	case XFS_DIR3_LEAF1_MAGIC:
	case XFS_DIR3_LEAFN_MAGIC:
	case XFS_DA3_NODE_MAGIC:
	case XFS_ATTR3_LEAF_MAGIC:
		return be64_to_cpu(((struct xfs_da3_blkinfo *)blk)->owner);
	}
	return 0;
}

void
mxfs_f4_registry_init(struct xfs_mount *mp)
{
	struct mxfs_f4_registry	*reg = &mp->m_mxfs_f4;
	int			i;

	spin_lock_init(&reg->f4_lock);
	for (i = 0; i < MXFS_F4_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&reg->f4_hash[i]);
	atomic64_set(&reg->f4_opens, 0);
	atomic64_set(&reg->f4_recommits, 0);
	atomic64_set(&reg->f4_retires, 0);
	atomic64_set(&reg->f4_stale_cancels, 0);
	atomic64_set(&reg->f4_shutdown_cancels, 0);
	atomic64_set(&reg->f4_abort_keeps, 0);
	atomic64_set(&reg->f4_orphans, 0);
	atomic64_set(&reg->f4_suppress_skips, 0);
	atomic64_set(&reg->f4_ordered_opens, 0);
	atomic_set(&reg->f4_unknown, 0);
}

void
mxfs_f4_registry_destroy(struct xfs_mount *mp)
{
	struct mxfs_f4_registry	*reg = &mp->m_mxfs_f4;
	struct mxfs_f4_record	*rec;
	struct hlist_node	*tmp;
	int			i, live = 0, orphan = 0;

	spin_lock(&reg->f4_lock);
	for (i = 0; i < MXFS_F4_HASH_BUCKETS; i++) {
		hlist_for_each_entry_safe(rec, tmp, &reg->f4_hash[i],
					  f4_node) {
			if (rec->f4_buffer_gone)
				orphan++;
			else
				live++;
			hlist_del(&rec->f4_node);
			kfree(rec);
		}
	}
	spin_unlock(&reg->f4_lock);
	/*
	 * Every open record should have been retired/cancelled by unmount's
	 * flushes, or orphaned by xfs_buf_free during buftarg drain.  A LIVE
	 * (non-orphan) record here means a buffer was freed without the
	 * orphan hook or a record leaked — both are registry defects.
	 */
	if (live || orphan)
		pr_warn("mxfs: P286-F4-TEARDOWN-OPEN live=%d orphan=%d — obligations still open at registry destroy\n",
			live, orphan);
	mxfs_probe("mxfs: F4-REGISTRY-TOTAL opens=%lld recommits=%lld retires=%lld stale_cancels=%lld shutdown_cancels=%lld abort_keeps=%lld orphans=%lld suppress_skips=%lld ordered=%lld unknown=%d open_at_destroy=%d\n",
		(long long)atomic64_read(&reg->f4_opens),
		(long long)atomic64_read(&reg->f4_recommits),
		(long long)atomic64_read(&reg->f4_retires),
		(long long)atomic64_read(&reg->f4_stale_cancels),
		(long long)atomic64_read(&reg->f4_shutdown_cancels),
		(long long)atomic64_read(&reg->f4_abort_keeps),
		(long long)atomic64_read(&reg->f4_orphans),
		(long long)atomic64_read(&reg->f4_suppress_skips),
		(long long)atomic64_read(&reg->f4_ordered_opens),
		atomic_read(&reg->f4_unknown), live + orphan);
}

struct mxfs_icwr_entry *
mxfs_icwr_get(struct xfs_mount *mp, xfs_daddr_t daddr, bool create)
{
	struct mxfs_icwr_registry *reg = &mp->m_mxfs_icwr;
	struct hlist_head	*bucket =
		&reg->icwr_hash[hash_64((u64)daddr, 8)];
	struct mxfs_icwr_entry	*ent;

	spin_lock(&reg->icwr_lock);
	hlist_for_each_entry(ent, bucket, ie_node) {
		if (ent->ie_daddr == daddr) {
			spin_unlock(&reg->icwr_lock);
			return ent;
		}
	}
	if (!create) {
		spin_unlock(&reg->icwr_lock);
		return NULL;
	}
	/* submit context may be atomic (bio submission under locks) */
	ent = kzalloc(sizeof(*ent), GFP_NOWAIT | __GFP_NOWARN);
	if (ent) {
		ent->ie_daddr = daddr;
		atomic_set(&ent->ie_inflight, 0);
		atomic64_set(&ent->ie_submit_gen, 0);
		atomic64_set(&ent->ie_complete_gen, 0);
		hlist_add_head(&ent->ie_node, bucket);
		atomic_inc(&reg->icwr_entries);
	}
	spin_unlock(&reg->icwr_lock);
	return ent;
}

void
mxfs_icwr_registry_init(struct xfs_mount *mp)
{
	struct mxfs_icwr_registry *reg = &mp->m_mxfs_icwr;
	int	i;

	spin_lock_init(&reg->icwr_lock);
	for (i = 0; i < MXFS_ICWR_HASH_BUCKETS; i++)
		INIT_HLIST_HEAD(&reg->icwr_hash[i]);
	init_waitqueue_head(&reg->icwr_wq);
	atomic64_set(&reg->icwr_submits, 0);
	atomic64_set(&reg->icwr_completes, 0);
	atomic64_set(&reg->icwr_resubmit_keeps, 0);
	atomic64_set(&reg->icwr_orphans, 0);
	atomic64_set(&reg->icwr_underflows, 0);
	atomic64_set(&reg->icwr_untracked, 0);
	atomic_set(&reg->icwr_entries, 0);
	atomic_set(&mp->m_mxfs_iclus_wr_inflight, 0);
}

void
mxfs_icwr_registry_destroy(struct xfs_mount *mp)
{
	struct mxfs_icwr_registry *reg = &mp->m_mxfs_icwr;
	struct mxfs_icwr_entry	*ent;
	struct hlist_node	*tmp;
	int	i, leaked = 0;

	spin_lock(&reg->icwr_lock);
	for (i = 0; i < MXFS_ICWR_HASH_BUCKETS; i++) {
		hlist_for_each_entry_safe(ent, tmp, &reg->icwr_hash[i],
					  ie_node) {
			leaked += atomic_read(&ent->ie_inflight);
			hlist_del(&ent->ie_node);
			kfree(ent);
		}
	}
	spin_unlock(&reg->icwr_lock);
	if (leaked)
		pr_warn("mxfs: P288-ICWR-TEARDOWN-LEAK inflight=%d — counted inode-cluster writes never completed (orphans=%lld)\n",
			leaked, (long long)atomic64_read(&reg->icwr_orphans));
	mxfs_probe("mxfs: ICWR-REGISTRY-TOTAL submits=%lld completes=%lld resubmit_keeps=%lld orphans=%lld underflows=%lld untracked=%lld entries=%d leaked_inflight=%d\n",
		(long long)atomic64_read(&reg->icwr_submits),
		(long long)atomic64_read(&reg->icwr_completes),
		(long long)atomic64_read(&reg->icwr_resubmit_keeps),
		(long long)atomic64_read(&reg->icwr_orphans),
		(long long)atomic64_read(&reg->icwr_underflows),
		(long long)atomic64_read(&reg->icwr_untracked),
		atomic_read(&reg->icwr_entries), leaked);
}

/*
 * Submit-side count, called from xfs_buf_submit_bio BEFORE the
 * partial-inode-write diversion (both paths complete via __xfs_buf_ioend).
 */
void
mxfs_icwr_submit(struct xfs_buf *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct mxfs_icwr_registry *reg;
	struct mxfs_icwr_entry	*ent;

	if (!(bp->b_flags & XBF_WRITE) || !mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm) ||
	    bp->b_ops != &xfs_inode_buf_ops)
		return;
	reg = &mp->m_mxfs_icwr;
	if (unlikely(bp->b_mxfs_iclus_wr_counted)) {
		/*
		 * Error-path resubmit before its completion decremented (the
		 * P-WRCNT-RESUBMIT family): keep the single logical-write
		 * token — the resubmission's completion decrements exactly
		 * once, and the keyed inflight never transits zero while the
		 * logical write is still capable of landing (ruling item A).
		 */
		atomic64_inc(&reg->icwr_resubmit_keeps);
		mxfs_probe_ratelimited("mxfs: P287-ICWR-RESUBMIT daddr=%lld inflight=%d — counted inode-cluster write resubmitted before completion; keeping single token\n",
				    (long long)bp->b_maps[0].bm_bn,
				    bp->b_mxfs_icwr_ent ?
					atomic_read(&bp->b_mxfs_icwr_ent->ie_inflight) : -1);
		return;
	}
	ent = mxfs_icwr_get(mp, bp->b_maps[0].bm_bn, true);
	if (unlikely(!ent)) {
		/*
		 * Allocation failed at submit: this write is UNTRACKED.  The
		 * sticky counter poisons every subsequent keyed proof whose
		 * entry lookup misses (conservative: proof_failed, telemetry)
		 * — a tracked-looking clean pass over an untracked in-flight
		 * write would be exactly the false certificate F3 exists to
		 * kill.
		 */
		atomic64_inc(&reg->icwr_untracked);
		pr_warn_ratelimited("mxfs: P287-ICWR-UNTRACKED daddr=%lld — icwr entry alloc failed; cluster proofs poisoned conservative\n",
				    (long long)bp->b_maps[0].bm_bn);
		return;
	}
	atomic64_inc(&ent->ie_submit_gen);
	atomic_inc(&ent->ie_inflight);
	atomic_inc(&mp->m_mxfs_iclus_wr_inflight);
	atomic64_inc(&reg->icwr_submits);
	bp->b_mxfs_icwr_ent = ent;
	bp->b_mxfs_iclus_wr_counted = true;
}

/*
 * Completion-side retire, called from __xfs_buf_ioend's write branch AFTER
 * the error/resubmit decision (a resubmit returns early there and keeps
 * the token; see mxfs_icwr_submit's neutralizer).
 */
void
mxfs_icwr_complete(struct xfs_buf *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct mxfs_icwr_entry	*ent = bp->b_mxfs_icwr_ent;
	struct mxfs_icwr_registry *reg;
	int	now;

	if (!bp->b_mxfs_iclus_wr_counted)
		return;
	bp->b_mxfs_iclus_wr_counted = false;
	bp->b_mxfs_icwr_ent = NULL;
	if (!mp)
		return;
	reg = &mp->m_mxfs_icwr;
	atomic64_inc(&reg->icwr_completes);
	if (ent) {
		/* gen bump BEFORE the dec: a proof that samples inflight==0
		 * is guaranteed to see this completion in complete_gen */
		atomic64_inc(&ent->ie_complete_gen);
		now = atomic_dec_return(&ent->ie_inflight);
		if (unlikely(now < 0)) {
			atomic_set(&ent->ie_inflight, 0);
			atomic64_inc(&reg->icwr_underflows);
			mxfs_probe_ratelimited("mxfs: P287-ICWR-UNDERFLOW daddr=%lld — keyed inflight went negative; clamped\n",
					    (long long)ent->ie_daddr);
		}
	}
	now = atomic_dec_return(&mp->m_mxfs_iclus_wr_inflight);
	if (unlikely(now < 0))
		atomic_set(&mp->m_mxfs_iclus_wr_inflight, 0);
	wake_up_all(&reg->icwr_wq);
}

/*
 * Teardown orphan hook (beside mxfs_f4_buf_free): a counted buffer freed
 * without its completion FAILS CLOSED — the keyed entry keeps its
 * inflight, so that cluster's release proofs land as proof_failed via the
 * bounded wait (telemetry while the gate is off) instead of certifying a
 * write whose fate is unknown.
 */
void
mxfs_icwr_buf_free(struct xfs_buf *bp)
{
	if (!bp->b_mxfs_iclus_wr_counted)
		return;
	bp->b_mxfs_iclus_wr_counted = false;
	if (bp->b_mount) {
		atomic64_inc(&bp->b_mount->m_mxfs_icwr.icwr_orphans);
		/* telemetry mirror must not leak with the entry (which is
		 * deliberately kept inflight) */
		if (atomic_dec_return(&bp->b_mount->m_mxfs_iclus_wr_inflight) < 0)
			atomic_set(&bp->b_mount->m_mxfs_iclus_wr_inflight, 0);
	}
	pr_alert("mxfs: P288-ICWR-ORPHAN daddr=%lld ent=%d — counted inode-cluster write buffer freed without completion; keyed entry kept inflight (fail closed)\n",
		 (long long)(bp->b_mxfs_icwr_ent ?
			     bp->b_mxfs_icwr_ent->ie_daddr : -1),
		 bp->b_mxfs_icwr_ent ?
			atomic_read(&bp->b_mxfs_icwr_ent->ie_inflight) : -1);
	bp->b_mxfs_icwr_ent = NULL;
}

/*
 * iop_committing hook, called under b_sema BEFORE xfs_buf_item_release
 * clears the per-transaction bli flags.  Opens (or re-commits) the
 * obligation for a dirty, non-stale, dir-class buffer.
 */
void
mxfs_f4_commit(struct xfs_buf *bp, unsigned int bli_flags)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct mxfs_f4_registry	*reg;
	struct mxfs_f4_record	*rec;
	uint64_t		owner;
	u64			gen;

	if (!mp || !mp->m_mxfs_dlm ||
	    mxfs_v5_dlm_is_single_node(mp->m_mxfs_dlm))
		return;
	if (!(bli_flags & (XFS_BLI_DIRTY | XFS_BLI_ORDERED)))
		return;
	if ((bp->b_flags & XBF_STALE) || (bli_flags & XFS_BLI_STALE))
		return;
	if (!mxfs_f4_class(bp))
		return;
	reg = &mp->m_mxfs_f4;
	owner = mxfs_f4_owner_decode(bp);
	if (bli_flags & XFS_BLI_ORDERED)
		atomic64_inc(&reg->f4_ordered_opens);
	gen = (u64)atomic64_inc_return(&mxfs_f4_genctr);
	rec = bp->b_mxfs_f4_rec;	/* b_sema-stable */
	if (!rec) {
		/* GFP_NOFS|__GFP_NOFAIL per CIL precedent (ruling item 11):
		 * no allocation-failure poison path to reason about. */
		rec = kmalloc(sizeof(*rec), GFP_NOFS | __GFP_NOFAIL);
		rec->f4_ino = owner;
		rec->f4_daddr = bp->b_maps[0].bm_bn;
		rec->f4_length = bp->b_length;
		rec->f4_gen = gen;
		rec->f4_buffer_gone = 0;
		rec->f4_aborted = 0;
		spin_lock(&reg->f4_lock);
		hlist_add_head(&rec->f4_node, mxfs_f4_bucket(reg, owner));
		spin_unlock(&reg->f4_lock);
		bp->b_mxfs_f4_rec = rec;
		atomic64_inc(&reg->f4_opens);
		if (owner == 0)
			atomic_inc(&reg->f4_unknown);
	} else {
		spin_lock(&reg->f4_lock);
		if (unlikely(rec->f4_ino != owner)) {
			/* block repurposed while a committed obligation is
			 * open — rehash under the new owner, conservatively
			 * keeping the record (ruling item 8 assert) */
			mxfs_probe_ratelimited(
			    "mxfs: P284-F4-OWNER-MISMATCH daddr=%lld old_ino=%llu new_ino=%llu gen=%llu — owner changed under an open obligation\n",
				(long long)rec->f4_daddr,
				(unsigned long long)rec->f4_ino,
				(unsigned long long)owner,
				(unsigned long long)gen);
			hlist_del(&rec->f4_node);
			if (rec->f4_ino == 0 && owner != 0)
				atomic_dec(&reg->f4_unknown);
			else if (rec->f4_ino != 0 && owner == 0)
				atomic_inc(&reg->f4_unknown);
			rec->f4_ino = owner;
			hlist_add_head(&rec->f4_node,
				       mxfs_f4_bucket(reg, owner));
		}
		rec->f4_gen = gen;
		spin_unlock(&reg->f4_lock);
		atomic64_inc(&reg->f4_recommits);
	}
	bp->b_mxfs_f4_committed_gen = gen;
	bp->b_mxfs_f4_owner = owner;
}

/* Write-bio submit (under the submitter's buffer hold): snapshot what this
 * bio covers.  Retire compares the snapshot at completion. */
void
mxfs_f4_submit(struct xfs_buf *bp)
{
	if (bp->b_flags & XBF_WRITE)
		bp->b_mxfs_f4_submit_gen = bp->b_mxfs_f4_committed_gen;
}

static void
mxfs_f4_record_close(struct xfs_buf *bp, struct mxfs_f4_record *rec,
		     atomic64_t *counter)
{
	struct mxfs_f4_registry	*reg = &bp->b_mount->m_mxfs_f4;

	spin_lock(&reg->f4_lock);
	hlist_del(&rec->f4_node);
	spin_unlock(&reg->f4_lock);
	if (rec->f4_ino == 0)
		atomic_dec(&reg->f4_unknown);
	atomic64_inc(counter);
	kfree(rec);
	bp->b_mxfs_f4_rec = NULL;
}

void
mxfs_f4_cancel(struct xfs_buf *bp, enum mxfs_f4_cancel_why why)
{
	struct mxfs_f4_registry	*reg;
	struct mxfs_f4_record	*rec = bp->b_mxfs_f4_rec;

	if (!rec || !bp->b_mount)
		return;
	reg = &bp->b_mount->m_mxfs_f4;
	if (why == MXFS_F4_CANCEL_ABORT) {
		/* NOT a cancel (ruling item 3): this abort may belong to a
		 * LATER transaction than the commit that opened the record;
		 * erasing it would lose an older committed obligation.  Keep
		 * open — shutdown-cancel or retire will disposition it. */
		rec->f4_aborted = 1;
		atomic64_inc(&reg->f4_abort_keeps);
		pr_warn_ratelimited(
		    "mxfs: P284-F4-ABORT-KEEP ino=%llu daddr=%lld gen=%llu — aborted without shutdown; obligation kept open\n",
			(unsigned long long)rec->f4_ino,
			(long long)rec->f4_daddr,
			(unsigned long long)rec->f4_gen);
		return;
	}
	mxfs_f4_record_close(bp, rec,
			     why == MXFS_F4_CANCEL_STALE ?
				&reg->f4_stale_cancels :
				&reg->f4_shutdown_cancels);
}

/*
 * Write completion (before the wr_counted decrement in __xfs_buf_ioend,
 * buffer still locked).  Retires on a successful, non-suppressed write
 * whose submit snapshot covers the latest committed gen.
 */
void
mxfs_f4_write_complete(struct xfs_buf *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct mxfs_f4_registry	*reg;
	struct mxfs_f4_record	*rec = bp->b_mxfs_f4_rec;

	if (!rec || !mp || !(bp->b_flags & XBF_WRITE))
		return;
	reg = &mp->m_mxfs_f4;
	if (bp->b_mxfs_fence_skipped) {
		/* the (f) shape: submitter saw "success", NOTHING reached
		 * the LUN.  The obligation stays open — this record is what
		 * lets release re-drive the buffer (ruling item 1). */
		atomic64_inc(&reg->f4_suppress_skips);
		pr_warn_ratelimited(
		    "mxfs: P287-F4-SUPPRESSED-COMPLETION ino=%llu daddr=%lld gen=%llu — fence suppressed the covering write; obligation stays open\n",
			(unsigned long long)rec->f4_ino,
			(long long)rec->f4_daddr,
			(unsigned long long)rec->f4_gen);
		return;
	}
	if (bp->b_error) {
		if (xfs_is_shutdown(mp))
			mxfs_f4_cancel(bp, MXFS_F4_CANCEL_SHUTDOWN);
		/* transient error: keep open; the retry path re-submits or
		 * escalates to shutdown */
		return;
	}
	if (bp->b_mxfs_f4_submit_gen < bp->b_mxfs_f4_committed_gen)
		return;	/* a newer commit landed after this bio's snapshot */
	mxfs_f4_record_close(bp, rec, &reg->f4_retires);
}

/* Buffer teardown with the obligation still open: fail closed.  The
 * DESCRIPTOR outlives the buffer (marked buffer_gone) so the census and
 * any future enforcement still see the exposure; only registry destroy
 * frees it. */
void
mxfs_f4_buf_free(struct xfs_buf *bp)
{
	struct xfs_mount	*mp = bp->b_mount;
	struct mxfs_f4_registry	*reg;
	struct mxfs_f4_record	*rec = bp->b_mxfs_f4_rec;

	if (!rec || !mp)
		return;
	reg = &mp->m_mxfs_f4;
	spin_lock(&reg->f4_lock);
	rec->f4_buffer_gone = 1;
	spin_unlock(&reg->f4_lock);
	atomic64_inc(&reg->f4_orphans);
	bp->b_mxfs_f4_rec = NULL;
	pr_warn("mxfs: P286-F4-ORPHAN ino=%llu daddr=%lld len=%u gen=%llu aborted=%u shutdown=%d — buffer freed with committed-never-submitted obligation open; record kept\n",
		(unsigned long long)rec->f4_ino, (long long)rec->f4_daddr,
		rec->f4_length, (unsigned long long)rec->f4_gen,
		rec->f4_aborted, xfs_is_shutdown(mp) ? 1 : 0);
}

/*
 * Release-proof query: open obligations owned by this dir.  unknown_out
 * returns the poison-bucket population — the proof treats unknown>0 as
 * open for EVERY dir (fail closed, ruling item 8).
 */
long
mxfs_f4_open_for_dir(struct xfs_mount *mp, uint64_t dir_ino, int *unknown_out)
{
	struct mxfs_f4_registry	*reg = &mp->m_mxfs_f4;
	struct mxfs_f4_record	*rec;
	long			n = 0;

	spin_lock(&reg->f4_lock);
	hlist_for_each_entry(rec, mxfs_f4_bucket(reg, dir_ino), f4_node)
		if (rec->f4_ino == dir_ino)
			n++;
	spin_unlock(&reg->f4_lock);
	if (unknown_out)
		*unknown_out = atomic_read(&reg->f4_unknown);
	return n;
}

/* P285 census detail: enumerate (up to 4) the open records behind a
 * walk-clean-but-F4-open occurrence, so the log names the exact buffers. */
static void
mxfs_f4_census_dump(struct xfs_mount *mp, uint64_t dir_ino)
{
	struct mxfs_f4_registry	*reg = &mp->m_mxfs_f4;
	struct mxfs_f4_record	*rec;
	struct { xfs_daddr_t daddr; unsigned int len; u64 gen; u8 gone, aborted; } snap[4];
	int			shown = 0;
	int			i;

	spin_lock(&reg->f4_lock);
	hlist_for_each_entry(rec, mxfs_f4_bucket(reg, dir_ino), f4_node) {
		if (rec->f4_ino != dir_ino || shown >= 4)
			continue;
		snap[shown].daddr = rec->f4_daddr;
		snap[shown].len = rec->f4_length;
		snap[shown].gen = rec->f4_gen;
		snap[shown].gone = rec->f4_buffer_gone;
		snap[shown].aborted = rec->f4_aborted;
		shown++;
	}
	spin_unlock(&reg->f4_lock);
	/*
	 * (D-FOREIGN-REPLAY-UNGATED-IMAGES default-on, design-consult proviso):
	 * an open record at a walked-clean dir release is either a REAL
	 * committed-never-submitted buffer (its image in this node's slice is
	 * the only copy; a clean-release RELMARK would let a survivor class the
	 * victim's image REDUNDANT_CLEAN and skip it) or a stale registry
	 * record (accounting imprecision, ruling items 4-5).  Decide it from the
	 * buffer itself, outside the registry lock: incore trylock, then the
	 * log item's DIRTY / IN_AIL state, the delwri flag and the F4 gens.
	 */
	for (i = 0; i < shown; i++) {
		struct xfs_buf		*bp;
		struct xfs_buf_log_item	*bip;
		const char		*truth;

		if (snap[i].gone) {
			pr_warn("mxfs: P285-F4-REC ino=%llu daddr=%lld len=%u gen=%llu gone=1 aborted=%u truth=BUFFER-GONE\n",
				(unsigned long long)dir_ino, (long long)snap[i].daddr,
				snap[i].len, (unsigned long long)snap[i].gen,
				snap[i].aborted);
			continue;
		}
		bp = NULL;
		if (xfs_buf_incore(mp->m_ddev_targp, snap[i].daddr,
				   snap[i].len, XBF_TRYLOCK, &bp) || !bp) {
			pr_warn("mxfs: P285-F4-REC ino=%llu daddr=%lld len=%u gen=%llu gone=0 aborted=%u truth=NOT-INCORE-OR-BUSY\n",
				(unsigned long long)dir_ino, (long long)snap[i].daddr,
				snap[i].len, (unsigned long long)snap[i].gen,
				snap[i].aborted);
			continue;
		}
		bip = bp->b_log_item;
		if (bip && ((bip->bli_flags & XFS_BLI_DIRTY) ||
			    test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags)))
			truth = "REAL-UNSUBMITTED";	/* dirty/AIL, home stale */
		else if (bp->b_mxfs_f4_committed_gen > bp->b_mxfs_f4_submit_gen)
			truth = "GEN-OPEN-NOT-DIRTY";	/* record open, item clean */
		else
			truth = "STALE-RECORD";		/* buffer already submitted */
		pr_warn("mxfs: P285-F4-REC ino=%llu daddr=%lld len=%u gen=%llu gone=0 aborted=%u truth=%s bli=%d dirty=%d in_ail=%d delwri=%d committed_gen=%llu submit_gen=%llu rec=%d\n",
			(unsigned long long)dir_ino, (long long)snap[i].daddr,
			snap[i].len, (unsigned long long)snap[i].gen,
			snap[i].aborted, truth, bip ? 1 : 0,
			bip ? !!(bip->bli_flags & XFS_BLI_DIRTY) : 0,
			bip ? !!test_bit(XFS_LI_IN_AIL, &bip->bli_item.li_flags) : 0,
			!!(bp->b_flags & _XBF_DELWRI_Q),
			(unsigned long long)bp->b_mxfs_f4_committed_gen,
			(unsigned long long)bp->b_mxfs_f4_submit_gen,
			bp->b_mxfs_f4_rec ? 1 : 0);
		xfs_buf_relse(bp);
	}
}

/*
 * THE F4 occurrence probe: the dir release proof walked clean (pending ==
 * durable) while committed-never-submitted obligations for this dir are
 * still open.  Under gate=0 the CAS then proceeds and the committed bytes
 * land later without authority — exactly what this registry exists to
 * make countable before enforcement.
 */
void
mxfs_relbar_f4_census(struct xfs_inode *ip, long f4_open, int f4_unknown,
		      const char *site)
{
	static atomic_t p285_n = ATOMIC_INIT(0);

	if (atomic_inc_return(&p285_n) <= 400)
		mxfs_probe("mxfs: P285-F4-CENSUS ino=%llu site=%s f4_open=%ld unknown=%d pend=%llu dur=%llu gate=%d — dir release proof walked clean with committed-never-submitted obligations open\n",
			(unsigned long long)ip->i_ino, site, f4_open,
			f4_unknown,
			(unsigned long long)READ_ONCE(ip->i_mxfs_pub_pending_seq),
			(unsigned long long)READ_ONCE(ip->i_mxfs_pub_durable_seq),
			mxfs_f4_gate);
	mxfs_f4_census_dump(ip->i_mount, ip->i_ino);
}

/*
 * ── 0.85.0: the obligation freeze (xfs_mount.h m_mxfs_oblf_*) ──
 *
 * One entry per victim slot, keyed by (victim_epoch, pub_seq); the union is
 * what __mxfs_ag_dlm_lock reads.  Every install/lift recomputes the union
 * under the lock and wakes the waitqueue — a lift is the only event a
 * blocked acquirer is waiting for, a wake on install costs nothing.
 */
static void
mxfs_oblf_recompute_locked(
	struct xfs_mount	*mp)
{
	uint64_t		mask = 0;
	bool			fsw = false;
	int			i;

	for (i = 0; i < 64; i++) {
		mask |= mp->m_mxfs_oblf_slot_mask[i];
		fsw |= mp->m_mxfs_oblf_slot_fswide[i];
	}
	WRITE_ONCE(mp->m_mxfs_oblf_mask, mask);
	WRITE_ONCE(mp->m_mxfs_oblf_fswide, fsw);
}

void
mxfs_oblf_note(
	struct xfs_mount	*mp,
	int			slot,
	int			state,
	uint32_t		victim_node,
	uint64_t		victim_epoch,
	uint32_t		pub_seq,
	uint64_t		ag_mask,
	bool			fswide)
{
	bool			changed = false;
	uint64_t		before, after;
	bool			fsw_before, fsw_after;

	if (slot < 0 || slot >= 64)
		return;
	spin_lock(&mp->m_mxfs_oblf_lock);
	before = mp->m_mxfs_oblf_mask;
	fsw_before = mp->m_mxfs_oblf_fswide;
	switch (state) {
	case MXFS_OBL_OPEN:
		if (mp->m_mxfs_oblf_slot_mask[slot] != ag_mask ||
		    mp->m_mxfs_oblf_slot_fswide[slot] != fswide ||
		    mp->m_mxfs_oblf_slot_epoch[slot] != victim_epoch ||
		    mp->m_mxfs_oblf_slot_seq[slot] != pub_seq) {
			mp->m_mxfs_oblf_slot_mask[slot] = ag_mask;
			mp->m_mxfs_oblf_slot_fswide[slot] = fswide;
			mp->m_mxfs_oblf_slot_epoch[slot] = victim_epoch;
			mp->m_mxfs_oblf_slot_seq[slot] = pub_seq;
			changed = true;
		}
		break;
	case MXFS_OBL_INVALID:
		/* fail closed: the whole filesystem, for this slot */
		if (!mp->m_mxfs_oblf_slot_fswide[slot] ||
		    mp->m_mxfs_oblf_slot_epoch[slot] != victim_epoch) {
			mp->m_mxfs_oblf_slot_mask[slot] = 0;
			mp->m_mxfs_oblf_slot_fswide[slot] = true;
			mp->m_mxfs_oblf_slot_epoch[slot] = victim_epoch;
			mp->m_mxfs_oblf_slot_seq[slot] = 0;
			changed = true;
		}
		break;
	default:	/* MXFS_OBL_NONE */
		if (mp->m_mxfs_oblf_slot_mask[slot] ||
		    mp->m_mxfs_oblf_slot_fswide[slot]) {
			mp->m_mxfs_oblf_slot_mask[slot] = 0;
			mp->m_mxfs_oblf_slot_fswide[slot] = false;
			mp->m_mxfs_oblf_slot_epoch[slot] = 0;
			mp->m_mxfs_oblf_slot_seq[slot] = 0;
			changed = true;
		}
		break;
	}
	if (changed)
		mxfs_oblf_recompute_locked(mp);
	after = mp->m_mxfs_oblf_mask;
	fsw_after = mp->m_mxfs_oblf_fswide;
	spin_unlock(&mp->m_mxfs_oblf_lock);
	if (!changed)
		return;
	mxfs_probe("mxfs: P-OBLF-%s slot=%d victim=%u/%llu seq=%u ag_mask=0x%llx fswide=%d — obligation freeze union 0x%llx/%d -> 0x%llx/%d\n",
		state == MXFS_OBL_OPEN ? "INSTALL" :
		state == MXFS_OBL_INVALID ? "INSTALL-INVALID" : "LIFT",
		slot, victim_node, (unsigned long long)victim_epoch, pub_seq,
		(unsigned long long)ag_mask, fswide ? 1 : 0,
		(unsigned long long)before, fsw_before ? 1 : 0,
		(unsigned long long)after, fsw_after ? 1 : 0);
	wake_up_all(&mp->m_mxfs_oblf_wq);
}

/* the v5 layer's observer (disklock monitor thread / registration scan /
 * the ladder's own publication) — must not sleep on cluster locks */
void
mxfs_dlm_obl_cb(
	void			*data,
	int			slot,
	int			state,
	uint32_t		victim_node,
	uint64_t		victim_epoch,
	uint32_t		pub_seq,
	uint64_t		ag_mask,
	bool			fswide)
{
	mxfs_oblf_note((struct xfs_mount *)data, slot, state, victim_node,
		       victim_epoch, pub_seq, ag_mask, fswide);
}

int
mxfs_ag_dlm_quiesce_wait(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	unsigned int		budget_ms)
{
	unsigned long		deadline = jiffies + msecs_to_jiffies(budget_ms);

	for (;;) {
		bool	busy;

		mxfs_pag_dlm_lock(pag, MXFS_SITE);
		busy = pag->pag_dlm_holders > 0 || pag->pag_dlm_demoting;
		mxfs_pag_dlm_unlock(pag, MXFS_SITE);
		if (!busy)
			return 0;
		if (xfs_is_shutdown(mp))
			return -EIO;
		if (time_after(jiffies, deadline))
			return -ETIMEDOUT;
		msleep(5);
	}
}
