// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__XFS_BUF_ITEM_H__
#define	__XFS_BUF_ITEM_H__

/* kernel only definitions */

struct xfs_buf;
struct xfs_mount;

/* buf log item flags */
#define	XFS_BLI_HOLD		(1u << 0)
#define	XFS_BLI_DIRTY		(1u << 1)
#define	XFS_BLI_STALE		(1u << 2)
#define	XFS_BLI_LOGGED		(1u << 3)
#define	XFS_BLI_INODE_ALLOC_BUF	(1u << 4)
#define XFS_BLI_STALE_INODE	(1u << 5)
#define	XFS_BLI_INODE_BUF	(1u << 6)
#define	XFS_BLI_ORDERED		(1u << 7)
/*
 * MXFS multi-node: this AG-metadata buffer has been registered for
 * deferred-DLM-release tracking in the current dirty epoch (see
 * mxfs_ag_meta_track).  Set on the first xfs_trans_log_buf call to
 * deduplicate further log_buf calls within the same epoch.  The bli
 * (and therefore this flag) is freed by xfs_buf_item_done after
 * writeback completion; the next dirty epoch starts with a fresh bli.
 */
#define XFS_BLI_MXFS_AGMETA_TRACKED (1u << 8)

#define XFS_BLI_FLAGS \
	{ XFS_BLI_HOLD,		"HOLD" }, \
	{ XFS_BLI_DIRTY,	"DIRTY" }, \
	{ XFS_BLI_STALE,	"STALE" }, \
	{ XFS_BLI_LOGGED,	"LOGGED" }, \
	{ XFS_BLI_INODE_ALLOC_BUF, "INODE_ALLOC" }, \
	{ XFS_BLI_STALE_INODE,	"STALE_INODE" }, \
	{ XFS_BLI_INODE_BUF,	"INODE_BUF" }, \
	{ XFS_BLI_ORDERED,	"ORDERED" }, \
	{ XFS_BLI_MXFS_AGMETA_TRACKED, "MXFS_AGMETA" }

/*
 * ─── MXFS AUTHORITY PROOF SIDECAR (sess103, step 5.3, ruling P0/P1) ───
 *
 * D-FOREIGN-REPLAY-UNGATED-IMAGES needs every logged metadata image to carry
 * proof of the grant that authorized the MUTATION.  Until 0.11.435 that proof
 * was looked up in xfs_buf_item_format_segment, at CIL format time, and the
 * sess102 design-consult ruling declared that UNSOUND (release blocker P0):
 *
 *     modify under epoch E1 -> release E1 -> reacquire under E2
 *                           -> the formatter stamps E2
 *
 * The emitted token would then name a tenure that did not authorize the
 * change, which is a false APPLY waiting for the gate to trust it.  The
 * symmetric error is just as bad: authority released AFTER a perfectly
 * authorized mutation reads as "no authority" at format time.  Format-time
 * state can classify NEITHER case, so it may not be the source.
 *
 * The proof is therefore captured at the FIRST PROTECTED DIRTYING of the
 * buffer in a transaction (xfs_trans_dirty_buf — the single seam every
 * buffer passes through to become dirty, where the transaction necessarily
 * still holds the authorizing tenure), stored here, and merely SERIALIZED by
 * the formatter.  Ruling invariants this structure exists to enforce:
 *
 *  - the proof is IMMUTABLE after the first protected dirtying;
 *  - re-logging the same buffer inside one transaction must resolve to the
 *    same authority object AND epoch — a difference is recorded, never
 *    silently overwritten, and downgrades the image to MIXED;
 *  - authority cannot be released before the transaction captured the proof;
 *  - one buffer carrying changes authorized by DIFFERENT objects cannot be
 *    represented by a single whole-buffer token.
 */
struct mxfs_bli_auth {
	uint64_t	mba_capseq;	/* window key (t_mxfs_capseq); 0 = none */
	uint64_t	mba_owner_ino;	/* derived owning inode, 0 if not inode-owned */
	uint64_t	mba_resource;	/* class-dependent resource id */
	uint64_t	mba_epoch;	/* durable grant epoch that authorized it */
	uint64_t	mba_lineage;	/* resource lineage of the authorizing
					 * binding; 0 = pre-lineage grant */
	uint64_t	mba_auth_gen;	/* i_mxfs_auth_gen at capture (inode arm) */
	uint16_t	mba_class;	/* MXFS_AUTH_CLASS_* */
	uint16_t	mba_blft;	/* BLFT seen at capture (format re-checks) */
	uint8_t		mba_status;	/* MXFS_AUTH_ST_* */
	uint8_t		mba_outcome;	/* MXFS_OWNAUTH_* diagnostic bucket */
	uint8_t		mba_dlm_mode;	/* i_dlm_mode at capture (inode arm) */
	uint8_t		mba_retype_pending;	/* sess445 D-0512: the BLFT changed
					 * after capture in this window and the
					 * proof has not been re-established under
					 * the new type; serialize voids while set */
};

/*
 * This is the in core log item structure used to track information
 * needed to log buffers.  It tracks how many times the lock has been
 * locked, and which 128 byte chunks of the buffer are dirty.
 */
struct xfs_buf_log_item {
	struct xfs_log_item	bli_item;	/* common item structure */
	struct xfs_buf		*bli_buf;	/* real buffer pointer */
	unsigned int		bli_flags;	/* misc flags */
	unsigned int		bli_recur;	/* lock recursion count */
	atomic_t		bli_refcount;	/* cnt of tp refs */
	int			bli_format_count;	/* count of headers */
	struct xfs_buf_log_format *bli_formats;	/* array of in-log header ptrs */
	struct mxfs_bli_auth	bli_mxfs_auth;	/* captured at first dirty */
	/*
	 * xfsaild authority refusal accounting (D-0487).  A dirty AG-metadata
	 * or released-directory bmbt image that this node no longer holds the
	 * grant for cannot be written (it would revert a peer) and cannot be
	 * dropped (it is a committed change); the push refuses it and these
	 * fields say for how long and how often, per item, so the terminal
	 * report names the item rather than a count.  Zero = never refused.
	 * bli_mxfs_refuse_first is jiffies|1 so it is never zero once set;
	 * bli_mxfs_refuse_lsn is li_lsn at the first refusal, so a re-log of
	 * a refused item is visible instead of silently restarting the clock.
	 */
	unsigned long		bli_mxfs_refuse_first;
	unsigned int		bli_mxfs_refuse_count;
	unsigned int		bli_mxfs_refuse_reported;
	xfs_lsn_t		bli_mxfs_refuse_lsn;
	struct xfs_buf_log_format __bli_format;	/* embedded in-log header */
};

/* D-0487: the mount-level fail-stop for a refused item that never clears */
struct work_struct;
void	mxfs_ailpin_work_fn(struct work_struct *work);
/* module parameters: the grace before the fail-stop, the age a cleared
 * refusal is reported at (pal/linux/xfs_buf_item.c) */
extern unsigned int mxfs_ailpin_grace_ms;
extern unsigned int mxfs_ailpin_clear_report_ms;

/*
 * Capture the authority proof for this buffer in this transaction's window.
 * Idempotent within a window; called from xfs_trans_dirty_buf only.
 */
struct xfs_trans;
void	mxfs_bli_auth_capture(struct xfs_trans *tp, struct xfs_buf *bp);
/* sess476: negative-arm forge of a CANCEL record's captured proof */
void	mxfs_dbg_cancel_token_forge_apply(struct xfs_buf *bp);
void	mxfs_bli_auth_note_retype(struct xfs_trans *tp, struct xfs_buf *bp,
				  uint16_t new_blft);

/*
 * Whether the caller retiring a buf log item is the I/O-completion
 * continuation that will go on to run bp->b_iodone.
 *
 * This is the ONLY thing that may excuse a retirement from consuming the
 * MXFS AG-metadata tracking token, and it is a property of the CALLER, not
 * of the buffer: the token is dropped either by the write completion
 * (mxfs_dlm_ag_meta_iodone, installed as b_iodone) or by
 * mxfs_ag_meta_reclaim, and exactly one of them must run.  It cannot be
 * inferred inside the retirement path — not from the return address (every
 * caller reaches the funnel through xfs_buf_item_done, so they all look
 * alike), not from XBF_WRITE (xfs_buf_ioend_fail_unsubmitted submits no
 * write and still runs the completion), and not from a sticky field on the
 * buffer (it can be stale or absent).  So the dispatcher states it.
 *
 * MXFS retires buf log items from about a dozen overlay sites that perform
 * no I/O at all — the release-drain and acquire-evict "retire the zombie
 * BLI" arms.  Those must reclaim; only the real completion may defer.
 */
enum xfs_bli_release_ctx {
	XFS_BLI_NO_IODONE,		/* nothing will run b_iodone: reclaim */
	XFS_BLI_IODONE_FOLLOWS,		/* __xfs_buf_ioend runs b_iodone next */
};

int	xfs_buf_item_init(struct xfs_buf *, struct xfs_mount *);
void	xfs_buf_item_done(struct xfs_buf *bp, enum xfs_bli_release_ctx ctx);
void	xfs_buf_item_put(struct xfs_buf_log_item *bip);
void	xfs_buf_item_log(struct xfs_buf_log_item *, uint, uint);
bool	xfs_buf_item_dirty_format(struct xfs_buf_log_item *);
void	xfs_buf_inode_iodone(struct xfs_buf *);
#ifdef CONFIG_XFS_QUOTA
void	xfs_buf_dquot_iodone(struct xfs_buf *);
#else
static inline void xfs_buf_dquot_iodone(struct xfs_buf *bp)
{
}
#endif /* CONFIG_XFS_QUOTA */
void	xfs_buf_iodone(struct xfs_buf *);
bool	xfs_buf_log_check_iovec(struct kvec *iovec);

unsigned int xfs_buf_inval_log_space(unsigned int map_count,
		unsigned int blocksize);

extern struct kmem_cache	*xfs_buf_item_cache;

#endif	/* __XFS_BUF_ITEM_H__ */
