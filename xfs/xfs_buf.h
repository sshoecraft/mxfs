// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_BUF_H__
#define __XFS_BUF_H__

#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/uio.h>
#include <linux/list_lru.h>

extern struct kmem_cache *xfs_buf_cache;

/*
 *	Base types
 */
struct xfs_buf;
struct mxfs_icwr_entry;		/* sess256 step-5 F3: private to xfs_mxfs_dlm.c */

#define XFS_BUF_DADDR_MAX	((xfs_daddr_t) S64_MAX)
#define XFS_BUF_DADDR_NULL	((xfs_daddr_t) (-1LL))

#define XBF_READ	 (1u << 0) /* buffer intended for reading from device */
#define XBF_WRITE	 (1u << 1) /* buffer intended for writing to device */
#define XBF_READ_AHEAD	 (1u << 2) /* asynchronous read-ahead */
#define XBF_ASYNC	 (1u << 4) /* initiator will not wait for completion */
#define XBF_DONE	 (1u << 5) /* all pages in the buffer uptodate */
#define XBF_STALE	 (1u << 6) /* buffer has been staled, do not find it */
#define XBF_WRITE_FAIL	 (1u << 7) /* async writes have failed on this buffer */

/* buffer type flags for write callbacks */
#define _XBF_LOGRECOVERY (1u << 18)/* log recovery buffer */

/* flags used only internally */
#define _XBF_KMEM	 (1u << 21)/* backed by heap memory */
#define _XBF_DELWRI_Q	 (1u << 22)/* buffer on a delwri queue */

/*
 * MXFS v6a phase 1 (v0.3.129, sess31): freshness gate for the
 * cross-node FUA-read mechanism.  Set after a successful
 * mxfs_buf_read_fua() — meaning the buf has been re-read from disk
 * via a FUA-bearing SCSI READ since its last stale event, so the
 * storage stack's per-initiator read cache (LIO target / iSCSI /
 * virtio-scsi) cannot be returning pre-modification content.
 *
 * Cleared in xfs_buf_stale() alongside _XBF_DELWRI_Q, so any stale
 * event (MXFS-driven cache invalidation OR XFS-internal trans
 * binval) re-arms the FUA-read gate.
 *
 * Without this flag, mxfs_buf_needs_fua_read forces FUA on every
 * metadata read while multi-node, eliminating page-cache amortization
 * within a single lock hold.  With it, the FIRST read after stale is
 * FUA (pierces the lower cache); subsequent reads of the same buf
 * while still holding the DLM lock are plain bio (kernel page cache
 * + xfs_buf cache amortize).  Per docs/v6-cache-architecture-proposal.md
 * §11.9 hypothesis H1.
 */
#define _XBF_FUA_FRESH	 (1u << 19)/* MXFS: re-read with FUA since last stale */

/*
 * MXFS sess33 (v0.3.148): set on cluster bufs that have been added to
 * pag_mxfs_alloc_buflist by xfs_ialloc_inode_init.  These bufs hold
 * _XBF_DELWRI_Q from being on mxfs's own delwri queue (drained by
 * mxfs_dlm_ag_drain_alloc_buflist in bast_work_fn Phase 2).  When
 * xfsaild's iop_push tries xfs_buf_delwri_queue on them, it fails
 * (_XBF_DELWRI_Q already set), so xfs_inode_item_push and
 * xfs_buf_item_push return XFS_ITEM_FLUSHING.  Items can't drain via
 * xfsaild — they MUST drain via mxfs's Phase 2 path.
 *
 * xfs_ail_push_ag_sync uses this flag to distinguish "in mxfs's drain
 * path" (skip from Phase 1 wait — Phase 2 will submit) from "in
 * xfsaild's normal path" (must keep waiting).  Without this flag,
 * skipping all _XBF_DELWRI_Q bufs in target AG is too aggressive:
 * regular dir3/agf/agi log bufs that xfsaild manages get skipped too,
 * AG-DLM gets released before xfsaild has flushed them, peer reads
 * stale (sess33 iter 3 corruption signature
 * "xfs_dir3_data_reada_verify").
 *
 * Cleared in xfs_buf_inode_iodone alongside _XBF_DELWRI_Q clearing
 * (after the mxfs Phase 2 drain submits and iodone fires).
 */
#define _XBF_MXFS_ALLOC_QUEUED (1u << 20)

/* flags used only as arguments to access routines */
/*
 * Online fsck is scanning the buffer cache for live buffers.  Do not warn
 * about length mismatches during lookups and do not return stale buffers.
 */
#define XBF_LIVESCAN	 (1u << 28)
#define XBF_INCORE	 (1u << 29)/* lookup only, return if found in cache */
#define XBF_TRYLOCK	 (1u << 30)/* lock requested, but do not wait */


typedef unsigned int xfs_buf_flags_t;

#define XFS_BUF_FLAGS \
	{ XBF_READ,		"READ" }, \
	{ XBF_WRITE,		"WRITE" }, \
	{ XBF_READ_AHEAD,	"READ_AHEAD" }, \
	{ XBF_ASYNC,		"ASYNC" }, \
	{ XBF_DONE,		"DONE" }, \
	{ XBF_STALE,		"STALE" }, \
	{ XBF_WRITE_FAIL,	"WRITE_FAIL" }, \
	{ _XBF_LOGRECOVERY,	"LOG_RECOVERY" }, \
	{ _XBF_FUA_FRESH,	"FUA_FRESH" }, \
	{ _XBF_MXFS_ALLOC_QUEUED, "MXFS_ALLOC_Q" }, \
	{ _XBF_KMEM,		"KMEM" }, \
	{ _XBF_DELWRI_Q,	"DELWRI_Q" }, \
	/* The following interface flags should never be set */ \
	{ XBF_LIVESCAN,		"LIVESCAN" }, \
	{ XBF_INCORE,		"INCORE" }, \
	{ XBF_TRYLOCK,		"TRYLOCK" }

/*
 * Internal state flags.
 */
#define XFS_BSTATE_DISPOSE	 (1 << 0)	/* buffer being discarded */

struct xfs_buf_cache {
	struct rhashtable	bc_hash;
};

int xfs_buf_cache_init(struct xfs_buf_cache *bch);
void xfs_buf_cache_destroy(struct xfs_buf_cache *bch);

/*
 * The xfs_buftarg contains 2 notions of "sector size" -
 *
 * 1) The metadata sector size, which is the minimum unit and
 *    alignment of IO which will be performed by metadata operations.
 * 2) The device logical sector size
 *
 * The first is specified at mkfs time, and is stored on-disk in the
 * superblock's sb_sectsize.
 *
 * The latter is derived from the underlying device, and controls direct IO
 * alignment constraints.
 */
struct xfs_buftarg {
	dev_t			bt_dev;
	struct block_device	*bt_bdev;
	struct dax_device	*bt_daxdev;
	struct file		*bt_file;
	u64			bt_dax_part_off;
	struct xfs_mount	*bt_mount;
	unsigned int		bt_meta_sectorsize;
	size_t			bt_meta_sectormask;
	size_t			bt_logical_sectorsize;
	size_t			bt_logical_sectormask;
	xfs_daddr_t		bt_nr_sectors;
	xfs_daddr_t		bt_sector_offset; /* MXFS envelope offset */

	/* LRU control structures */
	struct shrinker		*bt_shrinker;
	struct list_lru		bt_lru;

	struct percpu_counter	bt_readahead_count;
	struct ratelimit_state	bt_ioerror_rl;

	/* Hardware atomic write unit values, bytes */
	unsigned int		bt_awu_min;
	unsigned int		bt_awu_max;

	/* built-in cache, if we're not using the perag one */
	struct xfs_buf_cache	bt_cache[];
};

struct xfs_buf_map {
	xfs_daddr_t		bm_bn;	/* block number for I/O */
	int			bm_len;	/* size of I/O */
	unsigned int		bm_flags;
};

/*
 * Online fsck is scanning the buffer cache for live buffers.  Do not warn
 * about length mismatches during lookups and do not return stale buffers.
 */
#define XBM_LIVESCAN		(1U << 0)

#define DEFINE_SINGLE_BUF_MAP(map, blkno, numblk) \
	struct xfs_buf_map (map) = { .bm_bn = (blkno), .bm_len = (numblk) };

struct xfs_buf_ops {
	char *name;
	union {
		__be32 magic[2];	/* v4 and v5 on disk magic values */
		__be16 magic16[2];	/* v4 and v5 on disk magic values */
	};
	void (*verify_read)(struct xfs_buf *);
	void (*verify_write)(struct xfs_buf *);
	xfs_failaddr_t (*verify_struct)(struct xfs_buf *bp);
};

/*
 * sess-pve (AGI umount-wedge, RULE-4 instrumentation): per-buffer HOLD/RELE
 * history ring.  The 2/tcp post-fence umount wedges in xfs_buftarg_drain on ONE
 * xfs_agi buffer stuck at b_hold=2 (XBF_ASYNC|XBF_DONE|_XBF_KMEM, no bli, not
 * pinned; NOT the sess75/76 readahead leak — XBF_READ_AHEAD is clear).  Exactly
 * one non-LRU reference leaked.  This ring records the site + caller (_RET_IP_)
 * + resulting b_hold at EVERY b_hold mutation (all of which happen under b_lock,
 * except the single-threaded alloc init — so the ring is written under b_lock,
 * no torn entries), and the P-HOLDRING dump at the drain-stuck site replays it
 * so the leaked reference's acquisition site/caller is named directly.  Toggle
 * with MXFS_HOLD_TRACE; compiles out to nothing when 0.  NOT reset at
 * xfs_buf_stale — a hold leaked across an incarnation boundary must stay
 * visible.
 */
#define MXFS_HOLD_TRACE 1
/* site enum is unconditional so the call sites compile with the toggle at 0 */
enum mxfs_hold_site {
	MXFS_HS_ALLOC = 0,	/* _xfs_buf_alloc: initial b_hold = 1 */
	MXFS_HS_TRYHOLD,	/* xfs_buf_try_hold: rcu cache-hit hold */
	MXFS_HS_HOLD,		/* xfs_buf_hold: explicit external hold */
	MXFS_HS_STALE_LRU,	/* xfs_buf_stale: drop the LRU reference */
	MXFS_HS_RA_ORPHAN,	/* _xfs_buf_read: drop orphaned readahead hold */
	MXFS_HS_RELE_UNCACHED,	/* xfs_buf_rele_uncached */
	MXFS_HS_RELE_CACHED,	/* xfs_buf_rele_cached */
};
#if MXFS_HOLD_TRACE
#define MXFS_HOLD_RING 32
struct mxfs_hold_evt {
	unsigned long	caller;		/* _RET_IP_ of the mutation site */
	u32		flags;		/* b_flags snapshot after the mutation */
	u16		hold_after;	/* b_hold after the mutation */
	u8		site;		/* enum mxfs_hold_site */
	s8		delta;		/* +1 acquire, -1 release */
};
#endif

struct xfs_buf {
	/*
	 * first cacheline holds all the fields needed for an uncontended cache
	 * hit to be fully processed. The semaphore straddles the cacheline
	 * boundary, but the counter and lock sits on the first cacheline,
	 * which is the only bit that is touched if we hit the semaphore
	 * fast-path on locking.
	 */
	struct rhash_head	b_rhash_head;	/* pag buffer hash node */

	xfs_daddr_t		b_rhash_key;	/* buffer cache index */
	int			b_length;	/* size of buffer in BBs */
	unsigned int		b_hold;		/* reference count */
	atomic_t		b_lru_ref;	/* lru reclaim ref count */
	xfs_buf_flags_t		b_flags;	/* status flags */
	struct semaphore	b_sema;		/* semaphore for lockables */

	/*
	 * concurrent access to b_lru and b_lru_flags are protected by
	 * bt_lru_lock and not by b_sema
	 */
	struct list_head	b_lru;		/* lru list */
	spinlock_t		b_lock;		/* internal state lock */
	unsigned int		b_state;	/* internal state flags */
	wait_queue_head_t	b_waiters;	/* unpin waiters */
	struct list_head	b_list;
	struct xfs_perag	*b_pag;
	struct xfs_mount	*b_mount;
	struct xfs_buftarg	*b_target;	/* buffer target (device) */
	void			*b_addr;	/* virtual address of buffer */
	struct work_struct	b_ioend_work;
	struct completion	b_iowait;	/* queue for I/O waiters */
	struct xfs_buf_log_item	*b_log_item;
	struct list_head	b_li_list;	/* Log items list head */
	struct xfs_trans	*b_transp;
	struct xfs_buf_map	*b_maps;	/* compound buffer map */
	struct xfs_buf_map	__b_map;	/* inline compound buffer map */
	int			b_map_count;
	atomic_t		b_pin_count;	/* pin count */
	int			b_error;	/* error code on I/O */
	uint32_t		b_mxfs_dir_gen;	/* sess37: dp->i_dlm_dir_gen stamp at last fresh dir-block read; read-time block-dir coherency */
	uint32_t		b_mxfs_coherent_gen;	/* sess28: dp->i_dlm_dir_gen at last PLATTER-VERIFIED addname coherence check (mxfs_dir_addname_coherent_refresh). Distinct from b_mxfs_dir_gen (stamped on EVERY read, incl stale reads) — only the addname guard sets this, so it dedups the per-addname FUA platter check to ONCE per block per dir_gen (cheap, RULE-0). 0 = never verified -> check. */
	uint32_t		b_mxfs_dir_incarn;	/* sess15: VFS i_generation stamp at last fresh dir-block read/init for the owning dir inode; a cached buffer whose stamp != the reading inode's current i_generation is a PREVIOUS-incarnation ABA alias of a reused inode# at a reused daddr (its in-AIL "undestaged" content belongs to the freed prior incarnation) -> invalidate+re-read even past the dirty/in-AIL guard. 0 = never stamped (treat as needs-fresh-read). */
	uint32_t		b_mxfs_logged_seq;	/* sess35 run14d: bumped at every xfs_trans_log_buf; node-LOCAL modification counter */
	uint32_t		b_mxfs_written_seq;	/* sess35 run14d: snapshot of b_mxfs_logged_seq at write submit; logged != written => committed-unwritten LOCAL mods (cross-node-safe destage test — payload LSNs are stamped by whichever node last wrote the block, so LSN compares across journals are meaningless) */
	u64			b_mxfs_wr_flush_epoch;	/* sess6 (ccloop 46efd8b6): mount m_mxfs_flush_epoch snapshot at this buffer's last successful WRITE completion.  == current epoch => no device flush since this content was written => the platter may be BEHIND this buffer (target write cache) => never regress it from a platter/FUA read (xfs_iread_bmbt_block P34B guard).  0 = never written by this node (mount epoch starts at 1). */
	u64			b_mxfs_ag_gen;	/* sess40: pag->pag_dlm_meta_gen stamp at last fresh AG-meta read; read-time AG free-space coherency (anti double-alloc) */
	u64			b_tenure_id;	/* sess123: pag->ag_dlm_tenure_id stamp at last AG-meta read under the current AG-DLM hold; == current => this-node-authoritative, NEVER discard mid-tenure (replaces failed gen/LSN preserve-vs-discard heuristics for the AGI unlinked-list lost-update) */
	uint32_t		b_mxfs_grant_gen;	/* sess10(ccloop): owning dir inode's i_dlm_cached_grant_gen (acked-TCP per-grant token) at last COHERENT read of this dir block. GPT-5.5 design: freshness must mean "read under the CURRENT grant", NOT the lossy i_dlm_dir_gen (stamped fresh over stale content -> the 4/tcp dir_reuse stale_base=0 durable clobber). An EX RMW whose target block's b_mxfs_grant_gen != the inode's current grant gen was last read under an OLDER grant (we lost+reacquired EX since = a peer modified) -> re-read before the RMW. 0 = never stamped. */
	uint32_t		b_mxfs_dir_epoch;	/* sess16(ccloop) GPT-5.5 tenure model: owning dir inode's i_dlm_dir_valid_epoch (reliable level-triggered cross-node handoff epoch) at last COHERENT read of this dir block. If b_mxfs_dir_epoch < dp->i_dlm_dir_valid_epoch, this block was read under an EARLIER tenure than the inode now knows coherent (a peer was granted + modified the LUN since) -> the cached payload is a STALE RMW base -> re-read before use, OVERRIDING the payload-LSN undestaged keep-guard (epoch only advances after WE released EX, whose work Invariant-1 drained durable -> nothing un-drained to resurrect). 0 = never handed off (single-node / never-BAST'd) -> never stale. */
	u64			b_mxfs_idirty_mask;	/* sess27: PERSISTENT per-sector mask of inode-cluster sectors THIS node has logged (modified) in this buffer incarnation. mxfs_submit_partial_inode_write accumulates currently-logged sectors here and writes the UNION, so a freshly-allocated inode whose log item already detached (but whose sector was never whole-written) is still written -> fixes the dir_reuse durable inode-alloc REVERT. A peer inode this node only READ is never logged -> never in the mask -> never written -> false-sharing still protected. Cleared on xfs_buf_stale (buffer invalidation/reuse) so an ABA-reused buffer does not carry a stale mask. */
	bool			b_mxfs_dir_wr_counted;	/* sess40 (ccloop, GPT-5.5 writeback-completion-barrier): this dir DATA/leaf write bio was counted into mp->m_mxfs_dir_wr_inflight at submit; the matching __xfs_buf_ioend decrements + wakes exactly once.  The dir EX release fence waits for the counter to reach 0 so NO prior-tenure stale dir-block write can land after the next holder begins (root of dir_reuse readdir=799 single-dirent durable loss). */
	bool			b_mxfs_iclus_wr_counted;	/* sess256 step-5 F3: this inode-cluster (xfs_inode_buf_ops) home write was counted into its keyed mxfs_icwr_entry (+ the telemetry mirror) at submit; the matching __xfs_buf_ioend write-branch completion — placed AFTER the error/resubmit decision, so a resubmit KEEPS the single token with no transient zero — decrements + bumps complete_gen + wakes exactly once. */
	struct mxfs_icwr_entry	*b_mxfs_icwr_ent;	/* keyed registry entry this buffer's counted write belongs to; paired with b_mxfs_iclus_wr_counted at the same submit (entries are never freed until unmount, so the pointer cannot dangle). */
	bool			b_mxfs_fence_skipped;	/* ccloop c7ee71c6 sess7 (FENCE-V1): the P123 dir-block write fence SUPPRESSED this buffer's most recent write submission (sub-EX, no log obligation): the "success" completion the submitter saw put NOTHING on the LUN.  Consumed by mxfs_dir_flush_one_daddr's werr==0 postlude to skip the raw SCSI FUA re-publish (mxfs_dir_release_fua_write), which would otherwise bypass the fence and land the suppressed stale bytes on the platter anyway (the run-185647Z leaf1@PR regression).  Set in the fence's suppress arm; cleared whenever a dir-block write passes the fence (both under b_sema at submit). */
	uint32_t		b_mxfs_dir_wrcnt_max;	/* sess40 (ccloop) COUNT-REGRESSION detector: high-water mark of the active-dirent count this dir DATA/block buffer has ever WRITTEN.  A subsequent write with a LOWER count (without a matching in-txn remove) = this node RMW'd a stale base that lost entries it previously held = the silent dir_reuse readdir=799 lost-update that dataclobber's disk-superset compare MISSES (disk also lacked the entry at submit).  Logged as P-COUNTREGRESS at xfs_buf_submit_bio; reset to 0 on xfs_buf_stale (buffer reuse). */
	uint32_t		b_mxfs_relepoch;	/* sess50 (ccloop) PROVEN dir_reuse cross-node clobber fix: owning dir inode's i_dlm_epoch (RELIABLE LOCAL release counter — bumped on EVERY grant loss/stale, xfs_mxfs_dlm.c:9327 et al; immune to the unreliable grant_gen/i_mxfs_ex_grant_seq handoff-underfire) at the last time THIS node read/modified this dir DATA/leaf block coherently.  If at writeback b_mxfs_relepoch != 0 && < ip->i_dlm_epoch, this node RELEASED the dir grant since this image was coherent -> a peer may have superseded the block on the shared LUN (PROVEN: xnode=1, disk_cnt=buf_cnt+1, peer wrote the extra dirent) -> xfsaild flushing this stale image durably REVERTS the peer's add (the readdir=799 single-dirent loss).  Skip the reflush (buffer is CLEAN = already-durable from the release drain, so nothing is lost) and re-read.  0 = never stamped (fresh) -> never skipped. */
	bool			b_mxfs_inplace_read;	/* v0.10.32 (sess7 46efd8b6): this READ is being completed IN PLACE from the in-core image (no DMA) — set by the P91-FUA-SKIP-LOGGED guard just before its emulated xfs_buf_ioend.  __xfs_buf_ioend consumes it and SKIPS verify_read: the in-core image of a logged buffer is authoritative by definition, but its embedded CRC is only stamped at write submit, so CRC-verifying a modified-since-last-write image manufactures EFSBADCRC out of thin air (run 154203Z test1: every read of its own dirty bmbt leaf returned "Metadata CRC error" with the LUN fully valid -> 40 min of ENOENT; same family as the sess15 P15I inobt corpse). */
	bool			b_mxfs_stale_pending;	/* sess5(ccloop): the acquire-side dir reload (mxfs_dlm_reload_inode) wanted to STALE this cached dir block (fresh peer EX grant → its content is a prior-tenure base a peer superseded) but could not xfs_buf_trylock it (in-flight writeback / held).  Set under b_lock; the next xfs_da_read_buf of this dir DATA block force-invalidates (clears XBF_DONE) so the addname RMW cold-reads the peer's coherent image instead of the stale cached base (the dir_reuse readdir-undercount lost-update: acquire-reload locked_skip=1 left a stale block that addname RMW'd → 100 dirents clobbered).  Cleared on the forced re-read and on xfs_buf_stale (incarnation end).  Loss-safe: only set at a fresh acquire where Invariant-1 drained our own work durable, so the block is destaged and re-reading disk loses nothing. */
	uint8_t			b_mxfs_ioend_seen;	/* sess6 DIAG: count of completions (xfs_buf_ioend + xfs_buf_bio_end_io) that ran for this buffer incarnation (reset at xfs_buf_stale). */
	uint8_t			b_mxfs_relse_seen;	/* sess6 DIAG: count of completions that took the ASYNC (relse/queue_work) branch — a nonzero value on a stuck sync waiter = the wrongful-relse lost-wakeup. */
	uint8_t			b_mxfs_evi;		/* sess9 (ccloop a864) DIAG: next slot in b_mxfs_evring (free-running, slot = evi & 7). */
	uint64_t		b_mxfs_evring[8];	/* sess9 (ccloop a864) DIAG for the residual wedge#2 lost-wakeup: ring of the last 8 buffer lifecycle events (submit-snapshot / bio-issue / bio-end / ioend / worker / handle-error / resubmit / iowait-wake), each packing type|b_flags|sync_wait|force_sync|pid|~1ms-timestamp — see mxfs_buf_ev() in pal/linux/xfs_buf.c.  Dumped by the P-IOWAIT-STUCK probe so a stuck sync waiter names the EXACT ordered completion history (which submit reset the sync_wait snapshot, which path relse'd).  Diagnostic only; lock-free stores, races tolerated. */
	bool			b_mxfs_force_sync;	/* sess8 (ccloop a864): caller-side (xfs_bwrite / _xfs_buf_read / handle_error resubmit) latch of "this submission is synchronous", set under b_sema BEFORE xfs_buf_submit and consumed (cleared) at submit entry.  ORed with !(b_flags & XBF_ASYNC) there to decide sync-vs-async intent for THIS submission. */
	void			*b_mxfs_rd_preserve;	/* sess7 (ccloop 8ba7ae5c) READ-SIDE inode-cluster false-sharing fix (PROVEN iter_14 lost-final-shrink): snapshot of b_addr taken just before a cold DMA READ of an inode-cluster buffer that has inode log items attached (b_li_list non-empty = committed local state whose last iflush copy-in lives in this buffer).  The DMA brings peer-fresh platter bytes for the OTHER slots; at read completion the attached slots are restored from this snapshot (their platter image is never newer than the local one for an inode we may log), so the read can no longer clobber a just-iflushed image and let the delwri write push the pre-shrink platter bytes back (the AG22/295 dangling-extent double-alloc).  kmalloc'd; freed at completion / buffer free.  NULL = nothing preserved. */
	unsigned long		b_mxfs_freeflag;	/* ccloop 72513a13: bit 0 set atomically by the FIRST xfs_buf_free; a second free trips a P-BUF-DOUBLEFREE alert+stack and becomes a no-op instead of a double call_rcu (test25 panic 2026-07-18: BUG mm/slub.c:553 double-free in xfs_buf_free_callback, plus the RCU-list corruption that later fired a callback into unloaded module text).  Object is zalloc'd, so legit slab reuse starts clear. */
	uint64_t		b_mxfs_alloc_gen;	/* ccloop 72513a13 sess2: allocation generation (global monotonic, stamped in _xfs_buf_alloc).  An inode log item records the gen of the buffer it attaches to (ili_mxfs_buf_gen); a mismatch at push/drain time proves li_buf points at a RECYCLED allocation (premature free of the attached buffer — the dir_reuse@32 P113 wedge: dirty ILI in AIL, li_buf set, b_li_list empty, iflush_cluster -EAGAIN forever). */
	u64			b_mxfs_rd_preserve_mask;	/* bit i = inode slot i of this cluster is restored from b_mxfs_rd_preserve at read completion. */
	atomic_t		b_mxfs_sync_waiters;
	/*
	 * sess227 F4 obligation registry (D-FOREIGN-REPLAY-UNGATED-IMAGES
	 * hard-barrier F4: dir-class committed-never-submitted).  All four
	 * fields are written only under b_sema (commit hold / submit hold /
	 * completion owns the buffer).  A NONZERO b_mxfs_f4_committed_gen >
	 * b_mxfs_f4_submit_gen means a committed dir-class modification has
	 * never been pushed into a write submission: the release barrier
	 * must not let the DLM grant cross nodes until it retires.  Own u64
	 * generation, NOT b_mxfs_logged_seq — logged_seq is a log-call
	 * counter and XFS_BLI_ORDERED buffers dirty without advancing it
	 * (sess227 GPT ruling item 2).  submit copies committed at bio
	 * submit; retire at successful non-suppressed write completion with
	 * submit_gen >= committed_gen.
	 */
	u64			b_mxfs_f4_committed_gen;
	u64			b_mxfs_f4_submit_gen;
	u64			b_mxfs_f4_owner;	/* owner ino decoded from v5 hdr at open; 0 = unknown (poison bucket) */
	void			*b_mxfs_f4_rec;		/* struct mxfs_f4_record * while an obligation is open, else NULL */	/* ccloop3e02 sess2 ROOT FIX for dir_reuse@32/caw wedge#2a residual (lost b_iowait wakeup + the double-relse it causes): PROVEN via live /proc/kcore inspection (b_sema.count read 83 on a live-wedged buffer, vs the correct 0/1) that the sess6/8/9 fixes' shared per-buffer bool (b_mxfs_sync_wait) lets an UNRELATED concurrent submitter (xfsaild's async delwri push racing mxfs_dir_data_owner_scan's synchronous durable flush on the SAME xfs_buf — the buffer lock no longer excludes this once b_sema.count has already drifted off 0/1 from an EARLIER occurrence of this exact bug) overwrite the flag between the sync submitter's snapshot and its own completion, so the sync waiter's wakeup is silently lost AND both completions take the async/relse branch (a double xfs_buf_relse -> the very b_sema leak that lets the NEXT occurrence race even more easily -- self-reinforcing, hence "residual"/non-deterministic across many prior fix attempts).  Fix: an ADDITIVE atomic credit incremented once per truly-synchronous xfs_buf_submit, consumed by exactly one completion event via mxfs_buf_completion_wake_sync() (atomic_add_unless -1/0) regardless of which bio's completion runs first or how many unrelated submissions race on this buffer; a completion that finds no credit falls back to the pre-existing flags-based (XBF_ASYNC) relse/complete decision, so the normal single-submitter case is unchanged.  0 = no sync waiter currently registered. */
	void			(*b_iodone)(struct xfs_buf *bp);

	/*
	 * sess-pve (AGI umount-wedge fix): one-shot ownership token for the
	 * extra reference mxfs_ag_meta_track takes on an AG-meta buffer.
	 * 1 = a track hold is outstanding for the current dirty epoch.
	 * Consumed (cmpxchg 1->0) by EXACTLY ONE of mxfs_dlm_ag_meta_iodone
	 * (normal writeback) or mxfs_ag_meta_reclaim_abort (shutdown/abort
	 * detach with no writeback), which then drops the hold + decrements
	 * pag_dlm_meta_pending.  Without it the abort path leaked the hold,
	 * pinning agi/inobt/finobt at b_hold=2 -> xfs_buftarg_drain wedge.
	 * 0 at alloc (zalloc).
	 */
	atomic_t		b_mxfs_agmeta_hold;

	/*
	 * sess338 D-FOREIGN-SHADOW-UNWIND-HOST-SHUTDOWN-513B: this buffer's
	 * pending write carries FOREIGN-slice journal-recovery state — it was
	 * queued by pass-2 replay of a DEAD PEER's log slice through a shadow
	 * xlog whose l_mp is THIS SURVIVOR's live mount.  A write failure on
	 * it must fail the foreign replay, never the survivor: every
	 * b_mount-shutdown arm (xfs_buf_ioend_handle_error's _XBF_LOGRECOVERY
	 * one-strike + permanent-error shutdowns, xfs_bwrite's error
	 * shutdown) is skipped for it and the error propagates to the
	 * recovery waiter instead.  Deliberately a bool, NOT a b_flags bit
	 * (sess337 GPT ruling).  Set at every pass-2 delwri-queue/bwrite site
	 * under the buffer lock, ONLY when xlog_is_mxfs_foreign_replay();
	 * cleared at every I/O completion in __xfs_buf_ioend alongside the
	 * _XBF_LOGRECOVERY clear so it can never leak into live-mount I/O of
	 * the same cached buffer.  Adopted-slice (mount-time) recovery keeps
	 * upstream shutdown behavior — there the log IS the mounting fs's own
	 * log and the shutdown is correct containment.
	 */
	bool			b_mxfs_foreign_recovery;

	/*
	 * async write failure retry count. Initialised to zero on the first
	 * failure, then when it exceeds the maximum configured without a
	 * success the write is considered to be failed permanently and the
	 * iodone handler will take appropriate action.
	 *
	 * For retry timeouts, we record the jiffy of the first failure. This
	 * means that we can change the retry timeout for buffers already under
	 * I/O and thus avoid getting stuck in a retry loop with a long timeout.
	 *
	 * last_error is used to ensure that we are getting repeated errors, not
	 * different errors. e.g. a block device might change ENOSPC to EIO when
	 * a failure timeout occurs, so we want to re-initialise the error
	 * retry behaviour appropriately when that happens.
	 */
	int			b_retries;
	unsigned long		b_first_retry_time; /* in jiffies */
	int			b_last_error;

	/*
	 * sess113 lock-holder tracking (Gemini RULE-5 instrumentation): the
	 * return address of whoever currently holds b_sema, set in
	 * xfs_buf_lock/xfs_buf_trylock and cleared in xfs_buf_unlock.  The
	 * cache_coherency drain wedge is a cluster buffer left LOCKED with no
	 * live holder thread (an abandoned flush); printing b_lock_ip from the
	 * drain probe names the exact caller that locked it and never relse'd.
	 */
	void			*b_lock_ip;

#if MXFS_HOLD_TRACE
	/* sess-pve AGI umount-wedge hold/rele history — see MXFS_HOLD_TRACE above */
	struct mxfs_hold_evt	b_mxfs_hold_ring[MXFS_HOLD_RING];
	u16			b_mxfs_hri;		/* free-running write cursor */
	u8			b_mxfs_hr_dumped;	/* P-HOLDRING dump-once guard */
#endif

	const struct xfs_buf_ops	*b_ops;
	struct rcu_head		b_rcu;
};

/* Finding and Reading Buffers */
int xfs_buf_get_map(struct xfs_buftarg *target, struct xfs_buf_map *map,
		int nmaps, xfs_buf_flags_t flags, struct xfs_buf **bpp);
int xfs_buf_read_map(struct xfs_buftarg *target, struct xfs_buf_map *map,
		int nmaps, xfs_buf_flags_t flags, struct xfs_buf **bpp,
		const struct xfs_buf_ops *ops, xfs_failaddr_t fa);
void xfs_buf_readahead_map(struct xfs_buftarg *target,
			       struct xfs_buf_map *map, int nmaps,
			       const struct xfs_buf_ops *ops);

static inline int
xfs_buf_incore(
	struct xfs_buftarg	*target,
	xfs_daddr_t		blkno,
	size_t			numblks,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);

	return xfs_buf_get_map(target, &map, 1, XBF_INCORE | flags, bpp);
}

static inline int
xfs_buf_get(
	struct xfs_buftarg	*target,
	xfs_daddr_t		blkno,
	size_t			numblks,
	struct xfs_buf		**bpp)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);

	return xfs_buf_get_map(target, &map, 1, 0, bpp);
}

static inline int
xfs_buf_read(
	struct xfs_buftarg	*target,
	xfs_daddr_t		blkno,
	size_t			numblks,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp,
	const struct xfs_buf_ops *ops)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);

	return xfs_buf_read_map(target, &map, 1, flags, bpp, ops,
			__builtin_return_address(0));
}

static inline void
xfs_buf_readahead(
	struct xfs_buftarg	*target,
	xfs_daddr_t		blkno,
	size_t			numblks,
	const struct xfs_buf_ops *ops)
{
	DEFINE_SINGLE_BUF_MAP(map, blkno, numblks);
	return xfs_buf_readahead_map(target, &map, 1, ops);
}

int xfs_buf_get_uncached(struct xfs_buftarg *target, size_t numblks,
		struct xfs_buf **bpp);
int xfs_buf_read_uncached(struct xfs_buftarg *target, xfs_daddr_t daddr,
		size_t numblks, struct xfs_buf **bpp,
		const struct xfs_buf_ops *ops);
int _xfs_buf_read(struct xfs_buf *bp);
void xfs_buf_hold(struct xfs_buf *bp);

/* Releasing Buffers */
extern void xfs_buf_rele(struct xfs_buf *);

/* Locking and Unlocking Buffers */
extern int xfs_buf_trylock(struct xfs_buf *);
extern void xfs_buf_lock(struct xfs_buf *);
extern void xfs_buf_unlock(struct xfs_buf *);
#define xfs_buf_islocked(bp) \
	((bp)->b_sema.count <= 0)

static inline void xfs_buf_relse(struct xfs_buf *bp)
{
	xfs_buf_unlock(bp);
	xfs_buf_rele(bp);
}

/* Buffer Read and Write Routines */
extern int xfs_bwrite(struct xfs_buf *bp);

extern void __xfs_buf_ioerror(struct xfs_buf *bp, int error,
		xfs_failaddr_t failaddr);
#define xfs_buf_ioerror(bp, err) __xfs_buf_ioerror((bp), (err), __this_address)
extern void xfs_buf_ioerror_alert(struct xfs_buf *bp, xfs_failaddr_t fa);
void xfs_buf_ioend_fail(struct xfs_buf *);
void __xfs_buf_mark_corrupt(struct xfs_buf *bp, xfs_failaddr_t fa);
#define xfs_buf_mark_corrupt(bp) __xfs_buf_mark_corrupt((bp), __this_address)

/* Buffer Utility Routines */
static inline void *xfs_buf_offset(struct xfs_buf *bp, size_t offset)
{
	return bp->b_addr + offset;
}

static inline void xfs_buf_zero(struct xfs_buf *bp, size_t boff, size_t bsize)
{
	memset(bp->b_addr + boff, 0, bsize);
}

extern void xfs_buf_stale(struct xfs_buf *bp);

/* Delayed Write Buffer Routines */
extern void xfs_buf_delwri_cancel(struct list_head *);
extern bool xfs_buf_delwri_queue(struct xfs_buf *, struct list_head *);
int xfs_buf_delwri_queue_recovery(struct xfs_buf *bp,
		struct list_head *buffer_list, bool foreign);
void xfs_buf_delwri_queue_here(struct xfs_buf *bp, struct list_head *bl);
extern int xfs_buf_delwri_submit(struct list_head *);
int xfs_buf_delwri_fail(struct list_head *, int);
extern int xfs_buf_delwri_submit_nowait(struct list_head *);
extern int xfs_buf_delwri_submit_nopinwait(struct xfs_mount *,
					   struct list_head *);

static inline xfs_daddr_t xfs_buf_daddr(struct xfs_buf *bp)
{
	return bp->b_maps[0].bm_bn;
}

void xfs_buf_set_ref(struct xfs_buf *bp, int lru_ref);

/*
 * If the buffer is already on the LRU, do nothing. Otherwise set the buffer
 * up with a reference count of 0 so it will be tossed from the cache when
 * released.
 */
static inline void xfs_buf_oneshot(struct xfs_buf *bp)
{
	if (!list_empty(&bp->b_lru) || atomic_read(&bp->b_lru_ref) > 1)
		return;
	atomic_set(&bp->b_lru_ref, 0);
}

static inline int xfs_buf_ispinned(struct xfs_buf *bp)
{
	return atomic_read(&bp->b_pin_count);
}

static inline int
xfs_buf_verify_cksum(struct xfs_buf *bp, unsigned long cksum_offset)
{
	return xfs_verify_cksum(bp->b_addr, BBTOB(bp->b_length),
				cksum_offset);
}

static inline void
xfs_buf_update_cksum(struct xfs_buf *bp, unsigned long cksum_offset)
{
	xfs_update_cksum(bp->b_addr, BBTOB(bp->b_length),
			 cksum_offset);
}

/*
 *	Handling of buftargs.
 */
struct xfs_buftarg *xfs_alloc_buftarg(struct xfs_mount *mp,
		struct file *bdev_file);
extern void xfs_free_buftarg(struct xfs_buftarg *);
extern void xfs_buftarg_wait(struct xfs_buftarg *);
extern void xfs_buftarg_drain(struct xfs_buftarg *);
int xfs_configure_buftarg(struct xfs_buftarg *btp, unsigned int sectorsize,
		xfs_fsblock_t nr_blocks);

#define xfs_readonly_buftarg(buftarg)	bdev_read_only((buftarg)->bt_bdev)

int xfs_buf_reverify(struct xfs_buf *bp, const struct xfs_buf_ops *ops);
bool xfs_verify_magic(struct xfs_buf *bp, __be32 dmagic);
bool xfs_verify_magic16(struct xfs_buf *bp, __be16 dmagic);

/* for xfs_buf_mem.c only: */
int xfs_init_buftarg(struct xfs_buftarg *btp, size_t logical_sectorsize,
		const char *descr);
void xfs_destroy_buftarg(struct xfs_buftarg *btp);

#endif	/* __XFS_BUF_H__ */
