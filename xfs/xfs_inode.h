// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__XFS_INODE_H__
#define	__XFS_INODE_H__

#include "xfs_inode_buf.h"
#include "xfs_inode_fork.h"
#include "xfs_inode_util.h"

/*
 * Kernel only inode definitions
 */
struct xfs_dinode;
struct xfs_inode;
struct xfs_buf;
struct xfs_bmbt_irec;
struct xfs_inode_log_item;
struct xfs_mount;
struct xfs_trans;
struct xfs_dquot;

/* MXFS DLM lock cache states */
#define MXFS_DLM_ISTATE_NONE		0	/* no cached DLM lock */
#define MXFS_DLM_ISTATE_CACHED		1	/* DLM lock held, no BAST */
#define MXFS_DLM_ISTATE_BAST		2	/* DLM lock held, BAST pending (deferred) */
#define MXFS_DLM_ISTATE_DEMOTING	3	/* flushing/invalidating for BAST release */
#define MXFS_DLM_ISTATE_ACQUIRING	4	/* NEWARCH Phase 1.3
						 * (Gemini chokepoint design):
						 * slow-path caw_lock in flight
						 * on this node.  Blocks
						 * concurrent same-node fast-
						 * path acquires (they wait on
						 * i_dlm_wait); BAST arrivals
						 * are deferred via i_dlm_stale
						 * (do NOT queue bast_process —
						 * that would strip the slot
						 * out from under caw_lock); on
						 * caw_lock return, transitions
						 * to CACHED (or BAST if a peer
						 * BAST arrived while we were
						 * acquiring). */

typedef struct xfs_inode {
	/* Inode linking and identification information. */
	struct xfs_mount	*i_mount;	/* fs mount struct ptr */
	struct xfs_dquot	*i_udquot;	/* user dquot */
	struct xfs_dquot	*i_gdquot;	/* group dquot */
	struct xfs_dquot	*i_pdquot;	/* project dquot */

	/* Inode location stuff */
	xfs_ino_t		i_ino;		/* inode number (agno/agino)*/
	struct xfs_imap		i_imap;		/* location for xfs_imap() */

	/* Extent information. */
	struct xfs_ifork	*i_cowfp;	/* copy on write extents */
	struct xfs_ifork	i_df;		/* data fork */
	struct xfs_ifork	i_af;		/* attribute fork */

	/* Transaction and locking information. */
	struct xfs_inode_log_item *i_itemp;	/* logging information */
	struct rw_semaphore	i_lock;		/* inode lock */
	atomic_t		i_pincount;	/* inode pin count */
	struct llist_node	i_gclist;	/* deferred inactivation list */

	/*
	 * Bitsets of inode metadata that have been checked and/or are sick.
	 * Callers must hold i_flags_lock before accessing this field.
	 */
	uint16_t		i_checked;
	uint16_t		i_sick;

	spinlock_t		i_flags_lock;	/* inode i_flags lock */
	/* Miscellaneous state. */
	unsigned long		i_flags;	/* see defined flags below */
	uint64_t		i_delayed_blks;	/* count of delay alloc blks */
	xfs_fsize_t		i_disk_size;	/* number of bytes in file */
	xfs_rfsblock_t		i_nblocks;	/* # of direct & btree blocks */
	prid_t			i_projid;	/* owner's project id */
	xfs_extlen_t		i_extsize;	/* basic/minimum extent size */
	/*
	 * i_used_blocks is used for zoned rtrmap inodes,
	 * i_cowextsize is used for other v3 inodes,
	 * i_flushiter for v1/2 inodes
	 */
	union {
		uint32_t	i_used_blocks;	/* used blocks in RTG */
		xfs_extlen_t	i_cowextsize;	/* basic cow extent size */
		uint16_t	i_flushiter;	/* incremented on flush */
	};
	uint8_t			i_forkoff;	/* attr fork offset >> 3 */
	enum xfs_metafile_type	i_metatype;	/* XFS_METAFILE_* */
	uint16_t		i_diflags;	/* XFS_DIFLAG_... */
	uint64_t		i_diflags2;	/* XFS_DIFLAG2_... */
	struct timespec64	i_crtime;	/* time created */

	/*
	 * Unlinked list pointers.  These point to the next and previous inodes
	 * in the AGI unlinked bucket list, respectively.  These fields can
	 * only be updated with the AGI locked.
	 *
	 * i_next_unlinked caches di_next_unlinked.
	 */
	xfs_agino_t		i_next_unlinked;

	/*
	 * If the inode is not on an unlinked list, this field is zero.  If the
	 * inode is the first element in an unlinked list, this field is
	 * NULLAGINO.  Otherwise, i_prev_unlinked points to the previous inode
	 * in the unlinked list.
	 */
	xfs_agino_t		i_prev_unlinked;

	/*
	 * mxfs sess40 (D-AGI-UNLINKED F1, per-slot buckets): the AGI bucket
	 * this inode's unlinked-list entry actually lives in; -1 = not on any
	 * list.  Stamped at insert and by every recovery/reload walk that
	 * establishes list membership; the remove path uses THIS and never
	 * recomputes (bucket choice is the inserter's node slot in multi-node
	 * mode, so a remover must not re-derive it from its own identity or
	 * from agino hashing — GPT sess40 review, "explicit recorded bucket").
	 */
	int16_t			i_unlinked_bucket;

	/* sess40 (D-CROSSNODE-OPEN-UNLINK): count of open file descriptions
	 * this node holds for the inode.  Together with mapping_mapped() it
	 * answers "does this node have protected activity" — the predicate
	 * published to peers as an open-holder bit when a BAST makes us
	 * release the grant (the only moment a peer's destructive path can
	 * be about to run). */
	atomic_t		i_mxfs_open_n;

	/* sess40: this node has PUBLISHED an open-holder bit for the inode
	 * (BAST release while still open here).  The clear paths consult it
	 * first: without it, evict and every unlinked-inode exit would run a
	 * full slot probe (SCSI reads on the shared LUN) for inodes that
	 * never had a bit — measured as added target load on mass-eviction
	 * workloads.  Only published inodes pay the clear. */
	bool			i_mxfs_open_pub;

	/* sess46 (iclus open tracking): a standalone SET of this inode's
	 * open bit is IN FLIGHT from the icluster release-publication sweep.
	 * Under i_dlm_lock with i_mxfs_open_pub.  C4's last-close clear
	 * skips while set (the sweep's post-SET recheck performs the clear
	 * if activity reached zero mid-SET), closing the GPT
	 * close-during-SETTING race that would otherwise leave a permanent
	 * stale bit deferring peers' reaps until fencing. */
	bool			i_mxfs_open_setting;

	/* MXFS DLM lock cache */
	spinlock_t		i_dlm_lock;	/* protects DLM cache fields */
	wait_queue_head_t	i_dlm_wait;	/* blocked by DEMOTING state */
	struct work_struct	i_dlm_bast_work; /* deferred BAST processing */
	struct delayed_work	i_dlm_bast_dwork; /* sess124: MHT (minimum hold time) deferred BAST release timer */
	bool			i_dlm_bast_pending; /* sess124: a peer BAST is deferred under MHT; honor it on dwork expiry / unlock / evict */
	bool			i_dlm_dir_contended; /* sess25 (ccloop 4cb2d0a2): STICKY — set on ANY BAST received for this dir inode; gates mxfs_dir_ail_push_defer so a SHARED dir defers background dir-block destages to the release-drain even during the create-phase cold window (dir_gen still 0 on a fresh incarnation since the create path never bumps dir_gen — only reads do).  A truly private dir is never BAST'd → stays false → destages normally (no log-tail starvation).  Reset at inode init. */
	bool			i_dlm_dir_want_ex; /* ccloop 12e0d157 (Fable design): set when a peer BAST requested EX (a MODIFIER) on this dir since the last grant.  Distinct from i_dlm_dir_contended (set on ANY BAST incl PR readers / MHT self-demote / noino).  Gates the release-time dir-buffer invalidation (mxfs_dir_release_invalidate_data_blocks) under mxfs_dir_release_skip_nonex: a dir released while NO peer wants EX keeps its cached blocks (no peer can modify what it holds only ≥PR on), killing the 32-node dlm_scaling cold-reread storm.  Cleared at inode init and on each fresh grant. */
	u64			i_dlm_ex_acquire_ns; /* sess124: ktime of the most recent FRESH inode-EX grant (start of the MHT window) */
	u64			i_dlm_tenure_lastop_ns; /* sess7 (ccloop 72513a13): ktime of the most recent ilock_end on this inode — the last moment the current tenure was CONSUMED.  Quiet-age input for the MHT dwork: with a peer parked (bast_pending), a young-window tenure releases at the first sample where now-max(this,acquire_ns) >= the batch grace, instead of sleeping out the full 300ms window on an idle grant (cc@32 rv: 32-node rotation at 300ms/hop = 3-7.7s peer waits). */
	uint8_t			i_dlm_mode;	/* cached mode: NL/PR/EX */
	uint8_t			i_dlm_state;	/* MXFS_DLM_ISTATE_* */
	/* sess5 shadow-ledger provenance: return address of the last
	 * nlink-0 install and of the last MXFS_IF_RMC_ACCT clear — printed
	 * (%pS) by mxfs_rmc_unpaired so the unpaired 0->N dec names the
	 * exact site that installed/unaccounted the zero. */
	void			*i_rmc_last0_ra;
	void			*i_rmc_lastclr_ra;
	unsigned long		i_dlm_heldchk_j; /* v0.5.2: jiffies of the last P108 on-disk slot-ownership verify (one 512B slot read per idle dir-ilock cache hit; throttled to one per 100ms per inode — same correctness class, the verify is TOCTOU-bounded either way) */
	unsigned long		i_dlm_phantom_bast_j; /* sess7 FIX-20: jiffies of the last NONE/NL BAST that found NO local mirror (possible master-side phantom grant).  With i_dlm_phantom_bast_n it discriminates a one-off stale BAST (swallowed, cheap) from a phantom-holder BAST STORM (starved waiters retry ~1/s -> repeated BASTs): the 2nd+ strike within 15s escalates to a serialized reconcile release. */
	unsigned int		i_dlm_phantom_bast_n; /* sess7 FIX-20: consecutive no-mirror NONE/NL BAST strikes within the window */
	bool			i_dlm_reconcile_pending; /* sess7 FIX-20b: one-shot — the queued bast_process is a phantom reconcile; its P6Z mirror-empty arm must send the mirror-bypassing gen=0 release to the master instead of skipping silently */
	uint32_t		i_dlm_orphan_gg; /* sess15 FIX-H2: grant_gen seen at the last orphan-live release abort (cleanup-flavor bast_process vs a live-gen mirror entry).  With i_dlm_orphan_strikes it discriminates a grant mid-completion (gen turns over / gets consumed -> reset) from a genuinely STRANDED grant (same gen, never consumed, no ACQUIRING slow path across >=4 samples ~25ms apart -> release it; r12 proved abort-only wedges a hot dir 184s -> rc=-110 shutdown cascade). */
	uint8_t			i_dlm_orphan_strikes; /* sess15 FIX-H2: consecutive same-gen orphan-live abort samples */
	u64			i_dlm_orphan_since_ns; /* ccloop a864 sess4: ktime when the orphan-live (mode==NL) release strand was FIRST observed continuously.  Reset to 0 on genuine consumption (ACQUIRING / mode!=NL) or a non-orphan release.  Drives the WALL-CLOCK strand escape that the same-gen strike counter cannot reach on CAW (grant_seq churns under N-node contention -> strikes never converge -> node held dir EX 119s idle).  A true mid-completion grant resumes in microseconds, so >mxfs_caw_orphan_force_ms of continuous mode==NL is a genuine strand. */
	u64			i_dlm_bast_starve_since_ns; /* fence_during_write@8caw livelock fix: ktime when a peer BAST was first observed pending (i_dlm_bast_pending) on this ino while bast_process kept hitting the P15-REL-ABORT abort path.  UNLIKE i_dlm_orphan_since_ns this is NOT reset by local mode churn (ACQUIRING / mode!=NL) — only by i_dlm_bast_pending going false (peer served).  PROVEN NEED (live dmesg, ino=2099074 isdir=1): a hot-dir create+unlink storm on THIS node re-acquires/releases the dir's own lock every ~26ms, which resets i_dlm_orphan_since_ns via the "genuine consumption" branch on every single cycle, so the wall-clock strand escape never survives 3 continuous seconds even though a peer blocked 360s+ (3x120s ACQUIRE timeouts) waiting for the SAME ino and self-fenced (DLM inode lock unrecoverable -> xfs_force_shutdown).  This clock measures PEER STARVATION directly instead of continuous LOCAL idleness, so local churn cannot reset it. */
	uint32_t		i_dlm_init_seq; /* interactive session 2026-07-13: diagnostic-only.  Stamped from a global atomic counter in mxfs_dlm_inode_init (true fresh xfs_inode_alloc, incl. post-eviction re-iget).  Printed alongside P15-REL-ABORT to test the hypothesis that i_dlm_orphan_since_ns/i_dlm_bast_starve_since_ns keep getting wiped by in-core inode eviction+reinstantiation (icache reclaim churn under the fence_during_write hot-dir storm) rather than by any bug in the clocks' own reset logic — a DIFFERENT value across "consecutive" P15-REL-ABORT samples for the SAME ino proves the in-core inode was recycled in between. */
	uint16_t		i_dlm_p72_strikes; /* ccloop a864 sess3: consecutive P72 stuck-DEMOTING orphan swallows (mode==NL, holders==0) seen while i_dlm_demoter is non-NULL.  A non-NULL demoter at work_busy==0 is a stuck INLINE bast_process (blocked at mode==NL, past its Phase-2 drain, so demoter=NULL never runs).  A LIVE inline drain completes within 1-2 peer BASTs; the wedge storms 100s+.  Once this reaches MXFS_P72_ORPHAN_STRIKES the orphan-reclaim overrides the demoter gate and force-clears the bit.  Reset on claim / when the orphan shape no longer holds. */
	unsigned long		i_dlm_epoch;	/* v0.5.1: DLM hold-epoch.  Bumped every time this node LOSES the inode's DLM grant (mode -> NL) or marks it stale.  While i_dlm_mode != NL the on-disk grant is held, so no peer can have modified this inode/dir since the epoch last changed.  d_revalidate stamps the parent's epoch into dentry->d_time after a coordinated validation; a later cached lookup whose stamp still equals the parent's epoch (parent grant held, not stale) is provably fresh with ZERO disk I/O. */
	uint16_t		i_dlm_ex_holders; /* active IOLOCK_EXCL holders */
	uint16_t		i_dlm_pr_holders; /* active IOLOCK_SHARED holders */
	uint16_t		i_dlm_pin_count;  /* D9: multi-step op pins (mxfs_clayer/pinned_resource.h) */
	uint16_t		i_dlm_acq_inflight; /* ccloop daf50d34 sess2: count of slow-path DLM acquires in flight on this inode (bumped with ISTATE_ACQUIRING under i_dlm_lock, dropped at every slow-path exit).  PROVEN (mkdir_storm r5, test15 ino 12585041): a stale bast_process exit trampled state ACQUIRING->NONE during an 836ms GRANT-WAIT; when the grant landed, mode=EX was published (v0.3.15 early publish) with state=NONE/holders=0, and bast_notify's NONE-held-idle branch released the 0ms-old tenure before the acquiring mkdir ever used it.  The op then FASTEX'd on the phantom cached EX (P-TDS-RMW held=0) and its late AIL destage clobbered the successor tenure's committed dirent (durable node1 loss).  state==ACQUIRING is the intended defer signal but is trample-able by concurrent pipeline exits; this counter is not: bast_notify's idle/orphan/immediate release branches and the MHT dwork treat >0 as "defer via i_dlm_bast_during_acq / re-arm" instead of releasing. */
	uint16_t		i_dlm_yield_remaining; /* D10: BAST yield quantum (mxfs_clayer/yield_quantum.h) */
	uint16_t		i_dlm_tenure_ops; /* sess6 (ccloop 72513a13): ILOCK cycles served by the CURRENT EX tenure (reset at every fresh-EX stamp).  Adaptive MHT floor input: a tenure that has served only ONE op is a one-shot (cc cv-write storm shape) and yields to a pending BAST after a ~5ms grace instead of the full dir_sf_mht_ms/inode_mht_ms floor; >=2 ops = burst (fairness/drc round shape) keeps the full batching floor. */
	uint16_t		i_dlm_dwork_strikes; /* v0.10.31: consecutive busy re-arms of i_dlm_bast_dwork within ONE deferral episode.  The dwork re-arms every ~8ms while ex/pr/pin holders are in flight; a holder that NEVER drops (create-path oops leaking the dir locks — test9 2026-07-10) made that an infinite 4ms spin holding an iget ref, so unmount leaked the inode ("Objects remaining on __kmem_cache_shutdown") and post-rmmod bio completions panicked the node.  At MXFS_DWORK_STRIKE_MAX the dwork STRIKES OUT: logs P36-STRIKEOUT, drops its ref, does NOT re-arm.  i_dlm_bast_pending stays set, so ilock_end/unpin refire or the peers' ~1s BAST retries re-arm a fresh episode (strikes reset at fresh-episode arm only, NOT on repeat-BASTs of a running episode, else the 1s retries would reset the count forever). */
	bool			i_dlm_stale;	/* needs reload from disk after BAST */ uint8_t i_dlm_stale_src; /* sess11(a9a03929): code of the LAST i_dlm_stale=true setter (1=readdir 2=consumer_refresh 3=modify_prelock 4=adopt_fmt 5=bast_process_rel 6=bast_notify_acq 7=ilock_slow_prereload 8=fastpath_rearm 9-13=dlm_misc 14-17=iget 18-20=inode_misc 21-23=super 24=iflush_deadincarn 25=iflush_dirvalid_epoch 26=reload_identical_keepfork 27=file_rw_bail) — P11-ACQSTALE-SELFBAST forensics */ uint8_t i_dlm_bastq_src; /* sess11: site that queued the last bast_work/dwork (1=ilock_end_refire 2=demwait_redrive 3=notify_idle 4=notify_orphan 5=notify_immediate 6=ilock_begin_recov 7=acq_selfbast 9=mht_arm 10=stranded_arm 11=batch_arm 12=sf_tenure_arm 13=grantwin_park 14=close_release 15=pr_idle_release 16=dir_ex_sweep) */
	bool			i_dlm_bast_during_acq; /* sess35 (ccloop): a peer BAST arrived while this node was in ISTATE_ACQUIRING (slow-path DLM acquire in flight).  SEPARATE flag from i_dlm_stale: the post-acquire reload CLEARS i_dlm_stale before the post-publish reads it, so reusing i_dlm_stale to defer the BAST silently SWALLOWED the revoke — the holder kept the grant cached idle and the peer's request stalled the full 6000ms MXFS_LOCK_ACQUIRE_WAIT_MS until its retry re-fired the BAST (the dir_reuse 2/tcp ~6s handoff, PROVEN sess35: 9 ACQUIRING-EX BASTs lost/run).  Set by bast_notify's ACQUIRING branch; honored at the slow-path post-publish (-> ISTATE_BAST + drain) regardless of reload; cleared there. */
	struct task_struct	*i_dlm_tries_owner; /* ccloop-4dd7 sess2 ABBA breaker: task for which the NEXT slow-path acquire of THIS inode is retry-bounded (set by xfs_lock_two_inodes around its SECOND ilock_begin while it holds the first inode's grant-hold).  Gating by task means a concurrent acquirer of the same inode never inherits the bound. */
	int			i_dlm_tries;       /* retry budget for the bounded acquire (0 = unbounded/normal) */
	int			i_dlm_tries_rc;    /* OUT: 0 = acquired; -ETIMEDOUT = bounded acquire gave up (caller must drop its other grant-hold, back off, retry both) */
	bool			i_dlm_self_demote; /* sess51 (ccloop 8ddb16a2): the next mxfs_dlm_bast_process for this inode is a SELF-demote (the P109 EDEADLK upgrade-conflict recovery dropping our own cached PR->NL to re-request EX from a clean state), NOT a peer handoff.  No peer reads our state across a self-demote, so a clean (read-only) self-demote needs no durability drain — skipping it kills the tcp_dlm_scaling PR->EX upgrade-livelock amplifier WITHOUT removing the coherency-masking barrier on genuine peer handoffs (dir_reuse/rsync_paired).  Set in the EDEADLK recovery before queuing bast_work; read+cleared at bast_process entry. */
	bool			i_dlm_unpublished; /* sess43: brand-new inode granted LOCALLY (i_dlm_mode=EX) with NO on-disk CAW slot yet; published lazily on a peer dir/AGI BAST or dropped silently on local eviction.  See notes/sess43_deferred_publish_design.md */
	struct list_head	i_dlm_unpub_link;  /* sess43: linkage on mp->m_mxfs_unpub_list while i_dlm_unpublished */
	xfs_ino_t		i_mxfs_unpub_parent; /* v0.5.6 (sess29 ccloop 14d31183): ino of the directory whose dirent names this unpublished inode; 0 = unknown (tmpfile/whiteout/pre-assignment window) and means "include in EVERY scoped BAST publish".  Lets the BAST-side publish drain claim slots ONLY for inodes a peer can actually reach through the lock being released (the released dir's children, or the released AG's inodes) instead of the whole list — the whole-list drain at 16 nodes claimed ~96k slots against the 65536-slot CAW table, took minutes per release, and starved EX waiters into 120s timeouts + shutdown (sess28 scaling_curve root cause 2).  Set after xfs_dir_create_child in xfs_create/xfs_symlink; a plain store suffices: a racing scoped drain that reads the pre-store 0 over-publishes (safe), never under-publishes.  Cross-dir rename/link of a still-unpublished inode force-publishes synchronously (mxfs_dlm_publish_inode) so the recorded parent can never go stale. */
	uint32_t		i_dlm_dir_gen;	/* sess37: bumped on DLM re-acquire-after-BAST; dir-block read path forces FUA re-read when cached buf's stamp < this (read-time/lazy block-dir invalidation, deadlock-free) */
	uint32_t		i_dlm_cached_grant_gen; /* sess61 (sess10 plan): the TCP DLM per-grant generation token cached at the last SLOW-PATH acquire of this inode.  On a dir-EX FAST-PATH serve, if mxfs_v5_dlm_inode_grant_gen() != this, the lock CHANGED HANDS (a peer was granted) since we cached it -> the in-core dir base is stale -> force a reload-on-reacquire before the RMW.  This is the RELIABLE (acked-TCP grant_gen) replacement for the lossy DIR_MODIFY eviction-ring as the dir staleness signal (sess61 PROVEN root: fast-path RMW of a stale block0 clobbers peers' dirents). 0 = not yet cached. */
	uint32_t		i_dlm_dir_loaded_gen; /* sess94: value of i_dlm_dir_gen at the moment the SHORTFORM dir fork was last (re)loaded from disk.  If i_dlm_dir_gen has advanced past this when a cached EX-acquire fast-paths, the in-core shortform fork is STALE (a peer modified the dir) and RMW'ing it would clobber the peer's dirents — the unlink_visibility lost-update. */
	uint64_t		i_mxfs_dscan_clean_key; /* sess1 (ccloop 46efd8b6): datascan gen-gate.  Composite of (i_dlm_dir_gen, i_dlm_dir_valid_epoch, i_dlm_dir_loaded_gen) captured when mxfs_dir2_datascan_lookup last verified the leaf hash-index ENOENT-consistent (scan found nothing the leaf missed).  While the coherency state hasn't moved, further hash-miss lookups skip the O(dir) authoritative data scan (measured 459 read-IOs / 112ms per MISS on a 640-entry shared dir — every rv/uv negative lookup).  Any peer modify moves the epoch/gen (leaf-hole formation requires a peer write), and any real fork adopt resets this to the ~0 sentinel, re-arming one scan. */
	uint32_t		i_mxfs_rd_vgg;	/* ccloop c7ee71c6 sess7 (GPT tenure-coherence ruling): DLM grant gen under which this dir's fork was last VALIDATED for readdir (reload attempted+landed).  0 = never validated.  A grant gen change (re-grant after revoke, incl. the round-1 dir_gen==0 case the want_block_refresh gate misses) means the fork may predate a peer's EX tenure -> readdir revalidates ONCE per grant episode.  Solo dirs keep one grant forever -> one initial validation, zero steady-state cost (the sess38/91 anti-poll constraint). */
	bool			i_dlm_routed_iclus; /* ccloop 72513a13 sess4: WHICH resource backs the current i_dlm_mode grant — true = the inode-cluster (iclus) resource, false = the per-inode slot.  Stamped at every disk acquire; every release/sweep decision routes by THIS, never by re-evaluating S_ISREG (a mode-0 dead-shell acquire is per-inode, and re-evaluating at release orphaned the slot forever — proven: per-inode EX gen=2201 held 220s, 7 nodes queued on the root dir). */
	uint64_t		i_dlm_iclus_seen_seq; /* ccloop 72513a13 sess4: mxfs_iclus grant_seq at our last reload/adopt of this inode.  seen==current ⟹ the cluster grant was held (by us or nobody) continuously since — no peer EX possible — so the in-core image is coherent (reload skippable); seen!=current ⟹ a fresh cluster claim happened (peer may have written) — genuine handoff, force disk adopt.  0 = never loaded under iclus. */
	uint32_t		i_dlm_handoff_acted_gen; /* sess63: grant_gen at which we last ACTED on a cross-node EX handoff (forced a full disk-superset reload of this dir).  The master-exposed handoff bit (mxfs_v5_dlm_inode_grant_handoff) is consumed once per grant episode: act only when handoff && grant_gen != this, then set this=grant_gen.  Prevents a 2nd same-tenure reload re-adopting disk over our own in-flight mods (resurrection).  0 = never acted. */
	uint32_t		i_dlm_dir_valid_epoch; /* sess64 (GPT design): the MONOTONIC cross-node handoff epoch (mxfs_v5_dlm_inode_dir_epoch) that this dir's in-core base is known coherent with.  On any dir grant authorization the XFS layer reads the grant's dir_epoch; if it EXCEEDS this, a peer modified the dir since our base loaded -> force a disk-superset adopt + clean dir-block invalidation, then set this=grant_epoch.  LEVEL-triggered (a missed intermediate handoff still leaves grant_epoch > this), curing the edge-triggered handoff bool's ~80% under-fire.  0 = base predates any tracked handoff. */
	uint32_t		i_dlm_dir_valid_incarn; /* ccloop c7ee71c6 sess28: the i_generation (INCARNATION) that i_dlm_dir_valid_epoch's baseline was established under.  The CAW dir_epoch is a property of the inode NUMBER, not of an incarnation: caw_tombstone_slot/caw_claim_inherit_epoch deliberately carry it across an idle gap, and mxfs_v5_dlm_inode_dir_epoch() serves it out of a per-resource grant_meta cache that survives the inode being freed and re-created.  So `master_epoch > i_dlm_dir_valid_epoch` compares a DEAD incarnation's handoff lineage against a LIVE incarnation's baseline unless this matches VFS_I(ip)->i_generation — the same cross-incarnation-comparison class sess27 proved for di_gen in RELOAD-TYPEFLIP.  TRACE-PROVEN (2/caw, test2, ino 2099630): incarnation A published at epoch 0, was handed off and freed (EVICT-RING-FLAG incore_gen=2916713347 freed_gen=...348); incarnation B was created on the same number moments later and, still i_dlm_unpublished with no grant of its own, read grant_epoch=2 out of A's stale grant_meta — so P32E-DIREPOCH-FENCE skipped every flush of B and its mkdir was silently lost.  0 = no baseline (see mxfs_dir_epoch_superseded). */
#define MXFS_CBASE_UNSET	0	/* sess28: LOCAL_UNPUBLISHED — no baseline established */
#define MXFS_CBASE_SEEN		1	/* sess28: publish reached with the stamp knob off (control arm) */
#define MXFS_CBASE_VALID	2	/* sess28: baseline established at the first real EX grant */
	uint8_t			i_dlm_base_valid; /* ccloop c7ee71c6 sess45 (GPT Option-B contract, D-DIRENT-PUBLISH-STALE-BASE-P195-360): EXPLICIT validity bit for the dir-base coherence baseline pair (i_dlm_dir_valid_epoch, i_dlm_cached_grant_gen).  0 = the baseline was never established for this in-core incarnation OR was invalidated (EX release/demote, aborted adopt, phantom-EX bail) — the next dir-EX authorization MUST adopt the disk base before exposing the tenure to dir ops (mxfs.dir_adopt_at_acquire gate).  1 = the pair was stamped by mxfs_dir_base_stamp AFTER a completed adopt/keep decision (reload install point), a creator publish (first real EX grant, self_created), or an authority rebase.  Written with smp_store_release AFTER the epoch/gen stores; gate reads with smp_load_acquire.  Replaces the sentinel-0 inferences that made P195's tenure-vs-epoch disambiguation inert (valid_epoch=0 and cached_gen=0 are both legitimately reachable baselines — GPT sess27/sess44). */
	uint8_t			i_dlm_creator_base_state; /* ccloop c7ee71c6 sess28: explicit lifecycle of the CREATOR BASELINE for a directory this node created (MXFS_CBASE_*).  UNSET(0) = LOCAL_UNPUBLISHED, no baseline ever established — the state that made i_dlm_dir_valid_epoch stick at 0 and P32E-DIREPOCH-FENCE skip every flush of a self-created dir (D-SILENT-MKDIR-LOSS).  SEEN(1) = the inode reached its first real EX grant while mxfs.creator_baseline_stamp was 0, i.e. the CONTROL arm entered the state; this exists so the exposure counter is KNOB-INDEPENDENT (a fix-gated exposure counter makes the reproducing arm report zero exposure — sess27's method lesson).  VALID(2) = the baseline was established from that grant.  This is the explicit state GPT's sess27 review asked for: "never established" must not be inferred from the numeric 0, because epoch 0 and grant_gen 0 are both legitimately reachable baselines.  One-shot per incarnation; reset at inode init/reuse. */
	bool			i_dlm_icd_refused; /* v0.6.5 (sess5 186320ae): a per-op/release inode-cluster destage was REFUSED because the on-disk CAW slot was no longer ours (P-ICD-TENURE-REFUSE).  The committed change exists in the log/in-core but NOT on disk, and the ili may retire clean (ghost-skip), so "clean => disk is superset" is FALSE until the next successful destage.  The acquire-reload honors this by 3-way-MERGING our pre-reload fork over the adopted disk image (instead of the clean-wholesale-adopt that would revert our committed rename/rm — the n3_r1 ghost).  Set at refuse; cleared on a successful mxfs_inode_cluster_durable. */
	uint32_t		i_dlm_dir_acq_epoch; /* sess5(ccloop 186320ae) v0.6.5: the grant dir_epoch at which this dir's fork was last made coherent by the ACQUIRE-RELOAD falling through to xfs_inode_from_disk (adopt point).  The P65 epoch-consume adopt gate compares the current grant epoch against THIS, not valid_epoch: the modify/evict-path hooks legitimately sync valid_epoch UP to the master epoch mid-tenure for buffer stamping (b_mxfs_dir_epoch) and prior-tenure evicts, which ERASES the acquire gate's lag without any adopt having happened — the storm-dir stale-base resurrection (uv dangling dirent: a node's frozen 18-entry block view survives handoffs, its last unlinks convert block->sf from that stale base and durably re-assert peer-removed names).  ONLY the reload coherence point may advance this; a keep-stale-guard early return leaves it lagging so the next acquire re-fires the adopt.  0 = never made coherent. */
	void			*i_dlm_dir_sf_base; /* sess14: snapshot of this SHORTFORM dir's on-disk dirent image (xfs_dir2_sf_hdr + entries) captured at the last coherent disk read/reload — the BASE for a 3-way merge (base/ours/theirs).  A concurrent shortform RMW reconciles in-core (ours) with disk (theirs) relative to this base: names WE changed (ours != base) keep OURS, names we didn't touch follow THEIRS.  This keeps our own committed-not-durable rename/rm (no self-revert on a destage-lagging disk read) AND adopts the peer's committed adds/removes (no resurrection of a peer's removed dirent).  NULL = no snapshot yet (merge falls back to adopt-or-skip). kmalloc'd; freed in xfs_inode_free_callback. */
	uint32_t		i_dlm_dir_sf_base_bytes; /* sess14: byte length of i_dlm_dir_sf_base */
	void			*i_dlm_dir_pending; /* sess65: kmalloc'd array of struct mxfs_pend_ent — local positive dirents recently CREATED in this dir by this node (this incarnation).  Replayed (re-added) into the dir whenever a stale-block0 ADOPT drops our own just-created entries (the dir_reuse_coherency node1_f1 double-block0 orphan: rank1 converts sf->block0@A with node1_f1, a peer converts its stale shortform to block0@B which wins on disk, rank1's next create adopts block0@B dropping node1_f1; merge_ours only covers shortform<->shortform so it can't restore it).  Lazily allocated, bounded ring; freed in xfs_inode_free_callback. */
	uint32_t		i_dlm_dir_pending_bytes; /* sess65: used byte length of i_dlm_dir_pending */
	uint32_t		i_dlm_dir_pending_incarn; /* sess65: VFS i_generation the pending list belongs to; on incarnation change (rm-rf+recreate bumps di_gen) the list is dropped so we never replay a dead incarnation's names. */
	uint32_t		i_dlm_dir_evicted_gen; /* sess97: i_dlm_dir_gen value at the last EAGER consumer-side dir-DATA-block evict (mxfs_dlm_dir_consumer_refresh).  When i_dlm_dir_gen advances past this (a peer modified the dir), the next readdir/lookup eagerly drops ALL clean cached dir data blocks so they refetch the peer's durable image — replacing the lazy per-buffer restamp-prone hook that could cache a stale block as current. */
	uint32_t		i_dlm_dir_evicted_incarn; /* sess104 (Gemini ABA fix): VFS i_generation at the last whole-dir clean-block evict.  i_dlm_dir_gen counts WITHIN one inode incarnation and resets to 0 on a fresh struct, so under inode-number REUSE a peer's PREVIOUS-incarnation dir blocks (cached by physical daddr, not by inode) can collide on gen (old gen == new gen) and escape the gen-keyed evict.  XFS bumps di_gen on every reallocation, so evict-once-per-incarnation (this != i_generation) closes the ABA gap. */
	uint32_t		i_dlm_dir_coherent_gen; /* sess19(ccloop): i_dlm_dir_gen at the last mxfs_dir_refresh_stale_data_blocks (dir_coherent_modify) per-block coherence scan.  HANDOFF-GATE: the scan runs ONCE per cross-node dir-EX handoff (when i_dlm_dir_gen advances past this), NOT per addname — under EX no peer modifies mid-tenure, so a single tenure-start scan suffices.  Turns the O(blocks×creates) per-addname scan (5× too slow @ mht=50) into O(blocks×handoffs). */
	uint32_t		i_dlm_dir_evict_mep; /* sess26(ccloop) NEW-TENURE evict: the master dir epoch (mxfs_v5_dlm_inode_dir_epoch) observed at this dir's last modify-path clean-block evict.  When the master epoch ADVANCES past this, a peer held EX since our last evict (a genuine cross-node handoff) — so our cached dir blocks, INCLUDING ones lingering in-AIL, are durable-but-stale (Inv 1 drained them at the release that preceded the peer's tenure) and must be force-evicted so the first RMW of this new tenure cold-reads the peer's durable image.  Unlike valid_epoch (synced mid-tenure -> mis-flags this tenure's own earlier blocks -> readdir=0), this is compared at the EVICT-CALL granularity: same epoch => same tenure => keep genuine in-flight work. */
	uint64_t		*i_dlm_dir_removed; /* sess34(ccloop): inumbers REMOVED from this dir during the CURRENT EX tenure (since the last valid_epoch change) — the drain-merge removed-set.  At the release drain a disk-only dirent (on disk, absent in-core) is AMBIGUOUS: our own pending remove (don't graft) vs a peer's add we never refreshed (graft).  Its inumber being in this set proves it is OUR remove → never resurrect it; absent → a peer add → graft (fixes dir_reuse readdir=799 without the dir_write_merge over-graft to 803).  kmalloc'd, freed in xfs_inode_free_callback. */
	uint32_t		i_dlm_dir_removed_n;	/* sess34: used entries */
	uint32_t		i_dlm_dir_removed_cap;	/* sess34: allocated entries */
	uint32_t		i_dlm_dir_removed_epoch; /* sess34: i_dlm_dir_valid_epoch the removed-set belongs to; a mismatch => no removes recorded this tenure (set treated empty). */
	uint64_t		i_mxfs_ex_grant_seq; /* sess17b (ccloop 4eef1f39, Gemini DLM-epoch guard): node-global monotonic epoch stamped each time this inode TRANSITIONS into an EX grant (a fresh EX tenure).  Unchanged while EX is held continuously. */
	uint64_t		i_mxfs_dirty_seq; /* sess17b: value of i_mxfs_ex_grant_seq at the moment this inode was last logged/dirtied under EX.  At flush time, dirty_seq != ex_grant_seq means the dirty in-core state belongs to a PREVIOUS EX tenure (we yielded EX in between, so a peer may have freed/reused the inode on disk) -> a stale ghost; skip the flush instead of clobbering the peer's live on-disk incarnation (the rename_visibility/cross_write_read empty-content + bnobt resurrection family). */

	/*
	 * ─── MXFS DURABLE-AUTHORITY STATE (sess98, step 5.3(c)) ───
	 *
	 * D-FOREIGN-REPLAY-UNGATED-IMAGES needs every logged metadata image to
	 * carry proof that THIS node durably held EX on the resource backing
	 * the object at the moment the image was formatted.  The sess96 RULE-5
	 * ruling named the reason i_dlm_mode cannot be that proof:
	 *
	 *   i_dlm_mode == MXFS_LOCK_EX cannot distinguish an UNPUBLISHED local
	 *   grant (no on-disk slot exists at all), a DURABLE disk-backed
	 *   tenure, a tenure whose RELEASE has already begun (slot marked
	 *   releasing / handoff sent / peer already acquiring — all of which
	 *   happen BEFORE mode is lowered to NL), and a mirror re-affirm that
	 *   only restated a cached mode without any granting CAS.
	 *
	 * So authority is modelled separately, as an explicit state machine.
	 * ALL of these fields are written under i_dlm_lock, and only by the
	 * mxfs_inode_authority_* helpers in xfs_mxfs_dlm.c.
	 */
#define MXFS_AUTH_NONE			0	/* no authority claim */
#define MXFS_AUTH_UNPUBLISHED_EX	1	/* local-only EX, no on-disk slot */
#define MXFS_AUTH_DURABLE_EX		2	/* disk-backed EX tenure, provable */
#define MXFS_AUTH_RELEASING		3	/* release has BEGUN — dead for proof */
/*
 * Sentinel gen snapshot meaning "this acquire made no provenance claim, so it
 * may not install a tenure".  i_mxfs_auth_gen starts at 0 and only ever
 * increments, so it cannot reach this value in any realistic mount lifetime.
 */
#define MXFS_AUTH_GEN_NONE		(~(uint64_t)0)
/*
 * Outcomes of one install ATTEMPT (i_mxfs_auth_try).  0 means no attempt has
 * ever been made on this inode, so the field is meaningful straight out of a
 * zeroed slab.  The STATUS_BASE range mirrors enum mxfs_grant_auth_status one
 * for one, so a refusal that came from the snapshot classification keeps its
 * exact reason instead of collapsing into a generic "refused".
 */
#define MXFS_AUTH_TRY_NONE		0	/* never attempted */
#define MXFS_AUTH_TRY_INSTALL		1	/* installed a new tenure */
#define MXFS_AUTH_TRY_ADVANCE		2	/* same tenure, epoch advanced */
#define MXFS_AUTH_TRY_SAMETENURE	3	/* same tenure, epoch not newer */
#define MXFS_AUTH_TRY_NOGRES		4	/* caller passed no result struct */
#define MXFS_AUTH_TRY_STALEGEN		5	/* gen moved under the acquire */
#define MXFS_AUTH_TRY_RELEASING		6	/* release already begun */
#define MXFS_AUTH_TRY_UNPUB		7	/* still on the unpublished list */
#define MXFS_AUTH_TRY_ROUTING		8	/* backing/routing disagreement */
#define MXFS_AUTH_TRY_RECLAIM		9	/* reclaiming or shut down */
#define MXFS_AUTH_TRY_STATUS_BASE	16	/* + enum mxfs_grant_auth_status */
#define MXFS_AUTH_TRY_MAX		24
	uint8_t			i_mxfs_auth_state;
	uint8_t			i_mxfs_auth_kind;	/* enum mxfs_lock_type backing the tenure */
	uint8_t			i_mxfs_auth_reaffirm;	/* tenure installed from an already-held image */
	/*
	 * Bumped on EVERY revoke and EVERY release-begin, never on install.
	 *
	 * This is the anti-stale-completion counter the ruling demanded.  An
	 * acquire snapshots it under i_dlm_lock BEFORE descending into the DLM
	 * and re-checks it at install; a mismatch means authority was given up
	 * between the snapshot and the completion, so this completion's grant
	 * result describes a tenure that no longer exists and must not be
	 * installed.  `mode > i_dlm_mode` does NOT catch that case: it only
	 * rejects a completion that finds EX already installed, never a full
	 * EX -> NL -> EX cycle where the OLD completion wins i_dlm_lock.
	 */
	uint64_t		i_mxfs_auth_gen;
	uint64_t		i_mxfs_auth_resource;	/* gres.resource of the live tenure */
	uint64_t		i_mxfs_auth_epoch;	/* gres.grant_epoch stamped by the granting CAS */
	uint32_t		i_mxfs_auth_incarn;	/* i_generation the tenure was installed under */
	uint32_t		i_mxfs_auth_line;	/* __LINE__ of the last state change (forensics) */
	/*
	 * sess105 — THE LAST INSTALL ATTEMPT.
	 *
	 * i_mxfs_auth_line records the last SUCCESSFUL transition, which is
	 * precisely what a broken inode does NOT have: a failed install does
	 * not transition, so `line` only ever names where NONE was
	 * established (in practice the mode-lowering backstop).  It cannot say
	 * why the next write grant failed to install.  The sess104 RULE-5
	 * ruling named this as the one piece of persistent instrumentation
	 * worth adding, and it answers the whole classification table:
	 *
	 *   try == NONE                  no install was EVER attempted here
	 *   try_gen  < i_mxfs_auth_gen   a revoke happened AFTER the last
	 *                                attempt and nothing retried — a
	 *                                MISSING CALL/EVENT
	 *   try_gen == i_mxfs_auth_gen   the attempt is the most recent
	 *                                authority event; `try` says why it
	 *                                was refused, and try_mode/try_epoch
	 *                                carry the slot snapshot it saw
	 *
	 * Written under i_dlm_lock with the rest of the block; read under
	 * i_flags_lock at the dirty point, so both are one coherent image.
	 */
	uint8_t			i_mxfs_auth_try;	/* enum mxfs_auth_try */
	uint8_t			i_mxfs_auth_try_mode;	/* gres.mode the attempt offered */
	uint32_t		i_mxfs_auth_try_line;	/* __LINE__ of the attempt */
	uint64_t		i_mxfs_auth_try_epoch;	/* gres.grant_epoch offered */
	uint64_t		i_mxfs_auth_try_gen;	/* i_mxfs_auth_gen at attempt time */
	/*
	 * ccloop c7ee71c6 sess22 (P197) — WALL CLOCK for the dirtying above.
	 *
	 * P6-MIDTENURE-RELOAD-SKIP refuses a reload on the strength of
	 * `dirty_seq == ex_grant_seq`, which it reads as "this dir was modified
	 * under the CURRENT EX tenure, therefore no peer can have written since
	 * the tenure began".  That inference is only sound if ex_grant_seq is
	 * genuinely re-stamped on every re-entry into EX.  The silent-mkdir-loss
	 * trace (ROUND 29) shows P6 skipping with an EMPTY shortform base while
	 * the platter already held a peer-converted 32-entry BLOCK dir — which
	 * cannot happen inside one uninterrupted EX tenure.  So either the
	 * tenure was interrupted (a lost/stolen grant) or the stamp was carried
	 * over.  Comparing this timestamp against i_dlm_ex_acquire_ns settles it
	 * with one number: a dirtying OLDER than the current tenure's acquire
	 * proves P6's premise false.  Memory-only, set under ILOCK_EXCL beside
	 * dirty_seq, read only by probes.
	 */
	uint64_t		i_mxfs_dirty_ns;
	struct task_struct	*i_dlm_demoter;	/* thread inside bast_process for this inode (or NULL) */
	pid_t			i_dlm_demoter_pid;	/* sess5: leak forensics — stamped at every demoter set */
	char			i_dlm_demoter_comm[16];
	u64			i_dlm_demoter_set_ns;
	int			i_dlm_demoter_line;
	/*
	 * sess25: nesting depth of the demoter claim, owned exclusively by
	 * i_dlm_demoter (only the claiming task ever reads or writes it), so a
	 * plain int needs no additional synchronisation.  Exists because the
	 * claim is legitimately re-entered: a drain can re-enter the inode
	 * lock, and the release paths call each other.
	 */
	int			i_dlm_demoter_depth;
	/*
	 * sess25: SECOND claim slot.  One slot was not enough and the reason is
	 * measured, not guessed: making the single slot un-stealable fixed the
	 * self-wedge but REGRESSED crash_consistency from PASS 74s to FAIL at
	 * its 90s budget (same build, A/B'd via mxfs.demoter_legacy_clobber),
	 * because a refused claimant still ran its drain and every nested
	 * xfs_ilock it took then parked in the demote-wait for the 3s poll
	 * instead of being exempt.  Two concurrent drains on one inode is the
	 * measured reality (72 contests in one 32-node run, bast_work_fn vs
	 * bast_dwork_fn), so give it two slots: BOTH drains stay exempt, and
	 * each clears only its OWN slot, so neither can strand the other.
	 */
	struct task_struct	*i_dlm_demoter2;
	int			i_dlm_demoter2_depth;
	/*
	 * ccloop c7ee71c6 sess29 — SLOT 2 HAD NO FORENSICS AT ALL, and that
	 * made the only instrument aimed at the stranded-claim defect
	 * AMBIGUOUS.  mxfs_foreign_demoter() is true when EITHER slot is set,
	 * but P34J-RELOAD-DEMOTE-BAIL printed only i_dlm_demoter_pid/comm/line
	 * — slot 1's stamps, which are left behind by the last slot-1 claim
	 * even after that claim has been cleared.  So a strand in SLOT 2 was
	 * indistinguishable from a strand in slot 1, and it reported the wrong
	 * claim site.
	 *
	 * MEASURED CONTRADICTION that exposed this: test23 showed 224 bails,
	 * every one printing demoter_line=34955 (mxfs_inode_dlm_defer_bast),
	 * whose only unpaired exit is the P152-TRANSDRAIN-PUNT — and that node
	 * logged P152 ZERO times, while three nodes that DID punt showed 0 or 1
	 * bail.  The printed site could not have been the strand.
	 *
	 * Stamped in the slot-2 branches of MXFS_SET_DEMOTER exactly as slot 1
	 * is, so the bail can name the slot that is actually holding.
	 */
	pid_t			i_dlm_demoter2_pid;
	char			i_dlm_demoter2_comm[16];
	u64			i_dlm_demoter2_set_ns;
	int			i_dlm_demoter2_line;
	/*
	 * ccloop c7ee71c6 sess29 — ROOT FIX for D-MOUNT-DEGRADES-WITH-USE's
	 * remaining component: THE ONLY DEMOTER CLAIM THAT OUTLIVES ITS OWN
	 * CRITICAL SECTION.
	 *
	 * Every other claim in the tree is SET and CLEARed inside one function
	 * (spans of 6-75 lines).  mxfs_inode_dlm_defer_bast claims at
	 * xfs_mxfs_dlm.c:34955 and relies on mxfs_trans_drain_inode_unlocks to
	 * clear it 127 lines later, in a DIFFERENT function — and that drain has
	 * exactly one exit that skips the clear: the P152-TRANSDRAIN-PUNT, which
	 * deliberately retains the claim so the committing task keeps its
	 * exemption across its post-commit xfs_iunlock, then hands the release to
	 * the dwork.  Nothing ever released it again: the dwork's own
	 * MXFS_SET_DEMOTER cmpxchgs slot 1, finds the syscall task still there,
	 * lands in slot 2, and its trailing clear releases slot 2 only.
	 *
	 * PROVEN on sustained_load's 32-node stragglers: 224 and 354
	 * P34J-RELOAD-DEMOTE-BAILs on a SINGLE inode with a SINGLE
	 * demoter_pid, demoter_line=34955, demoter_comm=mkdir,
	 * demoter_age_ms=179907 (the whole run) and /proc/<pid> already gone,
	 * while healthy nodes showed exactly ONE bail at line 16541 with
	 * age_ms~150.  mxfs_foreign_demoter() then stays true for the life of the
	 * in-core inode, so EVERY reload of it pays mxfs.reload_demote_wait_ms
	 * and abandons the reload with i_dlm_stale still set.
	 *
	 * These two fields bound that retention instead of removing it (removing
	 * it would drop the exemption the punt exists to preserve): the punt
	 * records WHICH slot it retained and WHEN, and
	 * mxfs_demoter_punt_reclaim_check() releases it once the window it covers
	 * has provably closed — the retaining task no longer owns ILOCK-EXCL on
	 * this inode and the claim is older than mxfs.demoter_punt_grace_ms.
	 *
	 * bit 0 = slot 1 (i_dlm_demoter) retained, bit 1 = slot 2.
	 *
	 * i_dlm_punt_n is the COUNT of retained acquisitions per slot, and it is
	 * the field the release actually consumes.  A bit cannot express this:
	 * the claim nests (MXFS_SET_DEMOTER increments depth when the caller
	 * already owns the slot), and one transaction can defer the SAME inode
	 * more than once (P130-DEFERBAST-DUP is a real, logged shape), so two
	 * entries of one drain can BOTH punt.  With a bit, the single clear at
	 * the end of the retention window would only decrement depth and leave
	 * the second acquisition stranded — the very defect this code fixes,
	 * one nesting level down.  Counted, the release undoes exactly as many
	 * as the punt retained.
	 */
	uint8_t			i_dlm_demoter_punt;
	uint8_t			i_dlm_punt_n[2];
	u64			i_dlm_demoter_punt_ns;
	/*
	 * sess29: this inode has already been named by P214-DEMOTER-STRANDED.
	 * A strand causes hundreds of bails; without this the one line that
	 * identifies it is indistinguishable from the flood it causes, and
	 * pr_warn_ratelimited would drop it as readily as any other.
	 */
	bool			i_dlm_strand_named;
	/*
	 * sess25 (D-BAST-IRELE-INACTIVE-SELF-WEDGE): demoter claim/clear ring.
	 *
	 * i_dlm_demoter is a single non-nestable task pointer shared by every
	 * release path (bast_work_fn, bast_dwork_fn, the orphan reclaim, the
	 * EDEADLK self-demote).  A permanent wedge was captured on 3 of 32
	 * nodes where mxfs_dlm_bast_work_fn's OWN trailing xfs_irele cascaded
	 * into inactivation, re-took the inode lock, and parked in the
	 * demote-wait -- which can only happen if the claim it was holding was
	 * no longer == current.  A point-in-time snapshot cannot say who
	 * erased it: NULL destroys exactly the information needed.  Two
	 * candidate clobberers were refuted by their own probes firing ZERO
	 * times (P72-DEMOTER-OVERRIDE, P60-EDEADLK-FREEING), so the remaining
	 * one has no probe at all.
	 *
	 * This records every SET and CLEAR with its source line, the task that
	 * did it, and a monotonic cookie, so the sequence
	 *   SET(line=A,pid=X) ... CLEAR(line=B,pid=Y) ... WAIT(pid=X)
	 * reads the culprit off the ring instead of inferring it.  Lock-free
	 * on purpose: this is forensics, and a scrambled entry under a race is
	 * far cheaper than serialising every release path.
	 */
#define MXFS_DEMEV_N	12
	uint32_t		i_dlm_demev_line[MXFS_DEMEV_N];
	pid_t			i_dlm_demev_pid[MXFS_DEMEV_N];
	uint32_t		i_dlm_demev_cookie[MXFS_DEMEV_N];
	uint8_t			i_dlm_demev_op[MXFS_DEMEV_N];	/* 0=SET 1=CLEAR 2=WAIT-ENTER */
	uint8_t			i_dlm_demev_state[MXFS_DEMEV_N];
	uint8_t			i_dlm_demev_head;
	/*
	 * sess26: the A/B knob `demoter_legacy_clobber` reproduces the pre-fix
	 * unconditional store so the wedge can be re-armed on ONE build.  But
	 * the arm needs its own EXPOSURE measure: "legacy armed + no wedge" is
	 * uninformative unless we know a live claim was actually stolen.  So
	 * the legacy store records WHOSE claim it destroyed here, and the
	 * demote-wait reports when the parking task is that victim — which is
	 * the exact wedge precondition, named rather than inferred.
	 */
	pid_t			i_dlm_clobber_victim_pid;
	uint32_t		i_dlm_clobber_victim_line;
	/*
	 * sess26 H4: how many times in a row P6-MIDTENURE-RELOAD-SKIP has
	 * cleared this inode's i_dlm_stale WITHOUT reloading.  Reset by a real
	 * reload completion and at inode init, so a high value means the
	 * staleness is being set and skip-cleared repeatedly with no re-read in
	 * between -- a staleness LIVELOCK, in which this node never observes a
	 * peer's published state.  A differential named this path at 17.4x on a
	 * node that durably lost 8 dirents, and in one sample a single inode was
	 * 19 of 44 skips, which is what this counts properly.
	 */
	uint16_t		i_dlm_p6skip_n;
	pid_t			i_dlm_acq_pid;	/* ccloop-4dd7 sess3: ISTATE_ACQUIRING setter forensics — stamped at the (single) ACQUIRING set site in mxfs_dlm_ilock_begin.  b54r1 dir 131 sat in ACQUIRING 184s with zero local holders and no live acquirer anywhere on the node; every peer BAST was deferred to an acquire-completion that no longer existed -> peer -110 -> dirty-cancel shutdown.  These name the leaker on the next firing. */
	char			i_dlm_acq_comm[16];
	u64			i_dlm_acq_set_ns;
	uint16_t		i_dlm_acq_strikes; /* consecutive bast_notify ACQUIRING-deferrals observed with i_dlm_acq_inflight==0.  A live slow-path acquirer ALWAYS holds inflight>=1 (bumped before ACQUIRING is set, dropped at every exit, all under i_dlm_lock), so ACQUIRING+inflight==0 is a leaked state: nothing will ever honor the deferred BAST.  At the strike threshold the notify path reclaims via DEMOTING + bast_process (same machinery as P-DEMWAIT-REDRIVE). */
	pid_t			i_dlm_exh_pid;	/* ccloop-4dd7 sess4: EX-admission holder forensics — stamped at every i_dlm_ex_holders 0->1 transition (all under i_dlm_lock).  b58r1: both nodes -110'd after 184s with a single live rm holding an EX admission (ex=1) the whole stall, blocked on something invisible to the DLM probes (cleared only by the shutdown).  P36-MHT-REARM prints these and dumps the holder's kernel stack at sustained-refusal strike thresholds, so the blocked holder names itself and its wait site on the next occurrence. */
	char			i_dlm_exh_comm[16];
	u64			i_dlm_exh_since_ns;
	bool			i_mxfs_reused_create; /* v0.5.4 (sess24 ccloop 14d31183): this CREATE reused an in-core incarnation (xfs_iget cache HIT with XFS_IGET_CREATE -> mxfs_dlm_rearm_unpublished).  Peers may still hold stale dcache/icache references to this inode NUMBER from the prior incarnation and can therefore name it -- and cleanly acquire its empty CAW slot -- without first reading our new parent dirent.  While i_dlm_unpublished, this keeps the synchronous sess107 unpublished-dir-EX backstop in mxfs_dlm_ilock_begin armed; FRESH cache-miss creates (mxfs_dlm_grant_local_new clears this) skip the backstop because no peer can name a never-before-used ino faster than the pre-commit async publish worker claims its slot (mxfs_dlm_publish_dirs_work, ~1 ms): dirent paths transit a lock we hold (BAST publishes the unpub list before release) and a lookup-iget of our not-yet-flushed dinode reads FREE on disk and bails ENOENT without any slot acquire. */
	uint64_t		i_mxfs_iget_ns;      /* sess3 (ccloop 46efd8b6): ktime_get_ns at mxfs inode-DLM field init (== iget construction).  Printed by P14-DABUF-HOLE as iget_age_ms — a tiny age at a hole proves the cold-iget-adopts-lagging-home mechanism (dir inode evicted, re-igot from a mid-tenure-lagging home image, walked with newer cached structure). */
	uint64_t		i_mxfs_lastrel_ns;   /* sess10(a9a03929) RULE-4 last-release ledger: ktime_get_real_ns at the end of the most recent release-path __mxfs_dlm_dir_inode_durable decision for this dir (bast_process sd stage or per-op wrapper).  Printed by P-SFDIR-REVERT so a platter-lags-commit event shows when the last durable-at-release ran relative to the stale reload.  0 = never. */
	uint64_t		i_mxfs_lastrel_size; /* sess10: i_disk_size at that decision point. */
	uint32_t		i_mxfs_lastrel_flag; /* sess10: 1=durable helper RAN, 2=SKIPPED by the pr_release_fast clean-release gate, 3=helper ran but self-guard bailed (not LOCAL handled elsewhere/…).  0 = never. */
	bool			i_mxfs_self_created; /* v0.5.4 (sess23 ccloop 14d31183): this inode was CREATED by this node this mount and no peer BAST has arrived for it.  Gates the per-mkdir shortform-parent cluster-durability barrier in xfs_create (mxfs_dlm_dir_inode_durable): a dir we created ourselves with zero observed peer interest cannot be mid-cold-read by a coordinated peer (peers reach it only through a shared ancestor, whose own barrier fired, or by taking its DLM lock — which BASTs us and clears this flag before the release-path flush).  Cleared on any peer BAST (mxfs_dlm_bast_notify); false for every inode igot from disk, so pre-existing/shared dirs always keep the barrier. */

	/*
	 * sess14 (ccloop c7ee71c6) D3 RESIDUAL — publication obligation.
	 * GPT RULE-5 design (memories sess14-D/H/J), the replacement for four
	 * REFUTED local write-path predicates.  The invariant to enforce:
	 *
	 *   a release drain may report success ONLY when every committed
	 *   change is durable at the home location; otherwise it must submit,
	 *   and a drain that cannot land must FAIL THE HANDOFF (bounded retry,
	 *   then fence/withdraw) — never release the grant silently.
	 *
	 * pub_pending_seq: bumped once per COMMITTED dirop/inode-core change.
	 * pub_durable_seq: advanced ONLY on confirmed home-location write
	 *                  completion for this inode's slot.
	 * Obligation outstanding  <=>  pub_pending_seq != pub_durable_seq.
	 *
	 * These MUST be maintained independently of XFS dirty state
	 * (ili_fields / XFS_LI_DIRTY / AIL membership) — the proven failure is
	 * that all of those read "clean" while a committed change sits only in
	 * the log, which is exactly how the drain came to print
	 * "flushed=1 wrote=0 rerr=-11" and then release (P146-RELDUR,
	 * tests/logs/firstcc_205730).
	 *
	 * DO NOT substitute i_mxfs_dirty_seq: despite the name it is a TENURE
	 * STAMP (value of i_mxfs_ex_grant_seq when last dirtied under EX), so
	 * it can only say "dirtied in a previous tenure" — it cannot express
	 * "N changes committed, M landed".
	 *
	 * Wiring order for the implementer: (1) bump pending at dirop commit;
	 * (2) advance durable at the confirmed-write point in the release
	 * drain and in xfs_iflush's completion path; (3) gate the drain's
	 * EAGAIN/clean-skip success return on pending == durable; (4) only
	 * then may the write-side guards revert to pure assertions.
	 *
	 * sess18 (ccloop c7ee71c6) COMPLETES step (2).  sess14 advanced durable
	 * ONLY at the release drain's own xfs_bwrite, which made the predicate a
	 * gross OVER-approximation: every inode landed by ANY other flush path
	 * (xfsaild, reclaim, sync, a co-resident cluster write) kept reading
	 * "obligation open" forever, because nothing else ever moved durable.
	 * That is why P176 fired 116x in a PASSING run — most of those were
	 * inodes that were perfectly durable, just landed by xfsaild.  With
	 * enforcement on, that over-approximation turns into a re-log storm at
	 * every release (RULE 0 hazard) and can re-publish a prior-tenure image.
	 *
	 * pub_flush_seq closes it: xfs_iflush snapshots pending at copy-in (the
	 * image now in the buffer carries every change up to that value), and
	 * the buffer's SUCCESS completion (xfs_iflush_finish, reached only when
	 * b_error is clear) advances durable to it.  That covers every flush
	 * path with one rule, and it is conservative in the safe direction: the
	 * snapshot is taken before the copy, so durable can only ever LAG the
	 * true durable state — an obligation may linger (false "open", costs a
	 * retry) but a change that never landed can never be marked durable.
	 */
	uint64_t		i_mxfs_pub_pending_seq;
	uint64_t		i_mxfs_pub_durable_seq;
	uint64_t		i_mxfs_pub_flush_seq;

	/*
	 * ccloop c7ee71c6 sess30 — STAGING TENURE STAMP, for GPT RULE-5 review
	 * item 2 on D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY: "logged this
	 * round" proves a JOURNAL representation, not authority to publish to
	 * HOME.
	 *
	 * xfs_iflush copies the in-core image into the cluster buffer under
	 * whatever tenure it then holds; the buffer is SUBMITTED much later by
	 * xfsaild.  Between those two points the grant can be BASTed away and a
	 * peer can take EX and publish.  Our staged bytes then land on top of
	 * the peer's — and every authority guard at the write site treats the
	 * slot as "logged, therefore ours to write".
	 *
	 * i_dlm_epoch is bumped on every grant loss / stale mark, so a stamp
	 * taken at copy-in and compared at submit answers "did we still hold the
	 * tenure the bytes were staged under?" with one 64-bit compare, no DLM
	 * query and no I/O — which matters because the compare happens inside
	 * pag_ici_lock, where the blocking held-query would sleep (sess20).
	 *
	 * The inode FLUSH LOCK is held from xfs_iflush until the buffer's
	 * iodone, so exactly one staging is outstanding at a time and the stamp
	 * cannot be overwritten under a live buffer.
	 */
	unsigned long		i_mxfs_pub_stage_epoch;
	uint8_t			i_mxfs_pub_stage_mode;
	/*
	 * CLOCK_REALTIME at copy-in.  The cross-node merge needs DIRECTION, not
	 * just difference: two publishes of one ino with different di_gen tails
	 * prove different incarnations but not which is older (a chunk-init gen
	 * is random, so the tails are not comparable).  With this, a peer
	 * publish that falls strictly BETWEEN our copy-in and our submit is
	 * provably newer than the bytes we are about to write, so our write is
	 * a revert and not a legitimate newer incarnation.
	 */
	uint64_t		i_mxfs_pub_stage_ns;
	uint8_t			i_mxfs_pipe_relog; /* sess33: the release pipeline's own
			 * tiny re-log transaction (P146V clean-but-unlanded arm,
			 * P182 relmerge arm) is in flight on this inode.  Gates
			 * the P234-LOG-NOEX source counter: those two arms
			 * legitimately stamp an obligation at NL from INSIDE the
			 * pipeline (which then lands it before the unlock —
			 * obligation=0 at every unlock proves it), so counting
			 * them would keep the criterion-3 tripwire permanently
			 * nonzero.  Set/cleared around the two call sites only;
			 * a racing foreign mutation during that µs window is
			 * missed by the tripwire but still covered by the
			 * pipeline's own drain. */
	/*
	 * sess32 P229 detection: nonzero (ns timestamp) while an
	 * xfs_ilock_nowait acquisition entered through the ilock_try
	 * preempt_count()>0 arm, which BYPASSES the DLM (no DEMOTING gate, no
	 * holder count).  EX is REFUSED there since 0.11.285 (an EX bypass
	 * would be an uncoordinated writer and its ilock_end decrement eats a
	 * concurrent holder's count); the stamp marks surviving PR bypasses so
	 * xfs_trans_log_inode can catch the log-under-read-bypass anomaly
	 * (P230); cleared at ilock_end.  Racy by design — detection only.
	 */
	uint64_t		i_mxfs_atomic_bypass_ns;
	/*
	 * sess30: __LINE__ of the site that last bumped i_dlm_epoch (= the
	 * release/stale path that ENDED the tenure).  i_dlm_epoch is bumped
	 * from nine different places; knowing the tenure was lost is not
	 * actionable until the leaking path is named.
	 */
	uint16_t		i_dlm_epoch_src;

	/*
	 * ccloop c7ee71c6 sess20 (P186) — highest di_nlink this node has ever
	 * OBSERVED on the platter for the CURRENT incarnation of this inode,
	 * plus the incarnation it belongs to.  A directory's link count only
	 * grows while children are being created, so an outgoing dinode image
	 * whose di_nlink is BELOW a value we have already seen durable is a
	 * provable durable revert — the "link bump lost, dirent kept" shape
	 * that dominates the sf_mkdir_storm failures (137 of 455 checks, and 0
	 * of the opposite shape).  Pure in-memory: stamped wherever a platter
	 * dinode is already in hand, compared at the publish site.  No extra
	 * I/O, no lock, and specifically NOTHING added to the release drain,
	 * whose latency this defect family is measurably sensitive to.
	 */
	uint32_t		i_mxfs_disk_nlink_seen;
	uint32_t		i_mxfs_disk_nlink_gen;

	uint32_t		i_mxfs_dead_incarn_gen; /* sess14 (ccloop c7ee71c6) D3 ROOT FIX: the di_gen of a NEWER on-disk incarnation of this ino, recorded when a reload dirent-validated a genuine type-flip (RELOAD-TYPEFLIP-DIRENT-OK: disk+parent-dirent agree the number was freed and reused) but had to bail because a release drain raced it (P34J-RELOAD-RACE-BAIL).  While set, this in-core object is a DEAD PRIOR INCARNATION: the drain's clean-but-unlanded re-log (P146V) and xfs_iflush MUST NOT write its core over the peer's live slot (the proven ino-167 cluster clobber: stale storm-dir dinode re-logged at NL and iflush_cluster'd over the peer's current file — 22/32 nodes lost the rename).  Cleared when a reload successfully adopts the disk incarnation, and at init. */

	/* sess132 (RULE 4): ILOCK last-locker forensics for the 16-node
	 * create-storm wedge — a bast_process drain blocked forever on
	 * i_lock with NO live holder (leaked ILOCK).  Records the most
	 * recent EXCL and SHARED takers + a shared-hold counter so the
	 * stuck-drain probe can name the leaking call path. */
	atomic_t		i_mxfs_ilk_rd_held; /* outstanding ILOCK_SHARED holds */
	atomic_t		i_mxfs_ilk_wr_held; /* sess33 (ccloop c7ee71c6) writer-quiescence census:
			 * outstanding ILOCK_EXCL holds taken through xfs_ilock /
			 * xfs_ilock_nowait ONLY (inc open-coded at those two
			 * sites, post-acquisition; dec in mxfs_ilk_note_unlock,
			 * whose only callers release xfs_ilock-taken locks).
			 * The mxfs-internal RAW down_write sites (reload path)
			 * deliberately do NOT count: they note_lock for
			 * forensics but release via raw up_write, and they
			 * never stamp the publication ledger concurrently with
			 * the release pipeline (same-thread ordering).
			 * mxfs_relbar_close_or_defer waits (bounded) for this
			 * to reach 0 before its durable passes: pend++ at
			 * xfs_trans_log_inode happens under ILOCK_EXCL and CIL
			 * insertion completes before the holder's dec, so
			 * observing 0 means every finished mutator's commit is
			 * log_force-capturable.  0 is an observation, not a
			 * stable state (a writer QUEUED in down_write has not
			 * inc'd yet); the defer/requeue backstop remains the
			 * safety mechanism — this only buys convergence
			 * without the .282 reader-convoy (never touches the
			 * rwsem, so readdir's ILOCK_SHARED is never waited on
			 * or blocked). */
	unsigned long		i_mxfs_ilk_wr_ret;  /* last EXCL locker caller IP */
	unsigned long		i_mxfs_ilk_rd_ret;  /* last SHARED locker caller IP */
	unsigned long		i_mxfs_ilk_un_ret;  /* last iunlock caller IP */
	pid_t			i_mxfs_ilk_wr_pid;
	pid_t			i_mxfs_ilk_rd_pid;
	char			i_mxfs_ilk_wr_comm[16];
	char			i_mxfs_ilk_rd_comm[16];

	/* VFS inode */
	struct inode		i_vnode;	/* embedded VFS inode */

	/* pending io completions */
	spinlock_t		i_ioend_lock;
	struct work_struct	i_ioend_work;
	struct list_head	i_ioend_list;

	/*
	 * ccloop c7ee71c6 sess23 — D-UNMOUNT-BUSY-INODES leak detector.
	 *
	 * `kmem_cache_destroy mxfs_inode: Slab cache still has objects` at rmmod
	 * reports "objects=18 used=1": exactly ONE xfs_inode outlives the last
	 * unmount, so the cache cannot be destroyed and the next insmod runs
	 * against a stale cache (use-after-free hazard).  P199 dumps the ICI
	 * radix tree at xfs_kill_sb, but that runs BEFORE generic_shutdown_super
	 * does shrink_dcache_for_umount + evict_inodes, so its census is of
	 * inodes that are about to be evicted normally — it cannot name the one
	 * that survives.  This link puts every allocated xfs_inode on a global
	 * list that outlives the mount, so xfs_destroy_caches() can name the
	 * survivor(s) with full state at the exact moment the slab warn fires.
	 */
	struct list_head	i_mxfs_live_link;
	unsigned long		i_mxfs_alloc_jiffies;
	/*
	 * sess23: attribution for the leaked reference.  Every igrab() inside
	 * an MXFS translation unit self-tags with its own __LINE__ (see the
	 * mxfs_igrab_tracked wrapper below and the per-file #define), so P202
	 * names the exact source line that took the reference that was never
	 * dropped.  file: 1=xfs_mxfs_dlm.c 2=xfs_icache.c 3=pal/linux/xfs_iops.c
	 * 4=xfs_filestream.c 5=xfs_mxfs_dentry.c.
	 */
	unsigned int		i_mxfs_grab_line;
	unsigned char		i_mxfs_grab_file;
	/*
	 * sess26: TRACKED-vs-UNTRACKED reference balance (P205-REFBAL).
	 *
	 * P203-LEVEL names the grab occupying each refcount level, but it is
	 * only sound under LIFO release order: if grab A takes 0->1 and B takes
	 * 1->2 and A releases first, the survivor is B's while LEVEL[1] still
	 * names A.  So it cannot prove WHO leaked.
	 *
	 * A per-SITE balance cannot work either, because mxfs_iput_tracked tags
	 * the RELEASE site and a reference legitimately crosses sites between
	 * grab and release.
	 *
	 * What IS decidable is whether the surviving reference travelled through
	 * a tracked igrab at all.  These count every tracked grab and every
	 * tracked release on this inode, so at unmount:
	 *   tgrabs - tputs == icount  -> the survivor came through mxfs_igrab_
	 *                                tracked, i.e. an MXFS path holds it
	 *   tgrabs - tputs == 0       -> the survivor came from an UNTRACKED
	 *                                grab (xfs_iget) whose matching plain
	 *                                iput never happened -- which points at
	 *                                the lookup/VFS handoff, not at MXFS's
	 *                                own igrab sites.
	 * That single bit decides which half of the code to search, and it does
	 * not depend on release ORDER at all.
	 */
	uint16_t		i_mxfs_tgrabs;
	uint16_t		i_mxfs_tputs;
	/*
	 * sess23: return address of the LAST caller of xfs_iget() that walked
	 * away with a reference on this inode.  The igrab line alone resolves
	 * to xfs_iget_cache_hit(), which is upstream's ordinary cache-hit grab
	 * and names nothing — the leak is a CALLER that never paired its iget
	 * with an xfs_irele.  P202 prints this with %pS.
	 */
	unsigned long		i_mxfs_iget_ret;
	/*
	 * sess23 H2 causal-link probe.  Stamped when P34J-RELOAD-RACE-BAIL
	 * ABANDONS a reload ("caller retries post-drain" — a promise that was
	 * never implemented for the DEMOTE flavour, which sess22 proved is how
	 * i_dlm_dir_valid_epoch is left behind and P32E then fences away every
	 * later flush).  P32E prints the age of this stamp so the chain
	 * race-bail -> fenced flush -> lost dirent can be established with a
	 * number instead of assumed.  0 = this inode has never race-bailed.
	 */
	u64			i_mxfs_racebail_ns;
	/*
	 * sess23: reference-event ring.  Every xfs_iget() that hands out a
	 * reference, every xfs_irele(), and every igrab()/iput() inside a
	 * tagged MXFS translation unit records (who, grab/release, resulting
	 * i_count) here.  P202 replays it for the inode that survived unmount,
	 * so the UNMATCHED grab is read off the ring instead of guessed at.
	 * Deliberately lock-free: this is forensics, and a scrambled entry
	 * under a race is far cheaper than serialising the iget/irele path.
	 */
	/*
	 * sess25 (D-BAST-WRITEBACK-ABBA-DEADLOCK): which folio-lock-taking
	 * flush the release drain is currently inside.  mxfs_dlm_bast_process
	 * calls filemap_write_and_wait TWICE and the two are NOT equivalent:
	 *
	 *   site 1 — the early page flush, run while i_dlm_mode is STILL the
	 *            granted mode.  A concurrent writeback submitter asking
	 *            for ILOCK_SHARED is satisfied by the nest-admit fast path
	 *            (i_dlm_mode >= request) and never reaches the demote-wait,
	 *            so this site cannot form the ABBA cycle.
	 *   site 2 — the S_ISREG durability flush, run AFTER
	 *            `ip->i_dlm_mode = MXFS_LOCK_NL` and BEFORE the on-disk
	 *            unlock.  Here mode==NL fails every nest-admit, so a
	 *            writeback submitter holding a folio lock parks in the
	 *            demote-wait, and this drain then blocks on that folio.
	 *            THIS is the site of the captured deadlock.
	 *
	 * 0 = not in a drain flush.  Printed by P47-FILEBLOCK so a blocked
	 * submitter names the drain phase it collided with, and used by the
	 * fix28 verification injection to target site 2 deterministically.
	 */
	unsigned char		i_dlm_drain_site;
	/* fix28 verification injection: the drain-side stall fires at most once
	 * per bast_process, not once per folio.  Cleared when drain_site is set
	 * to 2, set by the injection.  Debug-only; unused when fix28 is off. */
	unsigned char		i_dlm_drain_stalled;
#define MXFS_REFEV_N	10
	unsigned long		i_mxfs_refev_ip[MXFS_REFEV_N];
	unsigned char		i_mxfs_refev_kind[MXFS_REFEV_N]; /* 0=rele 1=grab(ip) 2=grab(file:line) 3=rele(file:line) */
	unsigned char		i_mxfs_refev_cnt[MXFS_REFEV_N];
	unsigned char		i_mxfs_refev_head;
	/* sess25: outstanding-grab stack — see mxfs_refev_rec(). */
#define MXFS_GRABST_N	16
	unsigned long		i_mxfs_grabst[MXFS_GRABST_N];
	unsigned char		i_mxfs_grabst_kind[MXFS_GRABST_N];
	unsigned char		i_mxfs_grabst_over;
	/*
	 * ccloop c7ee71c6 sess27 (D-UNMOUNT-BUSY-INODES), from the RULE-5 GPT
	 * consult.  An inode joins the inode LRU ONLY at i_count==0 — verified
	 * in /src/linux/fs/inode.c, __inode_lru_list_add() returns early
	 * `if (icount_read(inode))`.  The leaked inode is ALWAYS lru_linked=1
	 * with icount=1, so it provably passed through zero and the surviving
	 * reference belongs to a NEW busy tenure opened after that.
	 *
	 * xfs_fs_drop_inode() is called from iput_final() exactly at the zero
	 * transition, so the filesystem CAN observe it.  Bumping the tenure and
	 * clearing the grab table there scopes i_mxfs_grabst[] to the FINAL
	 * tenure alone — which removes the LIFO-ordering assumption that made
	 * the sess25/26 level table unsound, because the table then holds only
	 * this tenure's grabs.  With icount=1, slot 1 IS the outstanding
	 * reference.
	 *
	 * tenure_grabs==0 at unmount is itself decisive: it means NO
	 * MXFS-tracked site opened the final tenure, so the reference came from
	 * a VFS path (ihold/__iget) that a filesystem cannot hook — which,
	 * together with dentries=0, is a much narrower question than "who
	 * grabbed this inode, ever".
	 */
	uint32_t		i_mxfs_zero_seq;
	uint32_t		i_mxfs_tenure_grabs;
	unsigned long		i_mxfs_zero_jiffies;
} xfs_inode_t;

/* sess23: global live-xfs_inode registry — see i_mxfs_live_link above. */
extern spinlock_t		mxfs_live_inodes_lock;
extern struct list_head		mxfs_live_inodes;
extern int			mxfs_live_inode_track;
extern atomic64_t		mxfs_live_inode_allocs;
void mxfs_report_leaked_inodes(void);


static inline bool xfs_inode_on_unlinked_list(const struct xfs_inode *ip)
{
	return ip->i_prev_unlinked != 0;
}

static inline bool xfs_inode_has_attr_fork(const struct xfs_inode *ip)
{
	return ip->i_forkoff > 0;
}

static inline struct xfs_ifork *
xfs_ifork_ptr(
	struct xfs_inode	*ip,
	int			whichfork)
{
	switch (whichfork) {
	case XFS_DATA_FORK:
		return &ip->i_df;
	case XFS_ATTR_FORK:
		if (!xfs_inode_has_attr_fork(ip))
			return NULL;
		return &ip->i_af;
	case XFS_COW_FORK:
		return ip->i_cowfp;
	default:
		ASSERT(0);
		return NULL;
	}
}

static inline unsigned int xfs_inode_fork_boff(struct xfs_inode *ip)
{
	return ip->i_forkoff << 3;
}

static inline unsigned int xfs_inode_data_fork_size(struct xfs_inode *ip)
{
	if (xfs_inode_has_attr_fork(ip))
		return xfs_inode_fork_boff(ip);

	return XFS_LITINO(ip->i_mount);
}

static inline unsigned int xfs_inode_attr_fork_size(struct xfs_inode *ip)
{
	if (xfs_inode_has_attr_fork(ip))
		return XFS_LITINO(ip->i_mount) - xfs_inode_fork_boff(ip);
	return 0;
}

static inline unsigned int
xfs_inode_fork_size(
	struct xfs_inode	*ip,
	int			whichfork)
{
	switch (whichfork) {
	case XFS_DATA_FORK:
		return xfs_inode_data_fork_size(ip);
	case XFS_ATTR_FORK:
		return xfs_inode_attr_fork_size(ip);
	default:
		return 0;
	}
}

/* Convert from vfs inode to xfs inode */
static inline struct xfs_inode *XFS_I(struct inode *inode)
{
	return container_of(inode, struct xfs_inode, i_vnode);
}

/* convert from xfs inode to vfs inode */
static inline struct inode *VFS_I(struct xfs_inode *ip)
{
	return &ip->i_vnode;
}

/*
 * sess23 — igrab() call-site attribution (D-UNMOUNT-BUSY-INODES).
 *
 * An MXFS .c file that wants its igrab() calls attributed adds, AFTER its
 * includes:
 *      #define igrab(vi) mxfs_igrab_tracked((vi), __LINE__, <file-id>)
 * Every igrab in that file then records where it came from, and P202 prints
 * it for the inode that survived unmount.  Defined here (before any such
 * #define is in scope) so this wrapper itself still calls the real igrab.
 */
static inline void
mxfs_refev_rec(struct xfs_inode *ip, unsigned long who, unsigned char kind)
{
	unsigned char	h;

	if (!mxfs_live_inode_track)
		return;
	h = ip->i_mxfs_refev_head;
	if (h >= MXFS_REFEV_N)
		h = 0;
	ip->i_mxfs_refev_ip[h] = who;
	ip->i_mxfs_refev_kind[h] = kind;
	ip->i_mxfs_refev_cnt[h] =
		(unsigned char)atomic_read(&VFS_I(ip)->i_count);
	ip->i_mxfs_refev_head = (h + 1) % MXFS_REFEV_N;

	/*
	 * sess25 (D-UNMOUNT-BUSY-INODES): GRAB-BY-REFCOUNT-LEVEL table.
	 *
	 * The 10-entry ring above is a fixed HISTORY window and by unmount has
	 * wrapped many times over, which is why it never produced a capture
	 * despite being in the tree since sess23: a leak is an OLD grab with no
	 * matching release, and a history window structurally cannot hold it.
	 *
	 * A push/pop STACK was tried first and MEASURED WRONG: it saturated
	 * (depth=12 over=19 under=0 on the first real capture) because grabs
	 * are tracked but many releases are NOT — plain VFS iput() from dentry
	 * eviction never reaches any MXFS-tagged site, so pushes outnumber pops
	 * and the stack only grows.  Do not reinstate it.
	 *
	 * Instead, index by the refcount level the grab PRODUCED: the grab that
	 * took i_count to N is recorded in slot N.  At unmount the leaked inode
	 * has icount=1, so slot 1 names the grab holding that last reference.
	 * This is self-correcting — it never needs to observe a release, so
	 * untracked iput()s cannot desynchronise it; they merely leave stale
	 * entries in slots above the current count, which are ignored.
	 */
	if (kind == 1 || kind == 2) {
		unsigned char lvl =
			(unsigned char)atomic_read(&VFS_I(ip)->i_count);

		/* sess27: grabs are attributed to the CURRENT tenure only —
		 * mxfs_inode_tenure_reset() clears the table at every
		 * i_count->0 transition (see the field comments above). */
		ip->i_mxfs_tenure_grabs++;
		if (lvl >= 1 && lvl <= MXFS_GRABST_N) {
			ip->i_mxfs_grabst[lvl - 1] = who;
			ip->i_mxfs_grabst_kind[lvl - 1] = kind;
		} else {
			ip->i_mxfs_grabst_over++;
		}
	}
}

/*
 * sess27 — called from xfs_fs_drop_inode(), i.e. from iput_final() at the exact
 * instant i_count reaches 0.  Opens a new busy tenure: everything the old one
 * recorded is history and must not be attributed to the reference that survives
 * to unmount.  Deliberately NOT gated on mxfs_live_inode_track: if tracking is
 * toggled on mid-run, a stale pre-toggle table would be worse than an empty one.
 */
static inline void
mxfs_inode_tenure_reset(struct xfs_inode *ip)
{
	int	k;

	ip->i_mxfs_zero_seq++;
	ip->i_mxfs_tenure_grabs = 0;
	ip->i_mxfs_zero_jiffies = jiffies;
	ip->i_mxfs_grabst_over = 0;
	for (k = 0; k < MXFS_GRABST_N; k++) {
		ip->i_mxfs_grabst[k] = 0;
		ip->i_mxfs_grabst_kind[k] = 0;
	}
}

/* Pack a tagged file id + source line into the ring's "who" slot. */
#define MXFS_REFEV_SITE(file, line)	(((unsigned long)(file) << 32) | (line))

static inline struct inode *
mxfs_igrab_tracked(struct inode *vi, unsigned int line, unsigned char file)
{
	struct inode	*got;

	if (!vi)
		return NULL;		/* honour igrab()'s contract, NULL included */
	got = igrab(vi);
	if (got) {
		XFS_I(got)->i_mxfs_grab_line = line;
		XFS_I(got)->i_mxfs_grab_file = file;
		if (XFS_I(got)->i_mxfs_tgrabs < 0xffff)
			XFS_I(got)->i_mxfs_tgrabs++;
		mxfs_refev_rec(XFS_I(got), MXFS_REFEV_SITE(file, line), 2);
	}
	return got;
}

static inline void
mxfs_iput_tracked(struct inode *vi, unsigned int line, unsigned char file)
{
	/*
	 * iput(NULL) IS LEGAL — upstream's iput() returns early on NULL, and
	 * MXFS relies on that: mxfs_dlm_pr_sweep_work_fn's bail-out paths call
	 * iput(toput) where toput may never have been set.  Dereferencing
	 * before that check is a NULL deref, because XFS_I(NULL) is
	 * -offsetof(i_vnode), so the ring write lands at a tiny address.
	 *
	 * This cost a kernel panic on EVERY node at mount:
	 *   BUG: kernel NULL pointer dereference, address: 000000000000033c
	 *   Workqueue: mxfs-ino-bast/dm-1 mxfs_dlm_pr_sweep_work_fn [mxfs]
	 * The nodes rebooted, and since /src is deliberately not an fstab
	 * automount they came back without it — which then presented as a
	 * flapping TEST RIG (prep escalating and power-cycling forever) rather
	 * than as a bad build.  A wrapper must honour the wrapped function's
	 * contract exactly, NULL included.
	 */
	if (!vi)
		return;
	mxfs_refev_rec(XFS_I(vi), MXFS_REFEV_SITE(file, line), 3);
	/* sess26 P205-REFBAL: count BEFORE iput -- iput may free the inode, and
	 * touching it afterwards is a use-after-free. */
	if (XFS_I(vi)->i_mxfs_tputs < 0xffff)
		XFS_I(vi)->i_mxfs_tputs++;
	iput(vi);
}

/* convert from const xfs inode to const vfs inode */
static inline const struct inode *VFS_IC(const struct xfs_inode *ip)
{
	return &ip->i_vnode;
}

/*
 * For regular files we only update the on-disk filesize when actually
 * writing data back to disk.  Until then only the copy in the VFS inode
 * is uptodate.
 */
static inline xfs_fsize_t XFS_ISIZE(struct xfs_inode *ip)
{
	if (S_ISREG(VFS_I(ip)->i_mode))
		return i_size_read(VFS_I(ip));
	return ip->i_disk_size;
}

/*
 * If this I/O goes past the on-disk inode size update it unless it would
 * be past the current in-core inode size.
 */
static inline xfs_fsize_t
xfs_new_eof(struct xfs_inode *ip, xfs_fsize_t new_size)
{
	xfs_fsize_t i_size = i_size_read(VFS_I(ip));

	if (new_size > i_size || new_size < 0)
		new_size = i_size;
	return new_size > ip->i_disk_size ? new_size : 0;
}

/*
 * i_flags helper functions
 */
static inline void
__xfs_iflags_set(xfs_inode_t *ip, unsigned long flags)
{
	ip->i_flags |= flags;
}

static inline void
xfs_iflags_set(xfs_inode_t *ip, unsigned long flags)
{
	spin_lock(&ip->i_flags_lock);
	__xfs_iflags_set(ip, flags);
	spin_unlock(&ip->i_flags_lock);
}

static inline void
xfs_iflags_clear(xfs_inode_t *ip, unsigned long flags)
{
	spin_lock(&ip->i_flags_lock);
	ip->i_flags &= ~flags;
	spin_unlock(&ip->i_flags_lock);
}

static inline int
__xfs_iflags_test(const struct xfs_inode *ip, unsigned long flags)
{
	return (ip->i_flags & flags);
}

static inline int
xfs_iflags_test(xfs_inode_t *ip, unsigned long flags)
{
	int ret;
	spin_lock(&ip->i_flags_lock);
	ret = __xfs_iflags_test(ip, flags);
	spin_unlock(&ip->i_flags_lock);
	return ret;
}

static inline int
xfs_iflags_test_and_clear(xfs_inode_t *ip, unsigned long flags)
{
	int ret;

	spin_lock(&ip->i_flags_lock);
	ret = ip->i_flags & flags;
	if (ret)
		ip->i_flags &= ~flags;
	spin_unlock(&ip->i_flags_lock);
	return ret;
}

static inline int
xfs_iflags_test_and_set(xfs_inode_t *ip, unsigned long flags)
{
	int ret;

	spin_lock(&ip->i_flags_lock);
	ret = ip->i_flags & flags;
	if (!ret)
		ip->i_flags |= flags;
	spin_unlock(&ip->i_flags_lock);
	return ret;
}

static inline bool xfs_is_reflink_inode(const struct xfs_inode *ip)
{
	return ip->i_diflags2 & XFS_DIFLAG2_REFLINK;
}

static inline bool xfs_is_metadir_inode(const struct xfs_inode *ip)
{
	return ip->i_diflags2 & XFS_DIFLAG2_METADATA;
}

static inline bool xfs_is_internal_inode(const struct xfs_inode *ip)
{
	struct xfs_mount	*mp = ip->i_mount;

	/* Any file in the metadata directory tree is a metadata inode. */
	if (xfs_has_metadir(mp))
		return xfs_is_metadir_inode(ip);

	/*
	 * Before metadata directories, the only metadata inodes were the
	 * three quota files, the realtime bitmap, and the realtime summary.
	 */
	return ip->i_ino == mp->m_sb.sb_rbmino ||
	       ip->i_ino == mp->m_sb.sb_rsumino ||
	       xfs_is_quota_inode(&mp->m_sb, ip->i_ino);
}

static inline bool xfs_is_zoned_inode(const struct xfs_inode *ip)
{
	return xfs_has_zoned(ip->i_mount) && XFS_IS_REALTIME_INODE(ip);
}

bool xfs_is_always_cow_inode(const struct xfs_inode *ip);

static inline bool xfs_is_cow_inode(const struct xfs_inode *ip)
{
	return xfs_is_reflink_inode(ip) || xfs_is_always_cow_inode(ip);
}

static inline bool xfs_inode_has_filedata(const struct xfs_inode *ip)
{
	return ip->i_df.if_nextents > 0 || ip->i_delayed_blks > 0;
}

/*
 * Check if an inode has any data in the COW fork.  This might be often false
 * even for inodes with the reflink flag when there is no pending COW operation.
 */
static inline bool xfs_inode_has_cow_data(const struct xfs_inode *ip)
{
	return ip->i_cowfp && ip->i_cowfp->if_bytes;
}

static inline bool xfs_inode_has_bigtime(const struct xfs_inode *ip)
{
	return ip->i_diflags2 & XFS_DIFLAG2_BIGTIME;
}

static inline bool xfs_inode_has_large_extent_counts(const struct xfs_inode *ip)
{
	return ip->i_diflags2 & XFS_DIFLAG2_NREXT64;
}

/*
 * Decide if this file is a realtime file whose data allocation unit is larger
 * than a single filesystem block.
 */
static inline bool xfs_inode_has_bigrtalloc(const struct xfs_inode *ip)
{
	return XFS_IS_REALTIME_INODE(ip) && ip->i_mount->m_sb.sb_rextsize > 1;
}

/*
 * Return the buftarg used for data allocations on a given inode.
 */
#define xfs_inode_buftarg(ip) \
	(XFS_IS_REALTIME_INODE(ip) ? \
		(ip)->i_mount->m_rtdev_targp : (ip)->i_mount->m_ddev_targp)

static inline bool xfs_inode_can_hw_atomic_write(const struct xfs_inode *ip)
{
	if (IS_DAX(VFS_IC(ip)))
		return false;

	return xfs_inode_buftarg(ip)->bt_awu_max > 0;
}

static inline bool xfs_inode_can_sw_atomic_write(const struct xfs_inode *ip)
{
	if (IS_DAX(VFS_IC(ip)))
		return false;

	return xfs_can_sw_atomic_write(ip->i_mount);
}

/*
 * In-core inode flags.
 */
#define XFS_IRECLAIM		(1 << 0) /* started reclaiming this inode */
#define XFS_ISTALE		(1 << 1) /* inode has been staled */
#define XFS_IRECLAIMABLE	(1 << 2) /* inode can be reclaimed */
#define XFS_INEW		(1 << 3) /* inode has just been allocated */
#define XFS_IPRESERVE_DM_FIELDS	(1 << 4) /* has legacy DMAPI fields set */
#define XFS_ITRUNCATED		(1 << 5) /* truncated down so flush-on-close */
#define XFS_EOFBLOCKS_RELEASED	(1 << 6) /* eofblocks were freed in ->release */
#define XFS_IFLUSHING		(1 << 7) /* inode is being flushed */
#define __XFS_IPINNED_BIT	8	 /* wakeup key for zero pin count */
#define XFS_IPINNED		(1 << __XFS_IPINNED_BIT)
#define XFS_IEOFBLOCKS		(1 << 9) /* has the preallocblocks tag set */
#define XFS_NEED_INACTIVE	(1 << 10) /* see XFS_INACTIVATING below */
/*
 * If this unlinked inode is in the middle of recovery, don't let drop_inode
 * truncate and free the inode.  This can happen if we iget the inode during
 * log recovery to replay a bmap operation on the inode.
 */
#define XFS_IRECOVERY		(1 << 11)
#define XFS_ICOWBLOCKS		(1 << 12)/* has the cowblocks tag set */

/*
 * If we need to update on-disk metadata before this IRECLAIMABLE inode can be
 * freed, then NEED_INACTIVE will be set.  Once we start the updates, the
 * INACTIVATING bit will be set to keep iget away from this inode.  After the
 * inactivation completes, both flags will be cleared and the inode is a
 * plain old IRECLAIMABLE inode.
 */
#define XFS_INACTIVATING	(1 << 13)

/* Quotacheck is running but inode has not been added to quota counts. */
#define XFS_IQUOTAUNCHECKED	(1 << 14)

/*
 * Remap in progress. Callers that wish to update file data while
 * holding a shared IOLOCK or MMAPLOCK must drop the lock and retake
 * the lock in exclusive mode. Relocking the file will block until
 * IREMAPPING is cleared.
 */
#define XFS_IREMAPPING		(1U << 15)

/*
 * mxfs (sess55): a peer freed+reused this inode number while we held it
 * passively cached at NL (no DLM grant), so no BAST invalidated us.  The CAW
 * heartbeat-embedded evict-ring consumer sets this; a background workqueue then
 * does d_prune_aliases + xfs_irele to force the stale incarnation out — OUTSIDE
 * xfs_iget/ILOCK to avoid the xfsaild AIL-drain wedge.  The VFS staleness trap in
 * xfs_vn_lookup also checks it.  See notes/sess55_gemini_design.md.
 */
#define XFS_ISTALE_CAW		(1U << 16)

/*
 * mxfs (sess118): THIS node allocated this inode incarnation and has not yet
 * written it to its on-disk home block.  Set in xfs_init_new_inode (the only
 * site where this node creates a brand-new incarnation), cleared on the first
 * xfs_iflush that writes it.  The resurrection guard in xfs_iflush uses it to
 * tell a legitimate new-inode FIRST flush (FLAG set -> write, the on-disk slot
 * still holds the chunk-init/prior-free image so disk_gen != incore_gen is
 * EXPECTED) apart from a peer-resurrection ghost (FLAG clear + disk_gen !=
 * incore_gen -> a peer advanced the incarnation past us -> skip the flush so we
 * do not resurrect a freed/reincarnated inode).  di_gen is RANDOM (chunk-init
 * vs prandom-per-alloc) so it is only a reliable "different incarnation" signal
 * AFTER our own first flush has stamped the slot with our gen.  Memory-only:
 * no disk I/O in the xfsaild flush path.
 */
#define MXFS_IF_FIRST_FLUSH	(1U << 17)

/*
 * mxfs (sess17 ccloop 4eef1f39): THIS inode is being flushed by the SANCTIONED
 * release path (mxfs_dlm_bast_process reg-durable flush) and must be allowed
 * past the sess119 P119 non-EX guard in xfs_iflush_int.  The release path sets
 * i_dlm_mode = NL (release bookkeeping) BEFORE running the durable di_size
 * flush, so without this flag the P119 guard ("only flush while EX") would skip
 * writing the in-core di_size into the cluster buffer (P119-NONEX-FLUSH-SKIP)
 * and the peer's FUA read would see di_size=0 -> empty content (the
 * cross_write_read .md5-sidecar failure).  We legitimately held this inode's
 * DLM lock (a peer BAST'd us off it), so flushing our dirty state before the
 * release is architectural invariant #1.  Per-inode (set only on the inode we
 * are releasing): other inodes sharing the cluster buffer still get the full
 * P119 anti-resurrection check.  Set+cleared around xfs_iflush_cluster.
 */
#define MXFS_IF_DLM_RELFLUSH	(1U << 18)

/*
 * mxfs (sess19 ccloop 4eef1f39): THIS node performed the user-level removal
 * (unlink / rename-over / rmdir) that drove this inode's link count to 0 — set
 * in xfs_droplink at the nlink->0 transition (the genuine local-intent point,
 * NOT the low-level xfs_iunlink which also runs for internal re-inserts).
 * Cleared on iget instantiation/recycle (XFS_IRECLAIM_RESET_FLAGS) so a reused
 * inode number never inherits a prior incarnation's intent.
 *
 * The clustered destructive-inactivation guard (xfs_inactive) uses it to tell a
 * LEGITIMATE local free (flag SET: we removed the last link, we own the free)
 * apart from a TORN/STALE in-core copy of a peer's still-LIVE inode (flag CLEAR
 * + in-core nlink==0 from a torn reload / NL-cached eviction): freeing the
 * latter's blocks double-frees a block the peer's live inode still owns on disk
 * -> bnobt ltbno+ltlen>bno EFSCORRUPTED shutdown (the ~10-session recurring
 * blocker; proven via P47-INACT DISK-LIVE-same-gen=>A-lost-removal +
 * P81-DEXT disk_claims_freed=1).  disk_nlink is NOT a sound discriminator here
 * (FUA reads hit the stale platter; an unflushed local unlink reads nlink>0) —
 * local intent is.  (Gemini RULE-5 design.)
 */
#define MXFS_IF_LOCAL_UNLINK	(1U << 19)

/*
 * sess41 C8: ADOPTED freer authority — the elected survivor's sweep (or its
 * reap retries) is freeing a DEAD peer's orphan.  Satisfies the B3/B4
 * authority tests exactly like LOCAL_UNLINK, but must NEVER arm the
 * P2L-OWNFREE disk-free bypass: that bypass is only sound for a node's OWN
 * unpublished life, and an adopted freer can race a new claimant of the dead
 * slot whose scoped recovery frees the same orphan first — proceeding on a
 * disk-free read would double-free.  Cleared everywhere LOCAL_UNLINK is
 * (reload/recycle/remove); the reap worker re-restores it per retry under
 * its generation check, so flag stripping only delays one 30s cadence.
 */
#define MXFS_IF_ADOPTED_UNLINK	(1U << 28)

/*
 * mxfs (sess42 ccloop 14d31183): a peer modified this SHORTFORM directory
 * (CAW evict-ring DIR_MODIFY) and our cached inline dir fork is stale.  The
 * i_dlm_dir_gen bump that covers block/leaf dirs is a no-op for shortform:
 * xfs_dir2_sf_getdents reads if_data inline and never goes through
 * xfs_da_read_buf, so the gen-gated dir-block invalidation never fires and a
 * peer's added entry stays invisible (the posix_semantics 16-node barrier-dir
 * 120s visibility timeout).  Set by mxfs_dlm_evict_inode_cb (spinlock-only
 * context); consumed by xfs_readdir, which does an event-driven
 * mxfs_dlm_reload_inode BEFORE the shortform getdents so the inline entries
 * (or a peer-driven LOCAL->block conversion) are refreshed.  Event-driven by
 * design — never poll the disk per readdir (sess38/91 regression).
 */
#define MXFS_IF_DIR_RELOAD	(1U << 20)

/*
 * mxfs (sess21 ccloop 8ddb16a2): the acquire/reader evict could NOT refresh
 * this dir's LEAF (hash index) block because it was pinned/undestaged (the
 * single shared leaf block is perpetually pinned on the active-creating node —
 * every create touches it, so the CIL never quiesces it; clearing XBF_DONE on a
 * pinned buffer loses the un-checkpointed delta = sess64 corruption, so evict
 * SKIPS it).  The node then holds a STALE in-core leaf missing a peer's
 * committed hashvals; its next dir RMW + destage durably drops them (the
 * dir_reuse_coherency leaf-hash hole: readdir lists the name from the coherent
 * DATA block, lookup ENOENTs).  Set by the evict skip sites; consumed at the
 * top of the next dir-modify (xfs_dir_createname/removename/replace) which,
 * holding ILOCK_EXCL + an active tp + the dir-EX grant, REBUILDS the leaf hash
 * index from the coherent DATA blocks and RELOGS it (mxfs_dir_rebuild_leaf_from_
 * data) — no XBF_DONE clear, no extra DLM acquire.  Cleared after the rebuild.
 */
#define MXFS_IF_DIR_LEAF_STALE	(1U << 21)

/*
 * sess31: a dir DATA block was KEPT stale at the acquire-evict (in-AIL
 * undestaged: our own committed-but-unwritten add on a base a peer has since
 * superseded on the LUN — clearing XBF_DONE on it would corrupt, so the evict
 * cannot refresh it).  Its next RMW + async destage durably REVERTS the peer's
 * dirents the stale base lacks (the dir_reuse_coherency single-dirent loss,
 * readdir 799/800).  Set by the evict keep-branch; consumed at the top of the
 * next dir-modify which, holding ILOCK_EXCL + active tp + dir-EX, FUA-reads the
 * disk image of ONLY the kept-stale blocks and re-adds (xfs_dir_createname) any
 * peer dirent our in-core lacks BEFORE the RMW — coherent (leaf/free updated),
 * cheap (only stale blocks, not the whole dir).  Cleared after the reconcile.
 */
#define MXFS_IF_DIR_DATA_STALE	(1U << 22)

/*
 * ccloop-4dd7 sess5 RULE-4 s_remove_count shadow ledger: set iff THIS
 * inode's current i_nlink==0 state holds a +1 in sb->s_remove_count
 * (i.e. the 0-edge went through clear_nlink/drop_nlink accounting).
 * Every 0->N dec site (xfs_inode_from_disk adopt, xfs_droplink PIN,
 * xfs_bumplink from 0, VFS destroy) verifies the flag before the dec
 * and screams with a stack when unpaired — the suite-soak WARN storm
 * at fs/inode.c:289 is a permanently-negative s_remove_count, which
 * also makes sb_prepare_remount_readonly return -EBUSY forever.
 * Deliberately NOT in XFS_IRECLAIM_RESET_FLAGS: a set flag at recycle
 * means the destroy-side dec never ran for the corpse — an anomaly the
 * reinit hook must be able to observe, not silently clear.
 */
#define MXFS_IF_RMC_ACCT	(1U << 23)

/*
 * ccloop c7ee71c6 sess3 (RULE-5 GPT incarnation-coherence design, Phase A).
 * This in-core shell is a DEAD INCARNATION: a protective-grant reload read
 * the authoritative on-disk dinode and found the slot FREED (di_mode=0) or
 * carrying a DIFFERENT di_gen while this shell is CLEAN (no in-flight local
 * provenance) — the number was freed (and possibly reused) behind us, so
 * nothing this shell serves is real (parallel-universe dirs: the fleet ran
 * a whole dir_reuse round inside a 5-minutes-dead dir ino 165).  POISONED:
 * dir ops on it return -ESTALE at entry (after d_prune_aliases so the path
 * re-resolves), the reload never re-attempts adoption, and the iget
 * lookup-side evict retires the shell so a fresh iget instantiates the live
 * incarnation from disk.  NEVER adopt across incarnations in place (icache
 * is keyed by ino; i_generation must not change under a live inode) and
 * NEVER keep-alive a clean shell the disk has disowned.  Reset on recycle
 * (XFS_IRECLAIM_RESET_FLAGS) — the recycled shell IS the new incarnation.
 */
#define MXFS_IF_INCARN_STALE	(1U << 24)

/*
 * ccloop c7ee71c6 sess20 — PUBLICATION SKIPPED (H4 root fix).
 *
 * One 4 KiB inode-cluster buffer carries many inodes owned by different
 * nodes, so mxfs_submit_partial_inode_write submits only the sectors this
 * node may publish and drops the rest from the bio.  The buffer still
 * COMPLETES, and stock XFS completion is buffer-wide: xfs_buf_inode_iodone
 * -> xfs_iflush_finish clears ili_last_fields, deletes the item from the
 * AIL and declares the inode durable — for bytes that never left this host.
 * That is a false durability assertion, and it silently drops the change
 * from every retry mechanism XFS has.  (RULE-5 GPT review, sess20: "if an
 * inode slot was not written, its inode log item must not receive
 * successful-I/O completion semantics ... that alone is sufficient to lose
 * committed changes permanently.")
 *
 * Set on the inode by the submit path for exactly the slots it dropped, and
 * consumed by xfs_buf_inode_iodone, which then re-arms the item (ili_fields
 * |= ili_last_fields) and LEAVES IT IN THE AIL instead of completing it, so
 * xfsaild pushes it again.  Cleared by the consumer.
 */
#define MXFS_IF_PUB_SKIPPED	(1U << 25)

/*
 * sess35 (c7ee71c6) P241 instrumentation — CLUSTER-MERGE OVERLAY HIT.
 *
 * Set by mxfs_clmerge_ledger_rollback when the cluster-merge overlay
 * replaces this inode's slot in a buffer while its publication ledger
 * has an in-flight claim (flush != durable) OUTSIDE the RELFLUSH
 * rollback window.  Consumed at xfs_iflush_finish: a discharge that
 * advances durable over a merged-away image is a BLIND DISCHARGE and
 * is traced (P241) with the re-log state that decides whether the
 * in-core newer state will ever be flushed again.  Cleared by a
 * subsequent xfs_iflush copy-in (fresh image supersedes the overlay)
 * and by the P187 PUB_SKIPPED re-arm.  Instrumentation only — no
 * behavioral effect.
 */
#define MXFS_IF_CLMERGE_HIT	(1U << 26)

/*
 * mxfs (sess40 ccloop c7ee71c6, D-AGI-UNLINKED / tombstone-semantics fix):
 * THIS NODE COMMITTED THE IFREE for this in-core incarnation.  Set in
 * xfs_inactive_ifree immediately after a successful xfs_trans_commit of the
 * ifree transaction; never set on any guard-skip path (INACT-SKIP-STALE,
 * IFREE-REVALIDATE-SKIP, B2-B5).  Consumed by the two free-aware DLM release
 * sites (xfs_inactive exit and mxfs_dlm_evict), which previously inferred
 * "genuinely freed" from VFS nlink==0 — an invalid inference for a cached or
 * reloaded copy of a PEER's live open-unlinked inode (nlink==0, never freed
 * by us): the deterministic AGI-bucket reproducer showed the evict/inact exit
 * writing a free-style tombstone (dir_epoch/last_ex_slot cleared, P144) into
 * the slot of an inode a peer legitimately still owned.  "Inactivation
 * skipped != inode freed" (GPT sess40 ruling): only a committed ifree may
 * publish free-tombstone semantics.  Reset on inode recycle via
 * XFS_IRECLAIM_RESET_FLAGS.
 */
#define MXFS_IF_FREE_COMMITTED	(1U << 27)

/*
 * sess5 shadow-ledger wrappers: ALL nlink writes on xfs inodes route
 * through these so no set_nlink/clear_nlink/drop_nlink/inc_nlink edge
 * can touch sb->s_remove_count without the MXFS_IF_RMC_ACCT flag
 * following it.  mxfs_rmc_unpaired() (xfs_mxfs_dlm.c) screams with the
 * caller's stack when a 0->N dec finds an unaccounted zero.
 */
static inline void mxfs_rmc_unpaired(struct xfs_inode *ip, const char *site,
				     unsigned int newn)
{
	static atomic_t rmcu_n = ATOMIC_INIT(0);

	if (atomic_inc_return(&rmcu_n) > 50)
		return;
	pr_alert("mxfs: P9-RMC-UNPAIRED-%s ino=%llu new=%u rmcnt=%ld last0=%pS lastclr=%pS comm=%s — 0->N dec with UNACCOUNTED zero\n",
		site, (unsigned long long)ip->i_ino, newn,
		atomic_long_read(&VFS_I(ip)->i_sb->s_remove_count),
		ip->i_rmc_last0_ra, ip->i_rmc_lastclr_ra,
		current->comm);
	dump_stack();
}

static inline void mxfs_set_nlink(struct xfs_inode *ip, unsigned int nlink)
{
	struct inode	*inode = VFS_I(ip);
	unsigned int	old = inode->i_nlink;

	/*
	 * sess5 ROOT FIX (RULE-4 proven, b67r2 provenance print
	 * last0=xfs_dir_remove_child lastclr=destroy_inode): a VFS-DESTROYED
	 * corpse (I_CLEAR — every XFS IRECLAIMABLE shell) has its
	 * s_remove_count participation CLOSED: __destroy_inode already dec'd
	 * its nlink-0 state.  The MXFS reuse-reload runs xfs_inode_from_disk
	 * on such corpses BEFORE any recycle (xfs_iget_cache_hit sess40
	 * block), and set_nlink 0->1 there dec'd the live counter unpaired —
	 * leaving it permanently negative: every subsequent unlink+destroy
	 * pair then WARNs at fs/inode.c:289 (the suite-soak 833-hit storm)
	 * and sb_prepare_remount_readonly returns -EBUSY forever.  Adopt
	 * nlink RAW on corpses; xfs_reinit_inode re-opens accounting from
	 * the adopted value at recycle (0 -> clear_nlink inc; N -> no edge).
	 */
	if (inode->i_state & I_CLEAR) {
		inode->__i_nlink = nlink;
		return;
	}

	if (old == 0 && nlink != 0) {
		if (!xfs_iflags_test(ip, MXFS_IF_RMC_ACCT))
			mxfs_rmc_unpaired(ip, "set_nlink", nlink);
		xfs_iflags_clear(ip, MXFS_IF_RMC_ACCT);
		ip->i_rmc_lastclr_ra = __builtin_return_address(0);
	} else if (old != 0 && nlink == 0) {
		xfs_iflags_set(ip, MXFS_IF_RMC_ACCT);
		ip->i_rmc_last0_ra = __builtin_return_address(0);
	}
	set_nlink(inode, nlink);
}

static inline void mxfs_drop_nlink(struct xfs_inode *ip)
{
	drop_nlink(VFS_I(ip));
	if (VFS_I(ip)->i_nlink == 0) {
		xfs_iflags_set(ip, MXFS_IF_RMC_ACCT);
		ip->i_rmc_last0_ra = __builtin_return_address(0);
	}
}

static inline void mxfs_inc_nlink(struct xfs_inode *ip)
{
	if (VFS_I(ip)->i_nlink == 0) {
		if (!xfs_iflags_test(ip, MXFS_IF_RMC_ACCT))
			mxfs_rmc_unpaired(ip, "inc_nlink", 1);
		xfs_iflags_clear(ip, MXFS_IF_RMC_ACCT);
		ip->i_rmc_lastclr_ra = __builtin_return_address(0);
	}
	inc_nlink(VFS_I(ip));
}

/* All inode state flags related to inode reclaim. */
#define XFS_ALL_IRECLAIM_FLAGS	(XFS_IRECLAIMABLE | \
				 XFS_IRECLAIM | \
				 XFS_NEED_INACTIVE | \
				 XFS_INACTIVATING)

/*
 * Per-lifetime flags need to be reset when re-using a reclaimable inode during
 * inode lookup. This prevents unintended behaviour on the new inode from
 * ocurring.
 */
#define XFS_IRECLAIM_RESET_FLAGS	\
	(XFS_IRECLAIMABLE | XFS_IRECLAIM | \
	 XFS_EOFBLOCKS_RELEASED | XFS_ITRUNCATED | XFS_NEED_INACTIVE | \
	 XFS_INACTIVATING | XFS_IQUOTAUNCHECKED | XFS_ISTALE_CAW | \
	 MXFS_IF_LOCAL_UNLINK | MXFS_IF_ADOPTED_UNLINK | MXFS_IF_DIR_RELOAD | \
	 MXFS_IF_INCARN_STALE | MXFS_IF_FREE_COMMITTED)

/*
 * Flags for inode locking.
 * Bit ranges:	1<<1  - 1<<16-1 -- iolock/ilock modes (bitfield)
 *		1<<16 - 1<<32-1 -- lockdep annotation (integers)
 */
#define	XFS_IOLOCK_EXCL		(1u << 0)
#define	XFS_IOLOCK_SHARED	(1u << 1)
#define	XFS_ILOCK_EXCL		(1u << 2)
#define	XFS_ILOCK_SHARED	(1u << 3)
#define	XFS_MMAPLOCK_EXCL	(1u << 4)
#define	XFS_MMAPLOCK_SHARED	(1u << 5)
/*
 * sess1 (ccloop 46efd8b6) MXFS iread-PR: modifier bit for an ILOCK_EXCL
 * taken ONLY to serialize the in-core extent-map load (the
 * xfs_ilock_data_map_shared / xfs_ilock_attr_map_shared escalation on
 * xfs_need_iread_extents).  Loading the iext tree from committed on-disk
 * state needs the EXCLUSIVE ilock LOCALLY (in-core tree mutation) but only
 * PROTECTED-READ cluster-wide: PR already excludes every cluster writer,
 * and Invariant 1 makes disk consistent at any peer's release (GFS2 loads
 * inode metadata under a SHARED glock the same way).  Mapping this EXCL to
 * cluster EX (pre-sess1) let a routine post-adopt lookup on a 32-node hot
 * dir issue a cluster EX against 31 PR-cycling readers — measured: 12
 * nodes starved 3x120s (rc=-110) and SHUT DOWN inside cache_coherency@32's
 * read-only verify.  Deliberately NOT part of XFS_LOCK_MASK; only
 * xfs_ilock/xfs_iunlock consume it, for the DLM mode choice.
 */
#define	XFS_ILOCK_MXFS_PRIREAD	(1u << 6)
/*
 * sess37 CREATE-INTENT EX (mirror of PRIREAD, opposite direction).  A create
 * runs open(O_CREAT)'s LOOKUP half first: the dir ILOCK_SHARED maps to a
 * cluster PR, and the CREATE half's EX then finds 31 peers' PR class ahead
 * of it — measured live (32/caw dir_reuse, instr window): lookup-PR CAS
 * storm -> dir reload -> EX upgrade DENIED (-EDEADLK) -> PR drop + full
 * drain -> fresh EX, PER CREATE (>=3 wire transitions + a drain each).
 * When the VFS lookup carries create intent, tag the dir ILOCK so the
 * cluster mode is EX from the lookup on: the create half then hits the
 * already-held shortcut with ZERO wire ops.  Rides outside XFS_LOCK_MASK
 * exactly like PRIREAD; consumed only by xfs_ilock/xfs_iunlock.  Overrides
 * PRIREAD when both are set (create intent needs EX regardless of why the
 * local lock widened).  Knob mxfs.create_intent_ex (default 1).
 */
#define	XFS_ILOCK_MXFS_CREATEINT	(1u << 7)

/* sess38: gate+registry consult for the armed create-intent window; used by
 * every lock-mode computation inside it (xfs_ilock_data_map_shared and
 * mxfs_dlm_dir_consumer_refresh — the latter's untagged ILOCK_SHARED was
 * leak A of the surviving per-visit PR->EDEADLK->drain cycle). */
bool	mxfs_createint_dir_armed(struct xfs_inode *ip);

#define XFS_LOCK_MASK		(XFS_IOLOCK_EXCL | XFS_IOLOCK_SHARED \
				| XFS_ILOCK_EXCL | XFS_ILOCK_SHARED \
				| XFS_MMAPLOCK_EXCL | XFS_MMAPLOCK_SHARED)

#define XFS_LOCK_FLAGS \
	{ XFS_IOLOCK_EXCL,	"IOLOCK_EXCL" }, \
	{ XFS_IOLOCK_SHARED,	"IOLOCK_SHARED" }, \
	{ XFS_ILOCK_EXCL,	"ILOCK_EXCL" }, \
	{ XFS_ILOCK_SHARED,	"ILOCK_SHARED" }, \
	{ XFS_MMAPLOCK_EXCL,	"MMAPLOCK_EXCL" }, \
	{ XFS_MMAPLOCK_SHARED,	"MMAPLOCK_SHARED" }


/*
 * Flags for lockdep annotations.
 *
 * XFS_LOCK_PARENT - for directory operations that require locking a
 * parent directory inode and a child entry inode. IOLOCK requires nesting,
 * MMAPLOCK does not support this class, ILOCK requires a single subclass
 * to differentiate parent from child.
 *
 * XFS_LOCK_RTBITMAP/XFS_LOCK_RTSUM - the realtime device bitmap and summary
 * inodes do not participate in the normal lock order, and thus have their
 * own subclasses.
 *
 * XFS_LOCK_INUMORDER - for locking several inodes at the some time
 * with xfs_lock_inodes().  This flag is used as the starting subclass
 * and each subsequent lock acquired will increment the subclass by one.
 * However, MAX_LOCKDEP_SUBCLASSES == 8, which means we are greatly
 * limited to the subclasses we can represent via nesting. We need at least
 * 5 inodes nest depth for the ILOCK through rename, and we also have to support
 * XFS_ILOCK_PARENT, which gives 6 subclasses.  That's 6 of the 8 subclasses
 * supported by lockdep.
 *
 * This also means we have to number the sub-classes in the lowest bits of
 * the mask we keep, and we have to ensure we never exceed 3 bits of lockdep
 * mask and we can't use bit-masking to build the subclasses. What a mess.
 *
 * Bit layout:
 *
 * Bit		Lock Region
 * 16-19	XFS_IOLOCK_SHIFT dependencies
 * 20-23	XFS_MMAPLOCK_SHIFT dependencies
 * 24-31	XFS_ILOCK_SHIFT dependencies
 *
 * IOLOCK values
 *
 * 0-3		subclass value
 * 4-7		unused
 *
 * MMAPLOCK values
 *
 * 0-3		subclass value
 * 4-7		unused
 *
 * ILOCK values
 * 0-4		subclass values
 * 5		PARENT subclass (not nestable)
 * 6		unused
 * 7		unused
 * 
 */
#define XFS_IOLOCK_SHIFT		16
#define XFS_IOLOCK_MAX_SUBCLASS		3
#define XFS_IOLOCK_DEP_MASK		0x000f0000u

#define XFS_MMAPLOCK_SHIFT		20
#define XFS_MMAPLOCK_NUMORDER		0
#define XFS_MMAPLOCK_MAX_SUBCLASS	3
#define XFS_MMAPLOCK_DEP_MASK		0x00f00000u

#define XFS_ILOCK_SHIFT			24
#define XFS_ILOCK_PARENT_VAL		5u
#define XFS_ILOCK_MAX_SUBCLASS		(XFS_ILOCK_PARENT_VAL - 1)
#define XFS_ILOCK_DEP_MASK		0xff000000u
#define	XFS_ILOCK_PARENT		(XFS_ILOCK_PARENT_VAL << XFS_ILOCK_SHIFT)

#define XFS_LOCK_SUBCLASS_MASK	(XFS_IOLOCK_DEP_MASK | \
				 XFS_MMAPLOCK_DEP_MASK | \
				 XFS_ILOCK_DEP_MASK)

#define XFS_IOLOCK_DEP(flags)	(((flags) & XFS_IOLOCK_DEP_MASK) \
					>> XFS_IOLOCK_SHIFT)
#define XFS_MMAPLOCK_DEP(flags)	(((flags) & XFS_MMAPLOCK_DEP_MASK) \
					>> XFS_MMAPLOCK_SHIFT)
#define XFS_ILOCK_DEP(flags)	(((flags) & XFS_ILOCK_DEP_MASK) \
					>> XFS_ILOCK_SHIFT)

/*
 * Layouts are broken in the BREAK_WRITE case to ensure that
 * layout-holders do not collide with local writes. Additionally,
 * layouts are broken in the BREAK_UNMAP case to make sure the
 * layout-holder has a consistent view of the file's extent map. While
 * BREAK_WRITE breaks can be satisfied by recalling FL_LAYOUT leases,
 * BREAK_UNMAP breaks additionally require waiting for busy dax-pages to
 * go idle.
 */
enum layout_break_reason {
        BREAK_WRITE,
        BREAK_UNMAP,
};

/*
 * For multiple groups support: if S_ISGID bit is set in the parent
 * directory, group of new file is set to that of the parent, and
 * new subdirectory gets S_ISGID bit from parent.
 */
#define XFS_INHERIT_GID(pip)	\
	(xfs_has_grpid((pip)->i_mount) || (VFS_I(pip)->i_mode & S_ISGID))

int		xfs_inactive(struct xfs_inode *ip);
int		xfs_lookup(struct xfs_inode *dp, const struct xfs_name *name,
			   struct xfs_inode **ipp, struct xfs_name *ci_name,
			   bool create_intent);
int		xfs_create(const struct xfs_icreate_args *iargs,
			   struct xfs_name *name, struct xfs_inode **ipp);
int		xfs_create_tmpfile(const struct xfs_icreate_args *iargs,
			   struct xfs_inode **ipp);
int		xfs_remove(struct xfs_inode *dp, struct xfs_name *name,
			   struct xfs_inode *ip);
int		xfs_link(struct xfs_inode *tdp, struct xfs_inode *sip,
			 struct xfs_name *target_name);
int		xfs_rename(struct mnt_idmap *idmap,
			   struct xfs_inode *src_dp, struct xfs_name *src_name,
			   struct xfs_inode *src_ip, struct xfs_inode *target_dp,
			   struct xfs_name *target_name,
			   struct xfs_inode *target_ip, unsigned int flags);

void		xfs_ilock(xfs_inode_t *, uint);
int		xfs_ilock_nowait(xfs_inode_t *, uint);
void		xfs_iunlock(xfs_inode_t *, uint);
/* sess132 ILOCK forensics (see field block above) */
void		mxfs_ilk_note_lock(struct xfs_inode *ip, uint lock_flags,
				   unsigned long ret_ip);
void		mxfs_ilk_note_unlock(struct xfs_inode *ip, uint lock_flags,
				     unsigned long ret_ip);
void		xfs_ilock_demote(xfs_inode_t *, uint);
void		xfs_assert_ilocked(struct xfs_inode *, uint);
uint		xfs_ilock_data_map_shared(struct xfs_inode *);
uint		xfs_ilock_attr_map_shared(struct xfs_inode *);

int		xfs_ifree(struct xfs_trans *, struct xfs_inode *);
int		xfs_itruncate_extents_flags(struct xfs_trans **,
				struct xfs_inode *, int, xfs_fsize_t, int);
void		xfs_iext_realloc(xfs_inode_t *, int, int);

int		xfs_log_force_inode(struct xfs_inode *ip);
void		xfs_iunpin_wait(xfs_inode_t *);
#define xfs_ipincount(ip)	((unsigned int) atomic_read(&ip->i_pincount))

int		xfs_iflush_cluster(struct xfs_buf *);
void		xfs_lock_two_inodes(struct xfs_inode *ip0, uint ip0_mode,
				struct xfs_inode *ip1, uint ip1_mode);

int xfs_icreate(struct xfs_trans *tp, xfs_ino_t ino,
		const struct xfs_icreate_args *args, struct xfs_inode **ipp);

static inline int
xfs_itruncate_extents(
	struct xfs_trans	**tpp,
	struct xfs_inode	*ip,
	int			whichfork,
	xfs_fsize_t		new_size)
{
	return xfs_itruncate_extents_flags(tpp, ip, whichfork, new_size, 0);
}

int	xfs_break_dax_layouts(struct inode *inode);
int	xfs_break_layouts(struct inode *inode, uint *iolock,
		enum layout_break_reason reason);

static inline void xfs_update_stable_writes(struct xfs_inode *ip)
{
	if (bdev_stable_writes(xfs_inode_buftarg(ip)->bt_bdev))
		mapping_set_stable_writes(VFS_I(ip)->i_mapping);
	else
		mapping_clear_stable_writes(VFS_I(ip)->i_mapping);
}

/*
 * When setting up a newly allocated inode, we need to call
 * xfs_finish_inode_setup() once the inode is fully instantiated at
 * the VFS level to prevent the rest of the world seeing the inode
 * before we've completed instantiation. Otherwise we can do it
 * the moment the inode lookup is complete.
 */
static inline void xfs_finish_inode_setup(struct xfs_inode *ip)
{
	xfs_iflags_clear(ip, XFS_INEW);
	barrier();
	unlock_new_inode(VFS_I(ip));
}

static inline void xfs_setup_existing_inode(struct xfs_inode *ip)
{
	xfs_setup_inode(ip);
	xfs_setup_iops(ip);
	xfs_finish_inode_setup(ip);
}

void xfs_irele(struct xfs_inode *ip);

extern struct kmem_cache	*xfs_inode_cache;

/* The default CoW extent size hint. */
#define XFS_DEFAULT_COWEXTSZ_HINT 32

bool xfs_inode_needs_inactive(struct xfs_inode *ip);

struct xfs_inode *xfs_iunlink_lookup(struct xfs_perag *pag, xfs_agino_t agino);
int xfs_iunlink_reload_next(struct xfs_trans *tp, struct xfs_buf *agibp,
		xfs_agino_t prev_agino, xfs_agino_t next_agino, short bucket);

void xfs_end_io(struct work_struct *work);

int xfs_ilock2_io_mmap(struct xfs_inode *ip1, struct xfs_inode *ip2);
void xfs_iunlock2_io_mmap(struct xfs_inode *ip1, struct xfs_inode *ip2);
void xfs_iunlock2_remapping(struct xfs_inode *ip1, struct xfs_inode *ip2);
void xfs_lock_inodes(struct xfs_inode **ips, int inodes, uint lock_mode);
void xfs_sort_inodes(struct xfs_inode **i_tab, unsigned int num_inodes);

static inline bool
xfs_inode_unlinked_incomplete(
	const struct xfs_inode	*ip)
{
	return VFS_IC(ip)->i_nlink == 0 && !xfs_inode_on_unlinked_list(ip);
}
int xfs_inode_reload_unlinked_bucket(struct xfs_trans *tp, struct xfs_inode *ip);
int xfs_inode_reload_unlinked(struct xfs_inode *ip);

bool xfs_ifork_zapped(const struct xfs_inode *ip, int whichfork);
void xfs_inode_count_blocks(struct xfs_trans *tp, struct xfs_inode *ip,
		xfs_filblks_t *dblocks, xfs_filblks_t *rblocks);
unsigned int xfs_inode_alloc_unitsize(struct xfs_inode *ip);

int xfs_icreate_dqalloc(const struct xfs_icreate_args *args,
		struct xfs_dquot **udqpp, struct xfs_dquot **gdqpp,
		struct xfs_dquot **pdqpp);

#endif	/* __XFS_INODE_H__ */
