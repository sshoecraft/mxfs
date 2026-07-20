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
	bool			i_dlm_stale;	/* needs reload from disk after BAST */ uint8_t i_dlm_stale_src; /* sess11(a9a03929): code of the LAST i_dlm_stale=true setter (1=readdir 2=consumer_refresh 3=modify_prelock 4=adopt_fmt 5=bast_process_rel 6=bast_notify_acq 7=ilock_slow_prereload 8=fastpath_rearm 9-13=dlm_misc 14-17=iget 18-20=inode_misc 21-23=super) — P11-ACQSTALE-SELFBAST forensics */ uint8_t i_dlm_bastq_src; /* sess11: site that queued the last bast_work/dwork (1=ilock_end_refire 2=demwait_redrive 3=notify_idle 4=notify_orphan 5=notify_immediate 6=ilock_begin_recov 7=acq_selfbast 9=mht_arm 10=stranded_arm 11=batch_arm 12=sf_tenure_arm 13=grantwin_park 14=close_release 15=pr_idle_release 16=dir_ex_sweep) */
	bool			i_dlm_bast_during_acq; /* sess35 (ccloop): a peer BAST arrived while this node was in ISTATE_ACQUIRING (slow-path DLM acquire in flight).  SEPARATE flag from i_dlm_stale: the post-acquire reload CLEARS i_dlm_stale before the post-publish reads it, so reusing i_dlm_stale to defer the BAST silently SWALLOWED the revoke — the holder kept the grant cached idle and the peer's request stalled the full 6000ms MXFS_LOCK_ACQUIRE_WAIT_MS until its retry re-fired the BAST (the dir_reuse 2/tcp ~6s handoff, PROVEN sess35: 9 ACQUIRING-EX BASTs lost/run).  Set by bast_notify's ACQUIRING branch; honored at the slow-path post-publish (-> ISTATE_BAST + drain) regardless of reload; cleared there. */
	bool			i_dlm_self_demote; /* sess51 (ccloop 8ddb16a2): the next mxfs_dlm_bast_process for this inode is a SELF-demote (the P109 EDEADLK upgrade-conflict recovery dropping our own cached PR->NL to re-request EX from a clean state), NOT a peer handoff.  No peer reads our state across a self-demote, so a clean (read-only) self-demote needs no durability drain — skipping it kills the tcp_dlm_scaling PR->EX upgrade-livelock amplifier WITHOUT removing the coherency-masking barrier on genuine peer handoffs (dir_reuse/rsync_paired).  Set in the EDEADLK recovery before queuing bast_work; read+cleared at bast_process entry. */
	bool			i_dlm_unpublished; /* sess43: brand-new inode granted LOCALLY (i_dlm_mode=EX) with NO on-disk CAW slot yet; published lazily on a peer dir/AGI BAST or dropped silently on local eviction.  See notes/sess43_deferred_publish_design.md */
	struct list_head	i_dlm_unpub_link;  /* sess43: linkage on mp->m_mxfs_unpub_list while i_dlm_unpublished */
	xfs_ino_t		i_mxfs_unpub_parent; /* v0.5.6 (sess29 ccloop 14d31183): ino of the directory whose dirent names this unpublished inode; 0 = unknown (tmpfile/whiteout/pre-assignment window) and means "include in EVERY scoped BAST publish".  Lets the BAST-side publish drain claim slots ONLY for inodes a peer can actually reach through the lock being released (the released dir's children, or the released AG's inodes) instead of the whole list — the whole-list drain at 16 nodes claimed ~96k slots against the 65536-slot CAW table, took minutes per release, and starved EX waiters into 120s timeouts + shutdown (sess28 scaling_curve root cause 2).  Set after xfs_dir_create_child in xfs_create/xfs_symlink; a plain store suffices: a racing scoped drain that reads the pre-store 0 over-publishes (safe), never under-publishes.  Cross-dir rename/link of a still-unpublished inode force-publishes synchronously (mxfs_dlm_publish_inode) so the recorded parent can never go stale. */
	uint32_t		i_dlm_dir_gen;	/* sess37: bumped on DLM re-acquire-after-BAST; dir-block read path forces FUA re-read when cached buf's stamp < this (read-time/lazy block-dir invalidation, deadlock-free) */
	uint32_t		i_dlm_cached_grant_gen; /* sess61 (sess10 plan): the TCP DLM per-grant generation token cached at the last SLOW-PATH acquire of this inode.  On a dir-EX FAST-PATH serve, if mxfs_v5_dlm_inode_grant_gen() != this, the lock CHANGED HANDS (a peer was granted) since we cached it -> the in-core dir base is stale -> force a reload-on-reacquire before the RMW.  This is the RELIABLE (acked-TCP grant_gen) replacement for the lossy DIR_MODIFY eviction-ring as the dir staleness signal (sess61 PROVEN root: fast-path RMW of a stale block0 clobbers peers' dirents). 0 = not yet cached. */
	uint32_t		i_dlm_dir_loaded_gen; /* sess94: value of i_dlm_dir_gen at the moment the SHORTFORM dir fork was last (re)loaded from disk.  If i_dlm_dir_gen has advanced past this when a cached EX-acquire fast-paths, the in-core shortform fork is STALE (a peer modified the dir) and RMW'ing it would clobber the peer's dirents — the unlink_visibility lost-update. */
	uint64_t		i_mxfs_dscan_clean_key; /* sess1 (ccloop 46efd8b6): datascan gen-gate.  Composite of (i_dlm_dir_gen, i_dlm_dir_valid_epoch, i_dlm_dir_loaded_gen) captured when mxfs_dir2_datascan_lookup last verified the leaf hash-index ENOENT-consistent (scan found nothing the leaf missed).  While the coherency state hasn't moved, further hash-miss lookups skip the O(dir) authoritative data scan (measured 459 read-IOs / 112ms per MISS on a 640-entry shared dir — every rv/uv negative lookup).  Any peer modify moves the epoch/gen (leaf-hole formation requires a peer write), and any real fork adopt resets this to the ~0 sentinel, re-arming one scan. */
	bool			i_dlm_routed_iclus; /* ccloop 72513a13 sess4: WHICH resource backs the current i_dlm_mode grant — true = the inode-cluster (iclus) resource, false = the per-inode slot.  Stamped at every disk acquire; every release/sweep decision routes by THIS, never by re-evaluating S_ISREG (a mode-0 dead-shell acquire is per-inode, and re-evaluating at release orphaned the slot forever — proven: per-inode EX gen=2201 held 220s, 7 nodes queued on the root dir). */
	uint64_t		i_dlm_iclus_seen_seq; /* ccloop 72513a13 sess4: mxfs_iclus grant_seq at our last reload/adopt of this inode.  seen==current ⟹ the cluster grant was held (by us or nobody) continuously since — no peer EX possible — so the in-core image is coherent (reload skippable); seen!=current ⟹ a fresh cluster claim happened (peer may have written) — genuine handoff, force disk adopt.  0 = never loaded under iclus. */
	uint32_t		i_dlm_handoff_acted_gen; /* sess63: grant_gen at which we last ACTED on a cross-node EX handoff (forced a full disk-superset reload of this dir).  The master-exposed handoff bit (mxfs_v5_dlm_inode_grant_handoff) is consumed once per grant episode: act only when handoff && grant_gen != this, then set this=grant_gen.  Prevents a 2nd same-tenure reload re-adopting disk over our own in-flight mods (resurrection).  0 = never acted. */
	uint32_t		i_dlm_dir_valid_epoch; /* sess64 (GPT design): the MONOTONIC cross-node handoff epoch (mxfs_v5_dlm_inode_dir_epoch) that this dir's in-core base is known coherent with.  On any dir grant authorization the XFS layer reads the grant's dir_epoch; if it EXCEEDS this, a peer modified the dir since our base loaded -> force a disk-superset adopt + clean dir-block invalidation, then set this=grant_epoch.  LEVEL-triggered (a missed intermediate handoff still leaves grant_epoch > this), curing the edge-triggered handoff bool's ~80% under-fire.  0 = base predates any tracked handoff. */
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
	struct task_struct	*i_dlm_demoter;	/* thread inside bast_process for this inode (or NULL) */
	pid_t			i_dlm_demoter_pid;	/* sess5: leak forensics — stamped at every demoter set */
	char			i_dlm_demoter_comm[16];
	u64			i_dlm_demoter_set_ns;
	int			i_dlm_demoter_line;
	bool			i_mxfs_reused_create; /* v0.5.4 (sess24 ccloop 14d31183): this CREATE reused an in-core incarnation (xfs_iget cache HIT with XFS_IGET_CREATE -> mxfs_dlm_rearm_unpublished).  Peers may still hold stale dcache/icache references to this inode NUMBER from the prior incarnation and can therefore name it -- and cleanly acquire its empty CAW slot -- without first reading our new parent dirent.  While i_dlm_unpublished, this keeps the synchronous sess107 unpublished-dir-EX backstop in mxfs_dlm_ilock_begin armed; FRESH cache-miss creates (mxfs_dlm_grant_local_new clears this) skip the backstop because no peer can name a never-before-used ino faster than the pre-commit async publish worker claims its slot (mxfs_dlm_publish_dirs_work, ~1 ms): dirent paths transit a lock we hold (BAST publishes the unpub list before release) and a lookup-iget of our not-yet-flushed dinode reads FREE on disk and bails ENOENT without any slot acquire. */
	uint64_t		i_mxfs_iget_ns;      /* sess3 (ccloop 46efd8b6): ktime_get_ns at mxfs inode-DLM field init (== iget construction).  Printed by P14-DABUF-HOLE as iget_age_ms — a tiny age at a hole proves the cold-iget-adopts-lagging-home mechanism (dir inode evicted, re-igot from a mid-tenure-lagging home image, walked with newer cached structure). */
	uint64_t		i_mxfs_lastrel_ns;   /* sess10(a9a03929) RULE-4 last-release ledger: ktime_get_real_ns at the end of the most recent release-path __mxfs_dlm_dir_inode_durable decision for this dir (bast_process sd stage or per-op wrapper).  Printed by P-SFDIR-REVERT so a platter-lags-commit event shows when the last durable-at-release ran relative to the stale reload.  0 = never. */
	uint64_t		i_mxfs_lastrel_size; /* sess10: i_disk_size at that decision point. */
	uint32_t		i_mxfs_lastrel_flag; /* sess10: 1=durable helper RAN, 2=SKIPPED by the pr_release_fast clean-release gate, 3=helper ran but self-guard bailed (not LOCAL handled elsewhere/…).  0 = never. */
	bool			i_mxfs_self_created; /* v0.5.4 (sess23 ccloop 14d31183): this inode was CREATED by this node this mount and no peer BAST has arrived for it.  Gates the per-mkdir shortform-parent cluster-durability barrier in xfs_create (mxfs_dlm_dir_inode_durable): a dir we created ourselves with zero observed peer interest cannot be mid-cold-read by a coordinated peer (peers reach it only through a shared ancestor, whose own barrier fired, or by taking its DLM lock — which BASTs us and clears this flag before the release-path flush).  Cleared on any peer BAST (mxfs_dlm_bast_notify); false for every inode igot from disk, so pre-existing/shared dirs always keep the barrier. */

	/* sess132 (RULE 4): ILOCK last-locker forensics for the 16-node
	 * create-storm wedge — a bast_process drain blocked forever on
	 * i_lock with NO live holder (leaked ILOCK).  Records the most
	 * recent EXCL and SHARED takers + a shared-hold counter so the
	 * stuck-drain probe can name the leaking call path. */
	atomic_t		i_mxfs_ilk_rd_held; /* outstanding ILOCK_SHARED holds */
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
} xfs_inode_t;

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
	 MXFS_IF_LOCAL_UNLINK | MXFS_IF_DIR_RELOAD)

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
			   struct xfs_inode **ipp, struct xfs_name *ci_name);
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
		xfs_agino_t prev_agino, xfs_agino_t next_agino);

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
