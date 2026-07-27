// SPDX-License-Identifier: GPL-2.0
/*
 * MXFS — Multinode XFS
 * XFS-side DLM lock caching
 *
 * Provides per-inode DLM lock caching with BAST (blocking AST) handling.
 * Locks are held across operations and released only on:
 *   - BAST from another node
 *   - Inode eviction
 *   - Unmount
 *
 * This is the XFS-layer interface. The DLM transport layer is in
 * dlm/v5_mount.h. These functions call into v5_mount for actual
 * DLM I/O and use XFS internals (VFS_I, filemap, etc.) for flush.
 *
 * Copyright (c) 2026
 */
#ifndef XFS_MXFS_DLM_H
#define XFS_MXFS_DLM_H

struct xfs_inode;
struct xfs_mount;
struct xfs_perag;
struct xfs_buf;
struct work_struct;

/*
 * sess36: gate for the sess20-35 diagnostic prints (P-, MX-INSTR, H tags).
 * Default OFF (mxfs.instr=0).  These fire per-metadata-op (P9 dialloc,
 * P13/P63 acquire, P-H27 per dir-block write, H40 per create) and made
 * rsync ~100x slower than native XFS, failing the perf criteria.  They
 * are pure logging (no side effects), so gating them off cannot affect
 * correctness; set mxfs.instr=1 to re-enable for debugging.
 */
extern int mxfs_instr_enabled;
/* ccloop 72513a13 sess3: gate for the P125-AG-DIVERGE on-disk AG-slot
 * assertion in xfs_buf_submit_ex (a FUA probe-chain read per AG-metadata
 * write — 5.3 FUA reads/create through xfsaild when armed).  Default 0. */
extern int mxfs_p125_ag_diverge;
/* sess30 run14d: standalone gate for just the dir-block content traces
 * (P-DIRWR write submission + P-DIRRD read completion in xfs_buf.c).
 * Cheap enough to leave on through a whole coherency run, unlike instr. */
extern int mxfs_dirwr_enabled;
/* ccloop c7ee71c6 sess2: eager per-ifree durability chain (default 0). */
extern int mxfs_ifree_eager_durable;
extern int mxfs_inact_defer_unlock;
/* ccloop c7ee71c6 sess2: coalesced background destage kick. */
void mxfs_destage_kick(struct xfs_mount *mp);
/* ccloop 72513a13: max -EAGAIN requeue cycles for a deferred extent-free
 * whose blocking AG-DLM acquire returned -ETIMEDOUT (peer-held AG under
 * saturation).  Each cycle re-registers the 120s CAW waiter.  0 = legacy
 * fail-fatally-on-first-timeout.  See xfs_extent_free_finish_item. */
extern int mxfs_efi_agwait_max;
/* sess10(a9a03929): runtime scope for the storm-dir probe family (reuses the
 * pre-existing mxfs_watch_ino modparam defined in xfs_mxfs_dlm.c).
 * 0 = legacy ino<=256; nonzero = only that inode. */
extern unsigned long long mxfs_watch_ino;
/* sess10: watch INTENSITY.  watch_light=1 keeps the cheap content traces
 * (P13-LADD placements, P11-DATALOG, P9-LFREE, P10-RDBLK, P-DIRWR, P50-RD)
 * but SKIPS the heavy per-placement sync platter reads (P13-COLLIDE /
 * P49-STALEBASE walk) whose I/O amplification measurably re-times the race
 * (7 armed dir_reuse runs never failed; unarmed fails ~1/3). */
extern int mxfs_watch_light;
static inline bool mxfs_ino_watched(uint64_t ino)
{
	unsigned long long w = READ_ONCE(mxfs_watch_ino);

	return w ? (ino == (uint64_t)w) : (ino <= 256);
}
#define mxfs_idbg(fmt, ...) \
	do { if (unlikely(mxfs_instr_enabled)) pr_warn(fmt, ##__VA_ARGS__); } while (0)
#define mxfs_idbg_once(fmt, ...) \
	do { if (unlikely(mxfs_instr_enabled)) pr_warn_once(fmt, ##__VA_ARGS__); } while (0)

/*
 * NEWARCH Phase 0 measurement instrument — DELIBERATELY SLOW.
 *
 * When mxfs.force_coherent=1 every dir/inode cached fast-path acquire is
 * demoted to slow-path, and every cached dir-block buffer is invalidated
 * on read so the sanctioned read path refetches from the (SCST-coherent)
 * shared target.  Result: every lookup pays a full CAW slot round-trip +
 * inode reload.  This is the "force fully synchronous" mode used to
 * answer the Phase 0 gate question (NEWARCH §5/Phase 0): does the
 * coherency *contract* still hold once notification cannot be the
 * culprit?  Not a shipping mode — only a measurement.  Probe tag:
 * P0-FCOH (gated behind mxfs.instr to keep dmesg readable under the
 * 4-node criterion).
 */
extern int mxfs_force_coherent;

/* sess1 (ccloop 46efd8b6): iread-PR gate — extent-map-load ILOCK_EXCL maps
 * to cluster PR (see XFS_ILOCK_MXFS_PRIREAD in xfs_inode.h). */
extern int mxfs_iread_pr;

/* sess1 (ccloop 46efd8b6): datascan gen-gate — skip the per-miss O(dir)
 * authoritative data scan while the dir's coherency state is unchanged
 * since the last scan verified the leaf ENOENT-consistent.  See
 * i_mxfs_dscan_clean_key (xfs_inode.h) and mxfs_dir2_datascan_lookup. */
extern int mxfs_dscan_gen_gate;
/* macro (not inline fn): expansion sites have the complete xfs_inode type;
 * this header is also included where the struct is still incomplete. */
#define mxfs_dscan_state_key(dp) \
	(((uint64_t)(dp)->i_dlm_dir_gen << 40) ^ \
	 ((uint64_t)(dp)->i_dlm_dir_valid_epoch << 20) ^ \
	 (uint64_t)(dp)->i_dlm_dir_loaded_gen)

/*
 * Lock path — called from xfs_ilock() before VFS i_rwsem.
 * Checks cached DLM mode; acquires via CAW if cache miss.
 * Blocks if DEMOTING state active (BAST in progress).
 */
void mxfs_dlm_ilock_begin(struct xfs_inode *ip, uint8_t mode);

/*
 * sess9 (ccloop a864) shutdown withdrawal — a force-shut-down mount leaves
 * the cluster DLM instead of contending forever (r13 32/caw collapse).
 * mxfs_dlm_shutdown_withdraw queues m_mxfs_withdraw_work (callable from the
 * non-sleeping xfs_do_force_shutdown); the work fn runs the sleeping v5
 * withdraw (fence acquires + stop disklock heartbeat).
 */
void mxfs_dlm_shutdown_withdraw(struct xfs_mount *mp);
void mxfs_dlm_withdraw_work_fn(struct work_struct *work);

/*
 * Unlock path — called from xfs_iunlock() after VFS i_rwsem released.
 * Decrements holder count. If last holder and BAST pending,
 * processes the BAST (flush + invalidate + DLM release).
 */
void mxfs_dlm_ilock_end(struct xfs_inode *ip, uint8_t mode);

/*
 * sess54: pin an extra EX holder on a dir whose ILOCK_EXCL the caller currently
 * holds, to keep the DLM EX grant across a subsequent ILOCK-dropped durable
 * flush (mxfs_dlm_dir_inode_durable).  Pairs with mxfs_dlm_ilock_end(dp, EX).
 */
void mxfs_dlm_dir_hold_ex(struct xfs_inode *dp);

/*
 * Non-blocking lock — called from xfs_ilock_nowait().
 * Returns true if lock acquired (cached or non-blocking DLM).
 * Returns false if DEMOTING or DLM lock not immediately available.
 */
bool mxfs_dlm_ilock_try(struct xfs_inode *ip, uint8_t mode);

/*
 * IOLOCK demote (EX → SHARED) — adjust holder counts.
 * DLM lock stays at EX (no point downconverting a cached grant).
 */
void mxfs_dlm_ilock_demote(struct xfs_inode *ip);

/*
 * BAST notification from DLM layer.
 * Looks up inode via xfs_iget(INCORE), sets BAST/DEMOTING state.
 * Called from v5_bast_cb via registered callback.
 */
void mxfs_dlm_bast_notify(void *data, uint64_t ino, uint8_t requested_mode);

/*
 * Flush dirty data, invalidate page cache, release DLM lock.
 * Called when DEMOTING state is entered (from BAST work fn or iunlock).
 * Precondition: all local holders have drained.
 */
void mxfs_dlm_bast_process(struct xfs_inode *ip);

/*
 * sess14(a9a03929) SF-DIR TENURE FLOOR: the eager idle-release gates
 * (mxfs_dlm_ilock_end / mxfs_inode_unpin CACHED&&bast_pending arms) keep a
 * young shortform-dir EX tenure across syscall gaps instead of handing it
 * off at every idle moment.  keep_delay (i_dlm_lock held) returns the MHT
 * dwork delay if the tenure must be kept, 0 to release now; arm
 * (i_dlm_lock NOT held) schedules the dwork that will serve the parked
 * BAST at expiry.
 */
unsigned long mxfs_dlm_sf_tenure_keep_delay(struct xfs_inode *ip);
/* sess1 (ccloop 46efd8b6): generalized dir-EX tenure floor (all formats). */
unsigned long mxfs_dlm_dir_tenure_keep_delay(struct xfs_inode *ip);
void mxfs_dlm_sf_tenure_arm(struct xfs_inode *ip, unsigned long delay_j);

/*
 * sess109/sess129: targeted drain — wait for IP's OWN inode log item to leave
 * the AIL (pushing the AIL and kicking the CIL while waiting), without
 * depending on any OTHER AIL item's flushability.  Caller must settle first
 * (xfs_log_force(SYNC) + msleep + xfs_log_force(SYNC)) so the async CIL→AIL
 * insertion has happened.  Used by the bast_process release chokepoint and by
 * xfs_inactive_ifree's post-commit durability step (sess129: the whole-AIL
 * xfs_ail_push_all_sync there deadlocked against a creator holding the parent
 * dir's ILOCK_EXCL while retry-looping in xfs_iget on a NEED_INACTIVE child).
 */
void mxfs_ail_drain_inode_sync(struct xfs_inode *ip);

/*
 * Release cached DLM lock on inode eviction.
 * Cancels pending BAST work, releases DLM lock if held.
 */
void mxfs_dlm_evict(struct xfs_inode *ip);

/*
 * sess44 deferred-publish (see notes/sess43_deferred_publish_design.md).
 *
 * grant_local_new: grant a brand-new (XFS_IGET_CREATE) inode its DLM lock
 * LOCALLY — set i_dlm_mode=EX, state=CACHED, holder++, mark unpublished and
 * link onto mp->m_mxfs_unpub_list — WITHOUT a disk CAW round-trip.  All later
 * local ilocks fast-path.  This is the dominant rsync_paired cost killer:
 * a node-private rsync creates thousands of inodes that no peer ever touches,
 * so they never need an on-disk slot.
 *
 * publish_unpublished: drain the IN-SCOPE part of the unpublished list,
 * acquiring a real on-disk EX slot for each (by inode number).  Called from a
 * peer BAST on a directory/file inode or an AG — the synchronisation point at
 * which a peer is about to be able to reach our locally-granted inodes.
 * Re-establishes BAST routing so we flush each inode's data before the peer
 * reads it.  v0.5.6 (sess29 ccloop 14d31183): scoped — parent_ino != 0 drains
 * entries whose i_mxfs_unpub_parent matches (the released dir's children);
 * agno != NULLAGNUMBER drains entries living in that AG (peer AGI/inobt
 * reachability); entries with unrecorded parent (0) drain in EVERY call.
 * The unscoped whole-list drain claimed ~96k slots cluster-wide at 16 nodes
 * against the 65536-slot CAW table and starved EX waiters into shutdown.
 *
 * unpublish_drop: remove an inode from the unpublished list (clears the flag).
 * Used on the iget error path and inside evict; safe no-op if not unpublished.
 */
void mxfs_dlm_grant_local_new(struct xfs_inode *ip, uint8_t mode);
void mxfs_dlm_rearm_unpublished(struct xfs_inode *ip);
void mxfs_dlm_publish_unpublished(struct xfs_mount *mp, xfs_ino_t parent_ino,
				  xfs_agnumber_t agno);
void mxfs_dlm_publish_dirs_work(struct work_struct *work);
bool mxfs_dlm_unpublish_drop(struct xfs_inode *ip);

/*
 * v0.10.36 read-once demote: queue the release worker for a PR-held clean
 * regular file at last read-only close so the cached PR grant does not
 * linger on the CAW slot to be BAST-stripped by a later unlink storm
 * (mxfs.close_release, default on).  Called from xfs_file_release.
 */
void mxfs_dlm_close_release(struct xfs_inode *ip);

/*
 * v0.10.38 dir-EX-BAST idle-PR sweep worker (mxfs.dir_ex_bast_sweep).
 * INIT_WORK'd on m_mxfs_pr_sweep_work at mount; queued (rate-limited) by
 * mxfs_dlm_bast_process when a PR-held directory is stripped by a peer's
 * exclusive request.
 */
void mxfs_dlm_pr_sweep_work_fn(struct work_struct *work);

/*
 * NEWARCH Phase 1.4 — publish-on-create.  Synchronously promote one
 * unpublished inode to a real on-disk CAW slot.  Called from xfs_create
 * after xfs_trans_commit and before any namespace exposure
 * (xfs_iunlock + xfs_parent_finish + ipp publish), so the inode is
 * never namespace-visible while invisible in the on-disk holder
 * bitmap.  Closes the sess107 deferred-publish hazard: a peer reaching
 * an unpublished inode (via a cached parent dirent) acquires its empty
 * slot CLEANLY and never BASTs the creator → both nodes believe they
 * hold EX → durable lost update + AG corruption.
 *
 * Safe no-op if the inode is already published or unpublished is
 * disabled (single-node).  No-op for AG-type and other resources.
 */
void mxfs_dlm_publish_inode(struct xfs_inode *ip);

/*
 * Initialize DLM lock caching for this mount.
 * Registers the BAST callback with the DLM layer.
 * Called from xfs_fs_fill_super after mxfs_v5_dlm_init.
 */
void mxfs_dlm_cache_init(struct xfs_mount *mp);

/*
 * Initialize per-inode DLM fields.
 * Called from xfs_inode_alloc when a new xfs_inode is created.
 */
void mxfs_dlm_inode_init(struct xfs_inode *ip);

/*
 * Reload an inode's in-memory state from disk.  Used by xfs_iget_cache_hit
 * when the cached inode has i_dlm_stale set and the caller needs the
 * latest on-disk state (e.g., the iget(CREATE) free-state check).  The
 * caller must ensure on-disk state is stable for the duration — typically
 * by holding the AG DLM lock so peers cannot modify the dinode.
 */
/*
 * sess96: expect_ftype is the AUTHORITATIVE dirent ftype (XFS_DIR3_FT_*) when
 * the reload is triggered by a directory lookup whose dirent type is known;
 * pass XFS_DIR3_FT_UNKNOWN (0) when no dirent context.  Used to BYPASS the
 * sess90 typeflip-stale guard when the disk inode's type matches the dirent
 * (disk+dirent agree = genuine reuse, not a torn read).
 */
/* sess58: post_release=true means this reload follows a release+reacquire of
 * the inode's DLM lock (the slow-path from-NL acquire) — Invariant 1 drained
 * our mods at release, so on-disk is a SUPERSET (our entries + the peer's) and
 * a DIRECTORY reload is safe even with own log mods in flight (it cannot lose
 * our work).  post_release=false is a same-tenure FASTEX refresh where our
 * dir-grow may be in-flight-not-drained; reloading there would roll it back
 * (the sess36 regression), so the own-mods-in-flight self-skip is kept. */
void mxfs_dlm_reload_inode(struct xfs_inode *ip, uint8_t expect_ftype,
			   bool post_release);
/* <ccloop sess49> dir-fork delalloc tripwire (RULE 4): localize where a dir
 * data fork acquires a DELAYSTARTBLOCK extent (the 8/tcp DABUF_MAP_HOLE root). */
int mxfs_dir_delalloc_tripwire(struct xfs_inode *ip, const char *site);
/* sess68: owner-based evict of ALL cached dir metadata blocks (data/leaf/free/
 * node/bmbt) owned by ip, regardless of the current extent map.  Drops the
 * orphaned prior-incarnation blocks at reused daddrs that the per-extent-map
 * evict cannot reach (leaf-vs-data tear / ABA stale-block on inode reuse).
 * O(whole cache) — call only on shrink/incarnation-change adopt paths. */
void mxfs_dir_evict_owned_dir_blocks(struct xfs_inode *ip, bool leaf_only);
/* sess61: adopt a peer's committed dir format/content (FUA dinode check) before
 * a modify RMW; drops+reloads+retakes ILOCK (lock_flags) while DLM EX held. */
bool mxfs_dir_modify_adopt_disk_format(struct xfs_inode *dp,
				       unsigned int lock_flags);

/* sess55: producer bridge for the inode-eviction ring — called from xfs_ifree()
 * to tell passively-caching peers this node freed `ino` (incarnation gen `gen`). */
void mxfs_dlm_note_inode_freed(struct xfs_mount *mp, uint64_t ino, uint32_t gen);

/* sess80: producer bridge for a DIR_MODIFY eviction-ring entry — called from
 * the dir-modify chokepoints (xfs_dir_createname/removename/replace) so
 * passively-caching peers re-read this shared directory's blocks. */
void mxfs_dlm_note_dir_modified(struct xfs_mount *mp, uint64_t dir_ino);

/* sess82: durability-ordered dir-modify signal — push the dir's data blocks to
 * disk synchronously, THEN stage the DIR_MODIFY signal, so a peer's FUA-re-read
 * on receiving the signal is guaranteed to see the committed change.  Caller
 * holds dp ILOCK. */
void mxfs_dlm_dir_durable_signal(struct xfs_inode *dp);

/* sess13: PROACTIVE shortform-parent-dir cluster durability — call from
 * xfs_create AFTER the parent ILOCK is dropped.  Makes a shortform parent's
 * inode cluster (carrying the just-added inline dirent) platter-durable so a
 * peer's cold read of the parent sees the new child immediately (closes the
 * test_unlink_visibility ENOENT-on-fresh-dir window).  No-op for non-shortform
 * dirs and single-node.  MUST be called with dp ILOCK DROPPED. */
void mxfs_dlm_dir_inode_durable(struct xfs_inode *dp);
/* sess3(a9a03929): ungated body — the BAST-release drain's inode-cluster
 * destage.  Runs on EVERY transport (the per-op TCP gate lives only in the
 * wrapper above); internally dirty-gated so read-only holders pay nothing. */
void __mxfs_dlm_dir_inode_durable(struct xfs_inode *dp);

/* sess1(a9a03929): per-dirop durability barriers are CAW-only by default —
 * TCP peers always coordinate via the DLM so the BAST-release drain publishes
 * before any peer read.  dirop_durable_tcp=1 restores legacy behavior. */
bool mxfs_dirop_durable_needed(struct xfs_mount *mp);

/* sess97: consumer-side eager dir-block refresh — call at the top of every
 * cross-node directory READ (readdir/lookup).  When a peer has modified the
 * dir since our last refresh (i_dlm_dir_gen advanced), eagerly drops all clean
 * cached dir DATA blocks so the read refetches the peer's durable image. */
void mxfs_dlm_dir_consumer_refresh(struct xfs_inode *dp);
/* sess103: MODIFY-path sibling — caller already holds dp ILOCK_EXCL (xfs_remove/
 * xfs_rename/xfs_create via xfs_trans_alloc_dir), so this does NOT re-lock.
 * Cold-reads the peer's durable dir image before a shared-dir RMW so the modify
 * never resurrects a peer's already-committed dirent removals (durable
 * lost-update). */
void mxfs_dlm_dir_modify_refresh(struct xfs_inode *dp);
/* sess13: pre-ILOCK shortform-dir reload for the modify paths (MODE B
 * resurrection fix).  Caller must hold NO dp ILOCK (call before
 * xfs_trans_alloc*); consumes MXFS_IF_DIR_RELOAD and reloads the dinode so a
 * shortform RMW never works from a peer-stale inline-dirent base. */
void mxfs_dlm_dir_modify_reload_prelock(struct xfs_inode *dp);
/* sess17: block-level dirent UNION-MERGE — re-add peer dirents missing from our
 * in-core block-format dir, each in its own transaction.  Called at the modify
 * pre-lock hook (no outer trans / no ILOCK held).  Gated by mxfs.dir_merge. */
void mxfs_dir_merge_peer_blocks(struct xfs_inode *dp);

/* sess18: block-dir union-merge folded into the CALLER's transaction, reusing
 * the create's already-held dir-EX grant (NO extra DLM acquire — the fatal flaw
 * of v1/v2).  Caller holds dp ILOCK_EXCL + ijoin'd to tp with reservation
 * headroom; re-adds up to max_ents peer dirents missing from our in-core dir so
 * the create RMWs a union base.  Gated by mxfs.dir_merge. */
void mxfs_dir_merge_peer_into_tp(struct xfs_trans *tp, struct xfs_inode *dp,
				 int max_ents);
extern int mxfs_dir_merge_enabled;	/* module_param dir_merge (default 0) */

/* sess31: cheap per-block reconcile of kept-stale in-AIL dir DATA blocks, folded
 * into the caller's create transaction; consumes MXFS_IF_DIR_DATA_STALE.  Gated
 * by mxfs.dir_stale_reconcile (default 0). */
void mxfs_dir_reconcile_stale_data_blocks(struct xfs_trans *tp,
					  struct xfs_inode *dp);
extern int mxfs_dir_stale_reconcile;
/* sess32 A-vs-B probe: after create RMW, log peer dirents absent from in-core
 * (stale-base proof).  Read-only, gated mxfs.dir_postrmw_probe. */
void mxfs_dir_postrmw_probe(struct xfs_inode *dp);
extern int mxfs_dir_postrmw_probe_enabled;
#define MXFS_DIR_MERGE_MAX 16		/* max peer dirents merged per create */

/* sess34: drain-side disambiguated merge — per-tenure removed-set. */
extern int mxfs_dir_drain_merge;
void mxfs_dir_record_removed(struct xfs_inode *dp, xfs_ino_t ino);
bool mxfs_dir_was_removed(struct xfs_inode *dp, xfs_ino_t ino);
bool mxfs_dir_remset_valid(struct xfs_inode *dp);
bool mxfs_dir_name_incore_global(struct xfs_inode *dp, const char *name,
				 int namelen, xfs_daddr_t skip_d);

/* sess65: pending local-dirent replay (node1_f1 double-block0 orphan fix). */
#define MXFS_PEND_REPLAY_MAX	4	/* max our-dirent replays per create */
void mxfs_dir_pending_add(struct xfs_inode *dp, const struct xfs_name *name,
			  struct xfs_inode *cip);
void mxfs_dir_pending_replay(struct xfs_trans *tp, struct xfs_inode *dp,
			     xfs_extlen_t resblks);

/* sess18: force new multinode dirs to block format at mkdir (kills the sf->block
 * transition race = proven root of the 2/tcp durable dir lost-update). */
extern int mxfs_dir_force_block;	/* module_param dir_force_block (default 0) */
extern int mxfs_dir_iflush_fence;	/* sess65: module_param dir_iflush_fence (default 0) — lowest-block0-wins dir-inode flush fence */
bool mxfs_dir_should_force_block(struct xfs_inode *dp);

/* sess56/sess80: consumer of the eviction ring — invoked by the disklock
 * heartbeat monitor (registered via mxfs_v5_dlm_set_evict_cb in cache_init)
 * for each entry a peer publishes.  type==INODE_FREE flags a stale NL-cached
 * copy XFS_ISTALE_CAW; type==DIR_MODIFY bumps a cached dir's i_dlm_dir_gen.
 * data == xfs_mount*. */
void mxfs_dlm_evict_inode_cb(void *data, uint64_t ino, uint32_t gen,
			     uint32_t type);

/* sess40: invalidate a stale cached AG-meta buffer so the next read FUA-re-reads
 * a peer's committed free-space (anti AG double-alloc). Called from AG-meta read
 * paths (xfs_read_agf/agi/agfl, alloc/inobt btree block reads). */
struct xfs_perag;
void mxfs_ag_meta_invalidate_stale(struct xfs_mount *mp, struct xfs_perag *pag,
				   xfs_daddr_t d, int len);
/* sess133: dir data-fork bmbt child-block read coherency.  Invalidates a clean
 * cached bmbt block whose b_mxfs_dir_gen lags the owning dir's i_dlm_dir_gen so
 * the lazy xfs_iread_extents walk after a DLM reload re-reads a peer's grown
 * tree instead of mismatching the fresh if_nextents (EFSCORRUPTED shutdown).
 * Called from xfs_btree_read_buf_block for INODE-rooted cursors. */
void mxfs_dir_bmbt_invalidate_stale(struct xfs_inode *dp, xfs_daddr_t d,
				    int len);
/* sess36: dir format-transition (block<->leaf<->node) reuses block-0's daddr
 * in place without advancing the dir generation, so a pre-conversion cached
 * image of that daddr aliases as current and a later writeback clobbers the
 * post-conversion block.  Bump i_dlm_dir_gen + loaded_gen at the conversion
 * site and stamp the live converted buffers so pre-conversion buffers are
 * detected stale (bgen < dir_gen) by the read-invalidation / write guards. */
void mxfs_dir_gen_bump_on_convert(struct xfs_inode *dp, struct xfs_buf *dbp,
				  struct xfs_buf *lbp);
/* sess117: gen-independent acquire-side cold-read.  Discards every CLEAN cached
 * bnobt/cntbt buffer in the AG so the first allocator access after a fast-path
 * AG re-grant (cached / release_pending reclaim) cold-reads the peer's durable
 * free-space tree.  Closes the P93-REVERT-CLOBBER gap the frozen meta-gen and
 * slow-path-only invalidate_ag_meta leave open. */
void mxfs_ag_meta_coldread_discard(struct xfs_perag *pag, bool fresh_peer);
/* sess42 P70 diagnostic: 1=in-core differs from on-disk (stale read),
 * 0=identical (on-disk inconsistency), <0 error.  Caller holds buf locked. */
struct xfs_buf;
int mxfs_ag_buf_disk_differs(struct xfs_buf *bp);
/* sess91 ROOT FIX: true if the buffer carries a logged-but-not-checkpointed
 * (in-core authoritative) modification — pinned, has a BLI / non-empty
 * b_li_list, or is delwri-queued.  Re-reading disk over such a buffer clobbers
 * the uncheckpointed change (the lost-update family).  Used to guard every
 * XBF_DONE-clear / FUA-re-read of inode-cluster and AG-meta buffers. */
bool mxfs_buf_has_uncheckpointed_mods(struct xfs_buf *bp);
/* sess120 (Gemini RULE-5): LSN-precise "is this AG-meta buffer ahead of disk?"
 * Compares the payload write-LSN (bb_lsn/agf_lsn/...) against the BLI li_lsn.
 * Distinguishes a drained-but-AIL-lingering buffer (false) from an un-destaged
 * one (true) — the discriminator the in-AIL flags alone could not provide. */
bool mxfs_buf_is_undestaged(struct xfs_buf *bp);
/* sess133: same discriminator for dir3 data/block/leaf/free, da3 node and
 * bmbt buffers (payload-LSN vs li_lsn).  Lets the read-side gen invalidation
 * refresh a destaged-but-AIL-lingering stale dir/bmbt block (the true-silent-
 * dirent-loss window) while still protecting committed-unwritten work. */
bool mxfs_dir_buf_is_undestaged(struct xfs_buf *bp);
/* sess79 direction probe: on-disk bnobt/cntbt level-0 numrecs + rec0 via FUA. */
int mxfs_ag_buf_disk_bnobt(struct xfs_buf *bp, uint16_t *disk_nr,
			   uint32_t *disk_s0, uint32_t *disk_l0);
/* sess43 P71 diagnostic: on-disk agi_unlinked[bucket] head via FUA read.
 * 0xfffffffe = read error (distinct from NULLAGINO 0xffffffff). */
uint32_t mxfs_agi_disk_bucket_head(struct xfs_buf *agibp, int bucket);
/* sess43 P71 diagnostic: on-disk di_mode of this inode via FUA. 0=freed by peer
 * (cross-node double-inactivation), nonzero=allocated, <0 error. */
struct xfs_inode;
int mxfs_inode_disk_mode(struct xfs_inode *ip, uint32_t *nlink_out);

/*
 * Reset a cached inode's in-memory state to "free" without reading disk.
 * Used by xfs_iget_cache_hit when the caller is xfs_dialloc/IGET_CREATE:
 * the inobt (under AG DLM hold) has already certified the inode is free,
 * but our local cached struct may carry stale allocated content from
 * this node's prior use.  Reading from disk is wrong because xfs_ifree
 * never writes zeros to a freed slot — the on-disk content remains the
 * last iflushed alloc'd state.  Mirrors xfs_inode_uninit's in-memory
 * transformation (mode=0, fork teardown) without the on-disk transaction
 * operations, since the on-disk free was performed by the peer.
 */
void mxfs_dlm_reset_inode_for_create(struct xfs_inode *ip);

/*
 * AG allocation lock — per-AG DLM EX lock with node-local holder counting.
 * Prevents double-allocation across nodes for both blocks and inodes.
 * Holder counting handles nesting (inode alloc → block alloc in same AG).
 */
int  mxfs_ag_dlm_lock(struct xfs_mount *mp, struct xfs_perag *pag);
int  mxfs_ag_dlm_trylock(struct xfs_mount *mp, struct xfs_perag *pag);
int  mxfs_ag_dlm_lock_bounded(struct xfs_mount *mp, struct xfs_perag *pag);
void mxfs_ag_dlm_unlock(struct xfs_mount *mp, struct xfs_perag *pag);

/*
 * Defer the AG DLM unlock to xfs_trans_free time.  Used by xfs_alloc /
 * xfs_ialloc success paths so the DLM remains held while the allocation's
 * trans is alive — without this defer, the trans's AG-meta modifications
 * may not be in CIL when bast_work_fn's xfs_log_force(SYNC) runs, and a
 * peer can ACQ-FRESH and observe pre-allocation disk content.  See
 * priority-2 root cause in /src/mxfs/p15-analysis.md run-4.
 */
void mxfs_ag_dlm_unlock_deferred(struct xfs_trans *tp, struct xfs_perag *pag);
void mxfs_trans_drain_ag_unlocks(struct xfs_trans *tp);
/* FIX-21 (sess8 a9a03929): selective AG-grant migration at xfs_trans_dup —
 * carry forward only grants for AGs still referenced by pending defer work
 * items; the rest release at the old tp's trans_free (convoy breaker). */
void mxfs_trans_migrate_ag_unlocks(struct xfs_trans *tp, struct xfs_trans *ntp);
/* sess8: shortform-dir name-list formatter for the resurrection tracers
 * (P8-SFRM / P8-SFIFLUSH / P8-SFADOPT), gated by mxfs_dir_relverify. */
struct xfs_dir2_sf_hdr;
void mxfs_sf_fmt_names(struct xfs_mount *mp, struct xfs_dir2_sf_hdr *sfp,
		       char *buf, size_t sz);

/*
 * sess77: Pre-acquire per-AG DLM locks for a set of inodes in ascending AG
 * order BEFORE any inode ILOCK is taken — breaks the rename hold-and-wait
 * deadlock (see definition in xfs_mxfs_dlm.c).  Returns 0 on success.
 */
int  mxfs_trans_preacquire_inode_ags(struct xfs_trans *tp,
				     struct xfs_inode **inodes, int num_inodes);

/*
 * Inode-DLM bast deferral (Approach A — priority-3 dir-stale Mode A and
 * "Free inode N has blocks allocated").  When mxfs_dlm_ilock_end fires
 * with a pending BAST and there's an active trans on this task
 * (current->journal_info), the bast_process call (flush + DLM release)
 * is deferred onto the trans's t_mxfs_inode_unlocks list and fired from
 * mxfs_trans_drain_inode_unlocks at xfs_trans_free time.  Hypothesis:
 * firing bast_process while iop_unlock loop is still running, or while
 * trans-bound inode log items haven't reached the AIL, lets a peer
 * ACQ-FRESH and read pre-modification disk state.
 *
 * Returns true if the bast was queued for deferred processing; false if
 * the caller should fire bast_process inline (no trans context, or the
 * pending-entry allocation failed).
 */
bool mxfs_inode_dlm_defer_bast(struct xfs_trans *tp, struct xfs_inode *ip);
void mxfs_trans_drain_inode_unlocks(struct xfs_trans *tp);

/*
 * AG-metadata coherency hooks.
 *
 * mxfs_buf_is_ag_metadata: true if bp->b_ops matches one of the AG
 * metadata buffer types (AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt/
 * rmapbt/refcountbt) — i.e. a buffer whose stale on-disk image
 * a peer would observe via xfs_buf_read against the home block.
 *
 * mxfs_ag_meta_track: called from xfs_trans_log_buf when an
 * AG-metadata buffer is logged in multi-node mode.  Increments the
 * owning AG's pag_dlm_meta_pending, holds an extra buffer reference,
 * and installs mxfs_dlm_ag_meta_iodone as bp->b_iodone so the count
 * can be decremented on writeback completion.  Idempotent within a
 * single dirty epoch via XFS_BLI_MXFS_AGMETA_TRACKED.
 *
 * mxfs_dlm_ag_meta_iodone: per-buffer write-completion callback.
 * Decrements pag_dlm_meta_pending; if it hits zero AND the AG-lock
 * release was deferred AND no local holder is active, fires the
 * actual mxfs_v5_dlm_ag_unlock so peers can acquire.
 */
bool mxfs_buf_is_ag_metadata(struct xfs_buf *bp);
/* sess23 (ccloop): true if xfsaild's iop_push MUST NOT write this AG-meta
 * buffer because we do not currently hold the AG's DLM grant (a peer owns it
 * and our cached image is a stale prior-tenure log-tail artifact).  Caller
 * stales+drops it instead of reverting the peer's durable allocation.  See the
 * definition in xfs_mxfs_dlm.c for the full PROVEN rationale. */
bool mxfs_buf_xfsaild_skip_agmeta_write(struct xfs_buf *bp);
/* sess60: bmbt analogue — skip xfsaild writeback of a bmbt extent-map block
 * whose owner directory inode this node has released (i_dlm_mode==NL), so a
 * stale prior-tenure leaf image cannot clobber a peer's newer one. */
bool mxfs_buf_xfsaild_skip_bmbt_write(struct xfs_buf *bp);
/* sess66: MODIFY-TIME tenure stamp for a dir's bmbt buffers (bmbt analogue of
 * mxfs_ag_meta_track); called from xfs_trans_log_buf.  Stamps b_tenure_id with
 * the owner dir's EX-tenure epoch so xfsaild can drop a prior-tenure stale leaf
 * instead of clobbering a peer's durable image. */
void mxfs_dir_bmbt_track(struct xfs_buf *bp);
/* sess17 (ccloop): dir DATA/leaf-block analogue of the bmbt pair.  _track stamps
 * b_tenure_id at MODIFY time (from xfs_trans_log_buf); _skip suppresses an
 * xfsaild writeback of a dir DATA/leaf/block/free/node buffer whose owner dir
 * this node has released (NL) or whose image is from a prior EX tenure, so a
 * stale lingering BLI cannot clobber a peer's newer durable dirent block. */
void mxfs_dir_data_track(struct xfs_buf *bp);
/* Diagnostic snapshot of the skip-predicate state, filled by
 * mxfs_buf_xfsaild_skip_dir_write so the chokepoint can log P16-DIRBLK-SUBMIT
 * (detector) and act on the same single inode lookup. */
struct mxfs_dir_skip_info {
	uint64_t	owner;		/* owner ino from the dir3 block header */
	bool		is_dir_buf;	/* bp is a dir3 data/leaf/block/free/node */
	bool		in_core;	/* owner inode resolved in cache as a dir */
	int		mode;		/* owner i_dlm_mode, or -1 if not in_core */
	uint64_t	tenure_id;	/* bp->b_tenure_id (modify-time stamp) */
	uint64_t	cur_epoch;	/* owner i_mxfs_ex_grant_seq, or 0 */
	bool		nl_released;	/* owner grant released (NL) */
	bool		tenure_mismatch;/* image from a prior EX tenure */
	bool		incarn_aba;	/* sess40: buffer from a DEAD prior incarnation
					 * (b_mxfs_dir_incarn != owner i_generation) */
	bool		reflush_skip;	/* sess33: EX-held already-destaged clean dir
					 * buffer pure-redundant reflush suppressed */
	bool		tenure_reflush;	/* sess37: EX-held CLEAN destaged in-AIL dir
					 * buffer whose bgen<dir_gen (prior-tenure,
					 * not re-read since a handoff) — zombie
					 * reflush of superseded content; skip */
	bool		relepoch_skip;	/* sess50: CLEAN dir buffer whose b_mxfs_relepoch
					 * < owner i_dlm_epoch — this node RELEASED the dir
					 * grant since this image was coherent, so a peer may
					 * have superseded the block (PROVEN xnode=1 cross-node
					 * reflush); skip the revert (clean = already durable). */
	uint32_t	dir_gen;	/* owner i_dlm_dir_gen (peer-modify counter) */
	uint32_t	loaded_gen;	/* owner i_dlm_dir_loaded_gen (last adopted) */
	uint32_t	buf_incarn;	/* sess40: bp->b_mxfs_dir_incarn at write */
	uint32_t	cur_incarn;	/* sess40: owner VFS i_generation at write */
	int		active_count;	/* sess48: active dirents in the block being
					 * written (block-fmt count-stale, incl
					 * . + ..), or -1 if not computable */
	uint64_t	realns;		/* sess48: wall-clock at write submit, for
					 * cross-node write-ordering correlation */
	uint32_t	cached_grant_gen; /* sess50(ccloop): owner i_dlm_cached_grant_gen
					 * (the RELIABLE acked-TCP per-grant epoch) at
					 * write submit.  Compared to bp->b_mxfs_grant_gen
					 * (the epoch the buffer image was last read/born
					 * under) to discriminate a SUPERSEDED prior-grant
					 * lingering buffer (mismatch = the clobber) from a
					 * current-tenure legit op (match) — the temporal
					 * token content-compare lacks (sess69 CONCLUSIVE). */
};
bool mxfs_buf_xfsaild_skip_dir_write(struct xfs_buf *bp,
				     struct mxfs_dir_skip_info *info);
bool mxfs_dir_zombie_push_retire(struct xfs_buf *bp);	/* sess33 */
/* sess25: defer (keep in AIL, no I/O) a background xfsaild destage of an
 * EX-held contended multi-node dir DATA/LEAF block; land it via release-drain. */
bool mxfs_dir_ail_push_defer(struct xfs_buf *bp);
/* sess60 RULE-4 probe: log bmbt-leaf WRITE numrecs + owner hold state. */
void mxfs_bmbt_write_probe(struct xfs_buf *bp);
/* Phase 4/sess29: superset of is_ag_metadata; also covers inode cluster
 * bufs.  Used at the FUA-read gate in pal/linux/xfs_buf.c.  See the
 * function comment in xfs_mxfs_dlm.c for rationale. */
bool mxfs_buf_needs_fua_read(struct xfs_buf *bp);
/* sess79 FUA instrumentation + AG-ownership FUA-skip measurement lever. */
void mxfs_fua_count(struct xfs_buf *bp);
bool mxfs_buf_ag_owned_ex(struct xfs_buf *bp);
extern int mxfs_fua_skip_owned_inode;
extern int mxfs_inode_cluster_owned_skip;
extern atomic64_t mxfs_fua_inode_owned_skip;
extern atomic64_t mxfs_fua_scsi_actual;
extern atomic64_t mxfs_fua_p91_skip;
extern atomic64_t mxfs_iget_cluster_staled;
extern int mxfs_fua_disable;
extern int mxfs_publish_dirs;
void mxfs_ag_meta_track(struct xfs_buf *bp);
void mxfs_dlm_ag_meta_iodone(struct xfs_buf *bp);
void mxfs_ag_meta_reclaim_abort(struct xfs_buf *bp);
extern int mxfs_dbg_dialloc_shutdown;	/* DEBUG one-shot AGI umount-wedge test */

/*
 * v0.3.70: returns true while the FUA-read window is open for the AG that
 * owns this buffer.  The window opens for HZ/2 after each
 * mxfs_dlm_invalidate_ag_meta call.  Outside the window, callers should
 * fall through to the bio path so cached buffers (with our in-memory
 * modifications) remain authoritative.  Returns false if buf has no
 * pag (non-AG-resident, e.g., inode cluster bufs may live in the
 * buftarg cache).  For non-pag bufs the FUA hook should still fire
 * (use a separate predicate for those).
 */
bool mxfs_buf_in_fua_window(struct xfs_buf *bp);

/*
 * Cached AG DLM (OCFS2-style).  When the last local holder of an AG DLM
 * exits, the grant is kept on disk; pag_dlm_cached is set.  A peer that
 * needs the AG sends a BAST → mxfs_dlm_ag_bast_notify schedules
 * mxfs_dlm_ag_bast_work_fn, which drains pending writes for the AG
 * (cluster buffers, AG-meta buffers, inode-cluster buffers with pending
 * iflushes) and then calls mxfs_v5_dlm_ag_unlock for real.
 *
 * Eliminates the iflush-during-no-holder window in which xfsaild could
 * dirty cluster buffers between a local unlock and a local re-acquire,
 * leaving the on-disk cluster out of sync with peer-modified copies.
 */
struct work_struct;
void mxfs_dlm_ag_bast_notify(void *data, uint32_t agno, uint8_t mode);
void mxfs_dlm_ag_bast_work_fn(struct work_struct *work);
/* sess39: deferred-release flush+unlock worker (runs off the xfs-buf wq). */
void mxfs_dlm_ag_release_work_fn(struct work_struct *work);
/* sess39: FUA-write a buffer's content to the backing store (cross-node
 * di_size durability for the file-inode release). */
int mxfs_buf_write_fua(struct xfs_buf *bp);
void mxfs_dlm_ag_force_release_all(struct xfs_mount *mp);

/*
 * v0.3.62: SCSI READ(16) FUA passthrough for AG-metadata buffer reads.
 *
 * Multi-initiator iSCSI/LIO storage stacks may serve reads from a
 * per-initiator read cache that does not see another initiator's prior
 * writes — even when those writes were FUA.  v0.3.58 fixed the disklock
 * CAW slot read path; this declaration exposes the same SCSI passthrough
 * helper for use by the xfs_buf path so AG-metadata reads (AGI/AGF/
 * AGFL/bnobt/cntbt/inobt/finobt) can also bypass the LIO read cache.
 *
 * lba_512 is in 512-byte units relative to the start of bdev (NOT the
 * partition base).  Returns 0 on success; -EOPNOTSUPP if bdev is not a
 * SCSI sdev (caller falls back to bio path); other negative errno on
 * SCSI error.
 */
struct block_device;
int mxfs_pal_scsi_read_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				 void *buf, uint32_t len);
/* v0.3.117 sess29: WRITE(16) FUA passthrough.  Used by surgical
 * FUA-rewrite of released bufs in mxfs_dlm_bast_process. */
int mxfs_pal_scsi_write_fua_bdev(struct block_device *bdev, uint64_t lba_512,
				   const void *buf, uint32_t len);

/* v0.11.74: deferred PR unregister after the unmount log record — a
 * non-holder that unregisters before xfs_unmountfs bounces its final
 * log write off the peer's WE-RO reservation (EBADE shutdown). */
int mxfs_pal_scsi_pr_unregister_bdev(struct block_device *bdev, uint64_t key);

/* sess47 diagnostic: FUA-read the on-disk di_mode of a bare inode number
 * (0 = free on disk).  Used at the AG bnobt double-free site to tell a
 * lost-bnobt-removal (A) from a stale-cached-inode double-free (B). */
struct xfs_mount;
uint16_t mxfs_dbg_disk_di_mode(struct xfs_mount *mp, uint64_t ino,
			       uint32_t *genp);

#endif /* XFS_MXFS_DLM_H */

/* ICLUSTER mediating layer (ccloop 72513a13 sess3 — DLM_PLAN.md "ICLUSTER
 * PLAN").  Phase-1 core is landed and inert; mxfs.icluster_dlm stays 0
 * until the BAST fan-out + call-site routing land (state.md). */
extern int mxfs_icluster_dlm;
int mxfs_iclus_lock(struct xfs_mount *mp, uint64_t ino, uint8_t mode);
int mxfs_iclus_unlock(struct xfs_mount *mp, uint64_t ino, uint8_t mode,
		      bool is_free);
void mxfs_iclus_bast_notify(void *data, uint64_t base_ino, uint8_t req_mode);
bool mxfs_iclus_try_admit(struct xfs_mount *mp, uint64_t ino, uint8_t mode);
bool mxfs_dlm_iclus_covered(struct xfs_inode *ip);
uint8_t mxfs_iclus_granted_mode(struct xfs_mount *mp, uint64_t ino);
uint64_t mxfs_iclus_grant_seq(struct xfs_mount *mp, uint64_t ino);
void mxfs_iclus_purge_all(struct xfs_mount *mp);
