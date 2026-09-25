/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2018 Red Hat, Inc.
 * All rights reserved.
 */

#ifndef __LIBXFS_AG_H
#define __LIBXFS_AG_H 1

#include "xfs_group.h"

struct xfs_mount;
struct xfs_trans;
struct xfs_perag;

/*
 * Per-ag infrastructure
 */

/* per-AG block reservation data structures*/
struct xfs_ag_resv {
	/* number of blocks originally reserved here */
	xfs_extlen_t			ar_orig_reserved;
	/* number of blocks reserved here */
	xfs_extlen_t			ar_reserved;
	/* number of blocks originally asked for */
	xfs_extlen_t			ar_asked;
};

/*
 * Per-ag incore structure, copies of information in agf and agi, to improve the
 * performance of allocation group selection.
 */
struct xfs_perag {
	struct xfs_group pag_group;
	unsigned long	pag_opstate;
	uint8_t		pagf_bno_level;	/* # of levels in bno btree */
	uint8_t		pagf_cnt_level;	/* # of levels in cnt btree */
	uint8_t		pagf_rmap_level;/* # of levels in rmap btree */
	uint32_t	pagf_flcount;	/* count of blocks in freelist */
	xfs_extlen_t	pagf_freeblks;	/* total free blocks */
	xfs_extlen_t	pagf_longest;	/* longest free space */
	uint32_t	pagf_btreeblks;	/* # of blocks held in AGF btrees */
	xfs_agino_t	pagi_freecount;	/* number of free inodes */
	xfs_agino_t	pagi_count;	/* number of allocated inodes */

	/*
	 * Inode allocation search lookup optimisation.
	 * If the pagino matches, the search for new inodes
	 * doesn't need to search the near ones again straight away
	 */
	xfs_agino_t	pagl_pagino;
	xfs_agino_t	pagl_leftrec;
	xfs_agino_t	pagl_rightrec;

	uint8_t		pagf_refcount_level; /* recount btree height */

	/* Blocks reserved for all kinds of metadata. */
	struct xfs_ag_resv	pag_meta_resv;
	/* Blocks reserved for the reverse mapping btree. */
	struct xfs_ag_resv	pag_rmapbt_resv;

	/* Precalculated geometry info */
	xfs_agino_t		agino_min;
	xfs_agino_t		agino_max;

#ifdef __KERNEL__
	/* -- kernel only structures below this line -- */

#ifdef CONFIG_XFS_ONLINE_REPAIR
	/*
	 * Alternate btree heights so that online repair won't trip the write
	 * verifiers while rebuilding the AG btrees.
	 */
	uint8_t		pagf_repair_bno_level;
	uint8_t		pagf_repair_cnt_level;
	uint8_t		pagf_repair_refcount_level;
	uint8_t		pagf_repair_rmap_level;
#endif

	atomic_t        pagf_fstrms;    /* # of filestreams active in this AG */

	spinlock_t	pag_ici_lock;	/* incore inode cache lock */
	struct radix_tree_root pag_ici_root;	/* incore inode cache root */
	int		pag_ici_reclaimable;	/* reclaimable inodes */
	unsigned long	pag_ici_reclaim_cursor;	/* reclaim restart point */
	/*
	 * ccloopff21 holder tracking mirroring pag_dlm_holder_pid/comm
	 * below, for diagnosing a soft-lockup where multiple threads spun
	 * forever apparently contending pag_ici_lock (kworker/u10, kworker/u11,
	 * bash all stuck; xfs_icache.c:3201 XFS_ALL_IRECLAIM_FLAGS assert fired
	 * moments before).  Stamped on every acquire; read by a stuck-holder
	 * dump if the lock is ever held anomalously long.
	 */
	pid_t			pag_ici_holder_pid;
	char			pag_ici_holder_comm[16];
	unsigned long		pag_ici_held_since;

	struct xfs_buf_cache	pag_bcache;

	/* background prealloc block trimming */
	struct delayed_work	pag_blockgc_work;

	/* MXFS DLM AG lock state (node-local holder counting) */
	struct mutex	pag_dlm_lock;		/* serializes DLM AG acquire/release */
	int		pag_dlm_holders;	/* node-local holder count */
	/*
	 * Set by the inode-chunk allocation path when a new cluster has
	 * been initialized while holding this AG's DLM lock.  Consumed by
	 * mxfs_ag_dlm_unlock: if true at the last-holder release, force a
	 * full XFS sync so the home-block writes land on disk before a
	 * peer can observe the AGI update.
	 */
	bool		pag_mxfs_alloc_dirty;
	/*
	 * Per-AG delwri list of cluster buffers initialized by
	 * xfs_ialloc_inode_init under this AG's DLM lock.  Drained via
	 * xfs_buf_delwri_submit on the last-holder AG release so the home
	 * LBA is on disk before any peer observes the AGI update.  Scoped
	 * tight (only buffers from this holder's allocations) to avoid
	 * the global-AIL-drain livelock of xfs_ail_push_all_sync.
	 */
	struct mutex		pag_mxfs_alloc_buflist_lock;
	struct list_head	pag_mxfs_alloc_buflist;
	/*
	 * AG-metadata read-side time-travel fence.
	 * Stamped with m_mxfs_flush_epoch at every AG-metadata buffer
	 * (AGF/AGI/AGFL/bnobt/cntbt/inobt/finobt) WRITE COMPLETION on a
	 * multi-node mount.  A completed write means "reached the target's
	 * volatile write cache", NOT media (LIO drops FUA); if the buffer
	 * is then memory-evicted and later COLD-READ via the FUA/platter
	 * path before any device flush, the read returns the PRE-write
	 * media image and the in-core free-space state REGRESSES — the
	 * proven double-allocation mechanism (iter_10: same node re-
	 * allocated agno7/295 over its own live uv-dir block 136s later;
	 * three AGs on three nodes in one window; every DLM-handoff probe
	 * silent because no handoff is involved).  Cold reads of AG
	 * metadata consult this: epoch >= current flush epoch → device
	 * flush first (mxfs_release_coalesced_flush), then read.
	 */
	atomic64_t		pag_mxfs_meta_wr_epoch;
	/*
	 * (rsync-rename producer, fossil di_next_unlinked): sibling of
	 * pag_mxfs_meta_wr_epoch for INODE CLUSTER buffers, which
	 * mxfs_agmeta_ops deliberately excludes.  Stamped at every cluster
	 * write completion; the cold-read side currently only REPORTS
	 * (P-INOCL-COLDREAD) — fence action pending instrumented proof.
	 */
	atomic64_t		pag_mxfs_inocl_wr_epoch;
	/*
	 * (foreign-replay authority token, step 2a): the durable
	 * exclusive-grant epoch of this AG's CURRENT CAW tenure — the
	 * generation of the CAS that granted us EX, read back from the
	 * slot at fresh-acquire (the on-disk counterpart of the in-memory
	 * ag_dlm_tenure_id).  Buffer-log records for this AG will carry it
	 * as their authority token; a fenced node's images replay iff
	 * their token matches its slot's held-at-death epoch.  0 = no
	 * authority known (TCP transport, read failure, repaired slot) —
	 * token writers must fail closed (emit no-authority, never 0-as-
	 * valid).  Written only on the fresh-grant path while EX is held.
	 *
	 * step 5.1 — LIFECYCLE INVARIANT.  Every write is under
	 * pag_dlm_lock and uses WRITE_ONCE; the only lock-free reader is
	 * xfs_buf_item_format_segment (READ_ONCE).  The value means:
	 *
	 *   nonzero => this node POSITIVELY HOLDS this AG's EX grant at that
	 *              durable epoch AND no release of it has begun;
	 *   zero    => no authority may be claimed for this AG.
	 *
	 * Publish (nonzero) happens only after the granting CAS succeeds.
	 * Clear (zero) happens at every release-COMMIT point, strictly
	 * BEFORE the drain/flush/on-disk unlock of that release becomes
	 * visible — bast_work_fn Phase 2 (pag_dlm_demoting = true),
	 * mxfs_dlm_ag_force_release_all (unmount), and the single->multi
	 * administrative surrender.  Clearing only at the unlock sites would
	 * leave a window in which an item could capture an epoch this node
	 * is already surrendering.  Cached fast-path re-acquire does NOT
	 * touch it: the slot was never yielded, so the epoch still stands.
	 */
	uint64_t		pag_mxfs_grant_epoch;
	/*
	 * (lineage ruling): the slot binding's
	 * resource_lineage from the SAME grant result that carried
	 * pag_mxfs_grant_epoch.  Identifies WHICH binding of this AG's slot
	 * the epoch namespace belongs to — a slot recycled through a
	 * different resource restarts its epoch sequence, and only the
	 * lineage distinguishes tokens of the old binding from the new.
	 * Same lifecycle as the epoch: published under pag_dlm_lock with
	 * WRITE_ONCE only beside a proving epoch, cleared (0) at every
	 * release-commit point beside the epoch clear, READ_ONCE by the
	 * token producer.  Zero = binding lineage unknown (legacy peer
	 * minted the binding): tokens still emit but are not enforceable
	 * under the v3 lineage gate.  EQUALITY comparisons only.
	 */
	uint64_t		pag_mxfs_grant_lineage;
	/*
	 * (D-0353): the current AG grant came from the CAW single-node
	 * fast path (MXFS_GAUTH_SINGLE_NODE): no slot image, no epoch, but a
	 * legitimate tenure while the DLM is still single-node.  Lets the
	 * P243 epochless-hint guard keep the cached hint within the single-
	 * node era instead of forcing a false-fresh acquire on every call.
	 * Same lifecycle as pag_mxfs_grant_epoch: set at the publish site,
	 * cleared at every release-commit point and by the join barrier.
	 */
	bool			pag_mxfs_grant_single;
	/*
	 * (clean-release marker): the {epoch, lineage} of the tenure
	 * the release COMMIT just detached, saved in the SAME critical section
	 * that zeroes pag_mxfs_grant_epoch/lineage (mxfs_ag_handoff_commit).
	 * Read ONLY by the release worker that follows the COMMIT, to publish
	 * the XFS_LI_MXFS_RELMARK for exactly that tenure after the drain and
	 * before the unlock CAS.  Never authority: nothing may stamp a token
	 * from these.  Zeroed by the worker once the marker is published.
	 */
	uint64_t		pag_mxfs_rel_epoch;
	uint64_t		pag_mxfs_rel_lineage;
	/*
	 * AG-metadata coherency across DLM AG-lock grants.
	 *
	 * pag_dlm_meta_pending: count of AG-metadata buffers (AGF/AGI/AGFL/
	 * btree blocks) that were logged under this AG's DLM hold and have
	 * not yet completed on-disk writeback.  Incremented in
	 * xfs_trans_log_buf via mxfs_ag_meta_track when the buffer's
	 * b_ops matches an AG-metadata type.  Decremented in
	 * mxfs_dlm_ag_meta_iodone (per-buffer b_iodone) on writeback
	 * completion.
	 *
	 * pag_dlm_release_pending: set when the last local AG-lock
	 * holder exits while pag_dlm_meta_pending > 0; the actual DLM
	 * release is then deferred so a peer cannot acquire and read
	 * stale on-disk AG metadata before our writeback lands.
	 * Cleared either by a fast local re-acquire (we still hold the
	 * EX grant) or by mxfs_dlm_ag_meta_iodone when the final pending
	 * buffer's writeback completes (which then triggers the deferred
	 * mxfs_v5_dlm_ag_unlock).
	 */
	atomic_t		pag_dlm_meta_pending;
	bool			pag_dlm_release_pending;
	/*
	 * v0.3.131 (v6a phase 2 proper): bounded yield quantum
	 * for the per-trans alloc-buflist drain.  Decremented in
	 * mxfs_ag_dlm_unlock when the holders==0 path skips drain
	 * (lazy_ag_drain knob); when it reaches 0, the next holders==0
	 * unlock falls through to eager drain regardless of the knob.
	 * Reset to MXFS_BAST_YIELD_QUANTUM on each fresh acquire (or
	 * cached re-acquire from holders==0).
	 *
	 * Caps the amount of dirty AG metadata that can accumulate
	 * before peer's BAST forces drain — without this cap, lazy
	 * drain causes peer starvation (proven by v0.3.130
	 * experiment: T2 stuck for 600s while T1 held cached grants).
	 *
	 * Per docs/v6-cache-architecture-proposal.md §11 + spec D10.
	 */
	int			pag_dlm_yield_remaining;
	/*
	 * v0.3.147 adaptive yield quantum (prescription E).
	 * pag_dlm_yield_quantum_eff is the effective quantum reload value;
	 * adapts dynamically as: halve on peer BAST (fairness signal),
	 * double after MXFS_AG_YIELD_DOUBLE_THRESH consecutive non-contended
	 * eager-drain epochs (no peer asked, we can be more aggressive).
	 * Persists across acquire/release cycles.  Bounded [1, mxfs_ag_yield_quantum].
	 *
	 * pag_dlm_skips_no_bast counts consecutive eager drains without
	 * pag_dlm_bast_pending — used as the "double" trigger.  Cleared
	 * when peer BAST arrives or quantum doubles.
	 *
	 * Both default to 0 (lazy-init at first fresh acquire to
	 * mxfs_ag_yield_quantum).  Disabled by mxfs_ag_yield_adaptive=0,
	 * in which case mxfs_ag_yield_quantum is used as a static cap.
	 */
	int			pag_dlm_yield_quantum_eff;
	int			pag_dlm_skips_no_bast;
	/*
	 * v0.3.70: pag_dlm_fua_window_until — jiffies value until which
	 * the FUA-read hook is permitted on this pag.  Set to
	 * jiffies + HZ/2 on every mxfs_dlm_invalidate_ag_meta run
	 * (fresh-acquire / peer-joined transition).  After the window
	 * expires, AG-meta reads fall through to the bio path so the
	 * cached buffer (which has our in-memory modifications) is the
	 * authoritative content rather than disk.
	 *
	 * Sess22 evidence: T2 alloc'd agbno=22456 len=65520 at
	 * 179860.910, fail at 179864.180 with gtbno=22456 (pre-alloc
	 * state) — T2's own modifications were wiped during exclusive
	 * AG hold.  Hypothesis: a non-fresh-acquire FUA read replaced
	 * the in-memory bnobt buf content with stale on-disk content
	 * (T2's writes hadn't been pushed yet).
	 */
	unsigned long		pag_dlm_fua_window_until;
	/*
	 * Serializes concurrent fresh-acquire attempts on this node.  Held
	 * across mxfs_v5_dlm_ag_lock (the CAW poll loop, up to 120 s) so
	 * pag_dlm_lock can be dropped before the slow call.  Holding
	 * pag_dlm_lock across CAW deadlocks with mxfs_dlm_ag_meta_iodone
	 * (xfs-buf workqueue), which must take pag_dlm_lock to fire the
	 * deferred DLM release that the CAW grant is waiting on.
	 */
	struct mutex		pag_dlm_acquire_lock;
	/*
	 * Cached AG DLM (OCFS2-style).  When the last local holder releases
	 * the AG, the DLM grant is NOT dropped on disk — pag_dlm_cached is
	 * set instead.  The grant stays held until a peer requests it
	 * (BAST → mxfs_dlm_ag_bast_notify) or unmount.  This eliminates the
	 * iflush-during-no-holder window in which xfsaild could populate
	 * cluster buffers between an unlock and a re-acquire on the same
	 * node, which made cross-node cluster-buffer coherency impossible.
	 *
	 * pag_dlm_bast_pending: set by the AG BAST notify when a peer
	 * requests our cached AG; consumed by either the BAST work fn
	 * (drains buffers and calls v5_dlm_ag_unlock) or the last-holder
	 * unlock (schedules the BAST work if a holder is still active when
	 * the BAST arrives).
	 *
	 * pag_dlm_bast_scheduled: idempotency guard so a BAST that arrives
	 * while a previous one's work is still running doesn't queue a
	 * second concurrent worker.
	 */
	bool			pag_dlm_cached;
	/*
	 * per-AG metadata generation, bumped on every multi-node AG
	 * fresh-acquire.  The AG-meta buffer read path (agf/agi/agfl/bnobt/
	 * cntbt/inobt/finobt) compares a buffer's stamped b_mxfs_ag_gen to
	 * this; a lagging buffer is FUA-re-read so the allocator sees a peer's
	 * committed free-space btree (fixes AG free-space double-allocation
	 * under concurrent rename -> bmap/SB corruption).  Mirror of
	 * i_dlm_dir_gen / b_mxfs_dir_gen for directories.
	 */
	u64			pag_dlm_meta_gen;
	/*
	 * (design review design-consult redesign): monotonic counter bumped
	 * once per GENUINE fresh AG-DLM acquire from the cluster (the CAW-grant
	 * path where Invariant #1 already drained our prior tenure, so no
	 * this-node-ahead buffers survive).  A buffer whose b_tenure_id ==
	 * ag_dlm_tenure_id was read/modified during the CURRENT hold and is
	 * this-node-authoritative (we hold the AG EX => no peer can have
	 * advanced disk), so the read-time invalidation hook must NEVER discard
	 * it mid-tenure.  This is the reliable A-vs-B discriminator the
	 * b_mxfs_ag_gen / mxfs_buf_is_undestaged() LSN heuristics could not
	 * provide: a prev-epoch drained log-tail artifact carries an OLD tenure
	 * id (discard, cold-read peer's durable image), a current-tenure
	 * committed AGI unlinked-insert carries the CURRENT id (preserve).
	 * Reclaim of our own cached/release_pending EX does NOT bump it (same
	 * tenure — we never yielded the slot, our work must stay authoritative).
	 */
	u64			ag_dlm_tenure_id;
	/*
	 * (design review lineage-certificate design): true while
	 * this node holds an OPEN grant lineage for this AG — set at every
	 * genuine fresh CAW-grant acquire, cleared ONLY when a sanctioned
	 * release path yields the on-disk slot (bast_work_fn full drain,
	 * deferred release worker, force-release).  A fresh acquire that finds
	 * this still true means the previous grant lineage ended WITHOUT any
	 * release path running (slot evaporated / phantom loss) — the
	 * destructive acquire-side invalidation would then discard local
	 * CIL/AIL state whose release checkpoint never ran (P130-FALSE-FRESH,
	 * the silent bnobt lost-update prerequisite).
	 */
	bool			pag_dlm_lineage_open;
	/*
	 * last on-disk CAW slot generation observed
	 * for this AG at a fresh acquire.  The slot.generation is a SHARED
	 * cross-node ABA counter bumped on every acquire+release of this AG's
	 * lock by ANY node, so a change since we last looked reliably means a
	 * peer (or our own prior tenure) modified the AG.  When it changes we
	 * advance the (strictly monotonic) pag_dlm_meta_gen and reset the
	 * in-core PAG summary so the read-time invalidation cold-reads the
	 * peer's durable {AGF,AGFL,bnobt,cntbt,AGI,inobt} as a consistent set.
	 * Replaces the frozen local-only ++ scheme (/116 measured stuck
	 * at 1 -> all invalidation was dead code).
	 */
	u64			pag_dlm_disk_gen_seen;
	bool			pag_dlm_bast_pending;
	bool			pag_dlm_bast_scheduled;
	/*
	 * starvation forensics: when pag_dlm_bast_pending
	 * went 0->1 (jiffies) and how many cached fast-path re-adoptions
	 * happened while a peer was left waiting.  A 190s continuous AG-0 EX
	 * hold (P-LKTIMEOUT-HOLDER held_ms=189614) starved two peers' rm
	 * into defer_finish -110 shutdowns; these name whether the local
	 * node re-adopted past the pending BAST (ping-pong) or the work was
	 * lost/stuck.
	 */
	unsigned long		pag_dlm_bast_pending_since;
	u32			pag_dlm_readopt_n;
	/*
	 * (D-488 leg 7 part 1b, ruling): the rx strand
	 * detector found our own CAW holder bit on the platter with no
	 * in-core tenure.  This is NOT cached ownership and NOT write
	 * authority — the bast worker must first perform the verified
	 * READOPT mint (P294, fresh epoch through a real CAS) before any
	 * tenure or release can proceed.  Set/cleared under pag_dlm_lock;
	 * single-flight is guaranteed by pag_dlm_bast_scheduled, which is
	 * latched in the same critical section that sets this.
	 */
	bool			pag_dlm_readopt_pending;
	/*
	 * (design-consult ruling ccloop-c7ee71c6-sess391-GPT-ruling-ag-handoff-
	 * latch-closing-restartable; D-RSYNC-LAP-PACE-AG-SHARING-388): the
	 * handoff LATCH.  The AG BAST worker's release COMMIT (cached=false,
	 * demoting=true, epoch=0) used to be reachable only by the worker
	 * itself winning a race against local re-adopters at holders==0; at a
	 * 3 ms op cadence the worker lost that race ~2 M times per lap and a
	 * peer waited seconds.  Now the COMMIT is an atomic admission decision
	 * taken by whichever path observes holders==0 first once the
	 * prepass ran and the grace is spent: the last-holder unlock, a
	 * would-be re-adopter, or the worker.  pag_dlm_latched marks a COMMIT
	 * performed OUTSIDE the worker (the worker then skips straight to the
	 * post-COMMIT drains); pag_dlm_prepass_done marks that the worker has
	 * run its pre-COMMIT pass (publish unpublished inodes + bounded AIL
	 * push) for the current BAST generation — the latch is armed only
	 * after that, because the publish pass does data writeback that must
	 * acquire this very AG and would deadlock against a closed admission.
	 * Both cleared on every demote completion and at each new BAST
	 * generation.  pag_dlm_latch_ns stamps the COMMIT (either path) for
	 * the BAST->COMMIT / COMMIT->release latency accounting.
	 */
	bool			pag_dlm_latched;
	bool			pag_dlm_prepass_done;
	u64			pag_dlm_latch_ns;
	u64			pag_dlm_bast_rx_ns;	/* first rx of this generation */
	/*
	 * 0.22.2: BAST->COMMIT latency split for the handoff tail.
	 * work_enter_ns = first worker entry for this generation (rx->enter is
	 * workqueue/scheduling latency), armed_ns = prepass_done (enter->armed
	 * is the publish + bounded push), armed->COMMIT is the drain of admitted
	 * holders.  Zeroed at each new generation and at completion.
	 */
	u64			pag_dlm_work_enter_ns;
	u64			pag_dlm_armed_ns;
	u64			pag_dlm_queued_ns;	/* first worker queue after rx */
	int			pag_dlm_rx_holders;	/* holders at first rx */
	/*
	 * 0.23.0 (design-consult ruling ccloop-c7ee71c6-sess392-GPT-ruling-
	 * dialloc-try-reserve-candidate-rotation): dialloc candidate-rotation
	 * state.  pag_resv_cool = inode numbers whose DLM slot a peer held at a
	 * recent try-reserve (skipped without a probe until `until`); a bounded
	 * ring, search advice only — never correctness state.  pag_resv_cursor =
	 * the finobt record a budget-exhausted visit stopped at (NULLAGINO =
	 * none), so the next visit continues instead of re-probing the same
	 * first-free inode.  All under pag_resv_lock.
	 */
	spinlock_t		pag_resv_lock;
#define MXFS_RESV_COOL_N	32
	/*
	 * 0.75.121 (D-0946): `pubpend` separates WHY an entry is cooling.  A
	 * peer-held candidate is contention and belongs in the exhaustion
	 * verdict; a candidate cooling because THIS node still owes its home a
	 * write is not, and counting it as contention made the allocator declare
	 * a healthy AG spent and grow a fresh chunk (measured: 'P-DIALLOC-RESV-
	 * SWEPT agno=0 probes=0 contended=0 cool=56' -> RESV-GROW).  Fresh
	 * carves are not free: each is an opportunity for D-0948.
	 */
	struct {
		xfs_agino_t	agino;
		unsigned long	until;
		bool		pubpend;
	}			pag_resv_cool[MXFS_RESV_COOL_N];
	unsigned int		pag_resv_cool_next;
	xfs_agino_t		pag_resv_cursor;
	/*
	 * (D-0351 containment, design-consult ruling ccloop-c7ee71c6-sess430-
	 * GPT-ruling-d0351-dialloc-containment-two-phase): DISK-LIVE quarantine.
	 * aginos dialloc found FREE in the inobt but LIVE on the platter (a
	 * crossed FREE-PUBLISH invariant on some node).  Exact membership, no
	 * expiry, never evicted for the life of the mount; the allocator skips
	 * them and fails a create cleanly (-EUCLEAN, never a dirty cancel) when
	 * nothing else is left.  Separate from the timed pag_resv_cool ring,
	 * which is search advice only.  xarray: agino -> xa_mk_value(disk_gen).
	 */
	struct xarray		pag_disklive_q;
	unsigned int		pag_disklive_n;
	/*
	 * identity of the last holders 0->1 adopter.  When a
	 * peer's BAST finds the hold stuck (page_ms large, holders frozen>0),
	 * mxfs_dlm_ag_bast_notify dumps this task's stack (sched_show_task) —
	 * the holder of a 60s AG hold is often NOT in a DLM wait itself, so
	 * only its stack names the blocking edge.
	 */
	pid_t			pag_dlm_holder_pid;
	char			pag_dlm_holder_comm[16];
	/*
	 * (D-474 AIL-freeze anatomy): pag_dlm_lock hold forensics.
	 * P-AILMIN dumps showed the frozen AIL-min ILOCK owner blocked for
	 * >5 s in mutex_lock(&pag_dlm_lock) via mxfs_ag_dlm_trylock — a
	 * mutex documented as "never held across CAW".  Every lock/unlock
	 * site in xfs_mxfs_dlm.c goes through mxfs_pag_dlm_lock/_unlock,
	 * which stamp the lock site/owner/time here so P-AGMUTEX-HOLD can
	 * name the site pair that held it and P-AGMUTEX-WAIT the owner a
	 * long waiter found.
	 */
	u64			pag_dlm_lock_t0;
	int			pag_dlm_lock_site;
	pid_t			pag_dlm_lock_pid;
	char			pag_dlm_lock_comm[16];
	/*
	 * (D-474, convoy-aware noino fence): count of LOCAL tasks
	 * currently inside the BLOCKING per-AG CAW acquire for this AG
	 * (mxfs_v5_dlm_ag_lock in __mxfs_ag_dlm_lock), and the start time
	 * of the oldest such episode.  The no-inode release fence consults
	 * these when its AIL min freezes: a frozen EFI whose extents live
	 * in an AG a local task is waiting for is a bounded CONVOY (the
	 * EFD lands when that wait ends), not a wedge, and must not be
	 * charged against the 8-stall shutdown budget.  Measured at 25 AGs
	 * (7 node slots sharing home AGs): the peer held the shared AG 13 s;
	 * every fence on the node froze on one EFI and shut the node down.
	 */
	atomic_t		pag_mxfs_agwait_inflight;
	u64			pag_mxfs_agwait_since_ns;
	/*
	 * 0.89.9: the ALLOCATION-COVERAGE WITNESS (design-consult ruling
	 * docs/rulings/audit-gate-allocation-coverage-witness.md).  The cold
	 * structural audit's CLEAN is a release claim only when the preceding
	 * clustered workload demonstrably carved inode chunks in a shared AG
	 * on both nodes at overlapping times, reached another AG, released a
	 * chunk and moved the finobt on existing chunks; a final platter shows
	 * none of that (net not gross, inherited finobt occupancy, no node).
	 * These count SUCCESSFUL transitions on THIS node, per AG, read through
	 * /sys/kernel/debug/mxfs/<dev>/alloc_witness and cleared by a write to
	 * it; a snapshot before and after a phase is the phase's record.
	 *   carves     xfs_ialloc_ag_alloc published a new chunk's inobt and
	 *              finobt records and the AGI counts into its transaction
	 *              (an abort after that point shuts the filesystem down,
	 *              which fails the lap on its own; nothing here undoes it)
	 *   releases   xfs_difree_inode_chunk handed a chunk's blocks to the
	 *              deferred free-extent operation
	 *   fino_ins   xfs_difree_finobt inserted the record of an EXISTING
	 *              full chunk that just gained a free inode (full→partial)
	 *   fino_del   xfs_dialloc_ag deleted the record of an EXISTING
	 *              partial chunk that just became full (partial→full)
	 *   carve_first/last_ns  ktime_get_real_ns at the first and last carve
	 *              since the last clear — the overlap witness, paired with
	 *              the clock-offset bound the harness measures per node
	 * A newly carved chunk's own finobt insert and a released chunk's own
	 * finobt delete are NOT counted as finobt transitions: the ruling's
	 * lifecycle floor is about existing chunks.
	 */
	atomic64_t		pag_mxfs_wit_carves;
	atomic64_t		pag_mxfs_wit_releases;
	atomic64_t		pag_mxfs_wit_fino_ins;
	atomic64_t		pag_mxfs_wit_fino_del;
	atomic64_t		pag_mxfs_wit_carve_first_ns;
	atomic64_t		pag_mxfs_wit_carve_last_ns;
	struct work_struct	pag_dlm_bast_work;
	/*
	 * pag_dlm_demoting: set by mxfs_dlm_ag_bast_work_fn during the brief
	 * window between deciding to release the cached AG grant and the
	 * actual on-disk release completing.  Local acquires (fast or slow
	 * path) that find demoting=true block on pag_dlm_demote_wq instead
	 * of squeezing AG modifications in between bast's drain and unlock.
	 * Cleared (and the wq woken) once mxfs_v5_dlm_ag_unlock returns,
	 * either inline in bast_work_fn or in mxfs_dlm_ag_meta_iodone for
	 * the deferred-release path.  Replaces the v0.3.7 mutex approach
	 * which serialized the entire drain and starved peers' CAW retries.
	 */
	bool			pag_dlm_demoting;
	/*
	 * (D-0351): PUBLICATION-WRITE GATE.  Count of xfs_iflush
	 * copy-ins in flight that were sanctioned by the FREE obligation
	 * predicate (P55C) against pag_mxfs_grant_epoch.  The release COMMIT
	 * zeroes the epoch and then WAITS for this to drain before its
	 * buffer drain runs, so a copy-in that validated against the old
	 * epoch is always drain-visible (the bare epoch read had a TOCTOU —
	 * Design-consult ruling ccloop-c7ee71c6-sess427-GPT-ruling-free-publish-
	 * invariant-d0351).  begin: inc, smp_mb, re-check epoch (dec on
	 * mismatch); end: dec after the copy-in has attached the item to the
	 * locked buffer.
	 */
	atomic_t		pag_mxfs_pubwrite;
	/* (D-0351): FREE obligations the last release audit could not
	 * publish (pending frees + unrepaired) — the release worker defers
	 * the on-disk unlock while this is non-zero (bounded). */
	int			pag_mxfs_freeob_split;
	/* (D-0524): FREE_PENDING entries at the release gate that are
	 * orphans or cross-tenure — refuse the release without deferral. */
	int			pag_mxfs_freeob_fatal;
	wait_queue_head_t	pag_dlm_demote_wq;
	/*
	 * deferred-release flush worker.  mxfs_dlm_ag_meta_iodone runs
	 * in xfs-buf workqueue context where blkdev_issue_flush deadlocks, but
	 * the deferred on-disk AG unlock MUST be preceded by a cache flush so a
	 * peer's FUA read of the AG btrees sees our just-written free-space
	 * (else: stale bnobt -> double allocation -> EFSBADCRC shutdown).  So
	 * the iodone hands the flush+unlock off to this worker on system_wq.
	 */
	struct work_struct	pag_dlm_release_work;
#endif /* __KERNEL__ */
};

static inline struct xfs_perag *to_perag(struct xfs_group *xg)
{
	return container_of(xg, struct xfs_perag, pag_group);
}

static inline struct xfs_group *pag_group(struct xfs_perag *pag)
{
	return &pag->pag_group;
}

static inline struct xfs_mount *pag_mount(const struct xfs_perag *pag)
{
	return pag->pag_group.xg_mount;
}

static inline xfs_agnumber_t pag_agno(const struct xfs_perag *pag)
{
	return pag->pag_group.xg_gno;
}

/*
 * Per-AG operational state. These are atomic flag bits.
 */
#define XFS_AGSTATE_AGF_INIT		0
#define XFS_AGSTATE_AGI_INIT		1
#define XFS_AGSTATE_PREFERS_METADATA	2
#define XFS_AGSTATE_ALLOWS_INODES	3
#define XFS_AGSTATE_AGFL_NEEDS_RESET	4

#define __XFS_AG_OPSTATE(name, NAME) \
static inline bool xfs_perag_ ## name (struct xfs_perag *pag) \
{ \
	return test_bit(XFS_AGSTATE_ ## NAME, &pag->pag_opstate); \
}

__XFS_AG_OPSTATE(initialised_agf, AGF_INIT)
__XFS_AG_OPSTATE(initialised_agi, AGI_INIT)
__XFS_AG_OPSTATE(prefers_metadata, PREFERS_METADATA)
__XFS_AG_OPSTATE(allows_inodes, ALLOWS_INODES)
__XFS_AG_OPSTATE(agfl_needs_reset, AGFL_NEEDS_RESET)

int xfs_initialize_perag(struct xfs_mount *mp, xfs_agnumber_t orig_agcount,
		xfs_agnumber_t new_agcount, xfs_rfsblock_t dcount,
		xfs_agnumber_t *maxagi);
void xfs_free_perag_range(struct xfs_mount *mp, xfs_agnumber_t first_agno,
		xfs_agnumber_t end_agno);
int xfs_initialize_perag_data(struct xfs_mount *mp, xfs_agnumber_t agno);
int xfs_update_last_ag_size(struct xfs_mount *mp, xfs_agnumber_t prev_agcount);

/* Passive AG references */
static inline struct xfs_perag *
xfs_perag_get(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	return to_perag(xfs_group_get(mp, agno, XG_TYPE_AG));
}

static inline struct xfs_perag *
xfs_perag_hold(
	struct xfs_perag	*pag)
{
	return to_perag(xfs_group_hold(pag_group(pag)));
}

static inline void
xfs_perag_put(
	struct xfs_perag	*pag)
{
	xfs_group_put(pag_group(pag));
}

/* Active AG references */
static inline struct xfs_perag *
xfs_perag_grab(
	struct xfs_mount	*mp,
	xfs_agnumber_t		agno)
{
	return to_perag(xfs_group_grab(mp, agno, XG_TYPE_AG));
}

static inline void
xfs_perag_rele(
	struct xfs_perag	*pag)
{
	xfs_group_rele(pag_group(pag));
}

static inline struct xfs_perag *
xfs_perag_next_range(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	xfs_agnumber_t		start_agno,
	xfs_agnumber_t		end_agno)
{
	return to_perag(xfs_group_next_range(mp, pag ? pag_group(pag) : NULL,
			start_agno, end_agno, XG_TYPE_AG));
}

static inline struct xfs_perag *
xfs_perag_next_from(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag,
	xfs_agnumber_t		start_agno)
{
	return xfs_perag_next_range(mp, pag, start_agno, mp->m_sb.sb_agcount - 1);
}

static inline struct xfs_perag *
xfs_perag_next(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	return xfs_perag_next_from(mp, pag, 0);
}

/*
 * Per-ag geometry infomation and validation
 */
xfs_agblock_t xfs_ag_block_count(struct xfs_mount *mp, xfs_agnumber_t agno);
void xfs_agino_range(struct xfs_mount *mp, xfs_agnumber_t agno,
		xfs_agino_t *first, xfs_agino_t *last);

static inline bool
xfs_verify_agbno(struct xfs_perag *pag, xfs_agblock_t agbno)
{
	return xfs_verify_gbno(pag_group(pag), agbno);
}

static inline bool
xfs_verify_agbext(
	struct xfs_perag	*pag,
	xfs_agblock_t		agbno,
	xfs_agblock_t		len)
{
	return xfs_verify_gbext(pag_group(pag), agbno, len);
}

/*
 * Verify that an AG inode number pointer neither points outside the AG
 * nor points at static metadata.
 */
static inline bool
xfs_verify_agino(struct xfs_perag *pag, xfs_agino_t agino)
{
	if (agino < pag->agino_min)
		return false;
	if (agino > pag->agino_max)
		return false;
	return true;
}

/*
 * Verify that an AG inode number pointer neither points outside the AG
 * nor points at static metadata, or is NULLAGINO.
 */
static inline bool
xfs_verify_agino_or_null(struct xfs_perag *pag, xfs_agino_t agino)
{
	if (agino == NULLAGINO)
		return true;
	return xfs_verify_agino(pag, agino);
}

static inline bool
xfs_ag_contains_log(struct xfs_mount *mp, xfs_agnumber_t agno)
{
	return mp->m_sb.sb_logstart > 0 &&
	       agno == XFS_FSB_TO_AGNO(mp, mp->m_sb.sb_logstart);
}

static inline struct xfs_perag *
xfs_perag_next_wrap(
	struct xfs_perag	*pag,
	xfs_agnumber_t		*agno,
	xfs_agnumber_t		stop_agno,
	xfs_agnumber_t		restart_agno,
	xfs_agnumber_t		wrap_agno)
{
	struct xfs_mount	*mp = pag_mount(pag);

	*agno = pag_agno(pag) + 1;
	xfs_perag_rele(pag);
	while (*agno != stop_agno) {
		if (*agno >= wrap_agno) {
			if (restart_agno >= stop_agno)
				break;
			*agno = restart_agno;
		}

		pag = xfs_perag_grab(mp, *agno);
		if (pag)
			return pag;
		(*agno)++;
	}
	return NULL;
}

/*
 * Iterate all AGs from start_agno through wrap_agno, then restart_agno through
 * (start_agno - 1).
 */
#define for_each_perag_wrap_range(mp, start_agno, restart_agno, wrap_agno, agno, pag) \
	for ((agno) = (start_agno), (pag) = xfs_perag_grab((mp), (agno)); \
		(pag) != NULL; \
		(pag) = xfs_perag_next_wrap((pag), &(agno), (start_agno), \
				(restart_agno), (wrap_agno)))
/*
 * Iterate all AGs from start_agno through wrap_agno, then 0 through
 * (start_agno - 1).
 */
#define for_each_perag_wrap_at(mp, start_agno, wrap_agno, agno, pag) \
	for_each_perag_wrap_range((mp), (start_agno), 0, (wrap_agno), (agno), (pag))

/*
 * Iterate all AGs from start_agno through to the end of the filesystem, then 0
 * through (start_agno - 1).
 */
#define for_each_perag_wrap(mp, start_agno, agno, pag) \
	for_each_perag_wrap_at((mp), (start_agno), (mp)->m_sb.sb_agcount, \
				(agno), (pag))


struct aghdr_init_data {
	/* per ag data */
	xfs_agblock_t		agno;		/* ag to init */
	xfs_extlen_t		agsize;		/* new AG size */
	struct list_head	buffer_list;	/* buffer writeback list */
	xfs_rfsblock_t		nfree;		/* cumulative new free space */

	/* per header data */
	xfs_daddr_t		daddr;		/* header location */
	size_t			numblks;	/* size of header */
	const struct xfs_btree_ops *bc_ops;	/* btree ops */
};

int xfs_ag_init_headers(struct xfs_mount *mp, struct aghdr_init_data *id);
int xfs_ag_shrink_space(struct xfs_perag *pag, struct xfs_trans **tpp,
			xfs_extlen_t delta);
int xfs_ag_extend_space(struct xfs_perag *pag, struct xfs_trans *tp,
			xfs_extlen_t len);
int xfs_ag_get_geometry(struct xfs_perag *pag, struct xfs_ag_geometry *ageo);

static inline xfs_fsblock_t
xfs_agbno_to_fsb(
	struct xfs_perag	*pag,
	xfs_agblock_t		agbno)
{
	return XFS_AGB_TO_FSB(pag_mount(pag), pag_agno(pag), agbno);
}

static inline xfs_daddr_t
xfs_agbno_to_daddr(
	struct xfs_perag	*pag,
	xfs_agblock_t		agbno)
{
	return XFS_AGB_TO_DADDR(pag_mount(pag), pag_agno(pag), agbno);
}

static inline xfs_ino_t
xfs_agino_to_ino(
	struct xfs_perag	*pag,
	xfs_agino_t		agino)
{
	return XFS_AGINO_TO_INO(pag_mount(pag), pag_agno(pag), agino);
}

#endif /* __LIBXFS_AG_H */
