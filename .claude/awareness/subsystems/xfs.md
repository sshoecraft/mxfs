# xfs (XFS-6.19 fork + MXFS overlay)

<!-- sess415 (0.28.4): xfs_mxfs_dlm.c gained the D-512 T2/T6 drain
     pausepoints — dbg_rel_pause_{ino,stage,ms} params + static helper
     mxfs_dbg_rel_pause() defined just above mxfs_dlm_bast_process, with 5
     call sites: (1) pre-site-1-flush, (2) between flush and invalidate,
     (3) post-invalidate, (4) pre-site-2 post-NL data flush, (5)
     immediately before BOTH unlock_open CAS arms.  Debug no-ops unarmed;
     P-D512-RELPAUSE/-END markers; harness tests/d512_t2_pause.sh.
     Also 0.28.2 in this session: P-D512-* containment arms (drain-error
     fail-stop via mxfs_inode_wedge, dirty-mismatch fail-stop) — see the
     sess415 section at the end of this file and docs/reuse-barrier.md.
     sess416 (0.28.5): T8 synthetic injectors dbg_rel_fail_{ino,kind}
     (one-shot, self-clearing; helper mxfs_dbg_rel_fail() next to the
     pause helper): kind 1 = site-1 writeback rc:=-EIO (drain_hard wedge),
     2 = site-1 invalidate rc:=-EBUSY (refuse-unlock retry), 3 = site-2
     post-NL flush rc:=-EIO (DRAIN2 wedge), 4 = OR'd into the protective-
     reload dirty-mismatch predicate (poison + shutdown).  Marker
     P-D512-INJECT.  Harness tests/d512_t8_inject.sh (wedges 3 holder
     nodes by design — prep_cluster after). -->

**Owner files**: `xfs/` (331 files), `mxfs_clayer/` (4 files), top-level `mxfs.c`

> **0.89.89: `xfs/xfs_mxfs_dlm.c` is 32 files.** The XFS-side DLM layer is
> `xfs/xfs_mxfs_*.c` sharing `xfs/xfs_mxfs_dlm_priv.h`; which file holds what,
> and the rules for adding code, are in `docs/xfs-dlm-layout.md`. Every
> `xfs_mxfs_dlm.c:NNNN` reference below predates the split and names a line of
> the old single file; find the function by name. Recorded sites
> (`i_dlm_demoter_line`, `i_mxfs_auth_line`, `i_dlm_epoch_src`,
> `b_mxfs_done_site`, the DLMTR/DEMEV rings, AG mutex sites) are now
> `file-id:line` (`MXFS_SITE`); the ids are in that document.
**Last updated**: 2026-07-30 (ccloop c7ee71c6 sess28, 0.11.239-245 — **THE DIR EPOCH IS A PROPERTY OF THE INODE NUMBER, NOT OF AN INCARNATION**: `caw_tombstone_slot`/`caw_claim_inherit_epoch` deliberately carry a slot's `dir_epoch` across an idle gap and `grant_meta` outlives the inode, so every `master_epoch > i_dlm_dir_valid_epoch` compare was cross-incarnation — permanently true for a dir created on a recycled inode number, and `P32E-DIREPOCH-FENCE` (ships 1) then skipped every flush of it. NEW FIELD `i_dlm_dir_valid_incarn` (stamped at all 11 baseline assignment sites) + NEW PREDICATE `mxfs_dir_epoch_superseded()` used by BOTH consumers. NEW MODULE PARAMS: `mxfs.dir_epoch_incarn_gate` (default 1, the fix), `mxfs.creator_baseline_stamp` (default 0, MEASURED NO-OP — the epoch is 0 at every publish site). REMOVED: `mxfs.create_baseline_trackers` (dead code + latent sleep-in-atomic). NEW PROBES: P210-CREATOR-BASELINE (unconditional exposure counter), P211-EPOCH-{REBASE,NOGRANT,FOREIGN}; `base_state=` added to P195. NOTE THE SHIPPED ASYMMETRY: the fence consumer ships enabled while its maintainer `mxfs.dir_epoch_adopt` ships disabled (sess49 AG double-free) — a fence with no maintainer eventually refuses everything. See the dated section at the end.); 2026-09-08 (sess559: untrusted-iget AG bracket bounded, never `-EAGAIN` to `xfs_iget` — D-0930, final section)

> **sess58 (2/tcp criterion MET, build 60EFBE5E)** — two lock-coordination roots fixed in `xfs_inode.c`:
> 1. **AG↔dir lock order must be consistent (AG→dir).** create (dialloc-first) and rename (`mxfs_trans_preacquire_inode_ags`) acquire AG before dir; `xfs_remove` was dir→AG and ABBA-deadlocked a peer create. FIX: `xfs_remove` pre-acquires the child's AG (standalone `mxfs_ag_dlm_lock`) before `xfs_trans_alloc_dir`.
> 2. **`xfs_ilock_nowait` does NOT acquire the DLM grant for ILOCK** (only IOLOCK — atomic xfsaild/reclaim carve-out). So a DIR locked via the AIL-nowait branch of `xfs_lock_two_inodes` (remove/link) or `xfs_lock_inodes` (rename) was modified without EX authority → durable dirent resurrection. FIX: acquire the dir's DLM grant (`mxfs_dlm_ilock_begin`, DIR-only) in both nowait paths. Detector: `P58-DIRPIN-NONEX` (xfs_inode_item.c) fires if a dir pins at non-EX.

## Purpose

The on-disk filesystem code. Originally copied from `~/src/linux/fs/xfs/` at 6.19-rc0 and now project source — these files are MXFS code, modified in place as needed (sess33 alone touched `xfs_inode.c`, `xfs_trans_ail.c`, `libxfs/xfs_ialloc.c`, `libxfs/xfs_ag.{c,h}`, `xfs_mount.h`, `xfs_buf.h`, plus extensive work in `xfs_mxfs_dlm.{c,h}`). The MXFS coordination surface (per-AG DLM acquire/release on alloc paths, per-inode DLM acquire/release, the bast_work_fn drain pipeline) is layered on top of and into the XFS-derived code.

## Public API (mxfs-specific surface; XFS upstream not listed)

```
mxfs_ag_dlm_lock(mp, pag) -> int             — fast-path/CAW acquire AG-DLM
mxfs_ag_dlm_unlock(mp, pag) -> void           — fast-path release with optional lazy drain
mxfs_dlm_ag_bast_notify(mp_void, agno, mode)  — peer signals BAST for AG
mxfs_dlm_ag_bast_work_fn(work)                — workqueue body: drain + on-disk release
mxfs_inode_dlm_lock(ip, mode) -> int          — per-inode DLM acquire (PR/EX)
mxfs_inode_dlm_unlock(ip, mode)               — per-inode DLM release
mxfs_dlm_bast_process(ip)                     — per-inode BAST drain (called from work fn)
mxfs_dlm_invalidate_ag_meta(pag)              — drop cached AGF/AGI/btree bufs on fresh acquire
mxfs_dlm_grant_local_new(ip, mode)            — sess44 deferred-publish: brand-new inode gets LOCAL EX, no CAW slot
mxfs_dlm_publish_inode(ip)                    — promote ONE unpublished inode to a real EX slot; v0.5.6 sess29(run14d): also called synchronously from xfs_link + cross-dir xfs_rename of a still-unpublished inode (single i_mxfs_unpub_parent can't represent a second parent)
mxfs_dlm_rearm_unpublished(ip)                — sess128: re-arm deferred-publish on cache-hit IGET_CREATE (reused inode kept phantom EX after xfs_inactive released its slot; without this, peers acquire the reused number clean and read the not-yet-durable size=0 dinode)
mxfs_dlm_publish_unpublished(mp, parent_ino, agno) — v0.5.6 sess29(run14d): SCOPED drain of the unpub list on peer BAST.  Scope = entries whose i_mxfs_unpub_parent == parent_ino (released dir's children), OR living in agno (AG bast), OR parent==0 (unknown — every drain).  Set in xfs_create/xfs_symlink after xfs_dir_create_child.  Whole-list drain at 16 nodes claimed ~96k slots vs the 65536 table → minutes-long releases, EX-waiter 120s timeouts + shutdown (sess28 publish bomb).  Sibling: mxfs_dlm_publish_dirs_work now pre-claims REUSED-incarnation dirs only (i_mxfs_reused_create) — fresh dirs are covered by the scoped BAST drain and pre-claiming ~700/node was the 16n LUN-queue inflater
xfs_ail_push_ag_sync(ailp, agno)              — wait for AIL items in AG to drain
xfs_ail_push_ag_sync_bounded(ailp, agno,
                             stall_iters, min_iters) -> int
                                              — bounded variant; returns -EAGAIN on stall
```

## Key Data Structures

```c
struct xfs_perag {
    /* upstream fields ... */
    bool                pag_dlm_cached;        // grant kept on-disk after holders==0
    bool                pag_dlm_bast_pending;  // peer asked
    bool                pag_dlm_bast_scheduled;
    bool                pag_dlm_demoting;
    int                 pag_dlm_holders;
    int                 pag_dlm_yield_remaining;       // v6a phase 2 D10
    int                 pag_dlm_yield_quantum_eff;     // v0.3.147 adaptive eff
    int                 pag_dlm_skips_no_bast;         // adaptive doubling counter
    struct mutex        pag_dlm_lock;
    struct mutex        pag_dlm_acquire_lock;          // serializes CAW grant attempts
    struct list_head    pag_mxfs_alloc_buflist;        // mxfs's own delwri queue
    struct mutex        pag_mxfs_alloc_buflist_lock;
    bool                pag_mxfs_alloc_dirty;
    atomic_t            pag_dlm_meta_pending;          // inflight AG-meta writebacks
    bool                pag_dlm_release_pending;
    unsigned long       pag_dlm_fua_window_until;      // FUA-read window
    struct work_struct  pag_dlm_bast_work;
    wait_queue_head_t   pag_dlm_demote_wq;
};
```

## Internal Architecture

**Cached AG model.** `mxfs_ag_dlm_unlock` keeps the on-disk DLM grant after holders==0 (`pag_dlm_cached=true`). Subsequent acquires fast-path (no CAW). When peer wants the AG, peer's BAST sets `pag_dlm_bast_pending=true` and queues `pag_dlm_bast_work` on the per-mount ordered workqueue (`m_mxfs_ag_bast_wq`, v0.3.147).

**bast_work_fn pipeline (Phase 1 → 2):**
- Phase 1: `xfs_log_force(SYNC)` → `xfs_ail_push_ag_sync_bounded` → `blkdev_issue_flush`.
- Phase 2: claim demote slot (set `demoting=true`), `xfs_log_force(SYNC)` again, `mxfs_dlm_ag_drain_meta_buffers`, `mxfs_dlm_ag_drain_alloc_buflist`, `mxfs_dlm_ag_drain_inode_buffers`, `blkdev_issue_flush`, on-disk DLM unlock.

**Per-inode DLM** (`mxfs_inode_dlm_*`): mode PR/EX, BAST handler `mxfs_dlm_bast_process` does per-inode drain (per-AG ail_push for the inode's AG) + iflush + release.

**Adaptive yield quantum (v0.3.147 prescription E):** `pag_dlm_yield_quantum_eff` starts at 1 (when adaptive=1) and grows via doubling after `MXFS_AG_YIELD_DOUBLE_THRESH=4` consecutive non-contended eager drains, halves on every peer BAST. Bounded [1, `mxfs_ag_yield_quantum`].

## Cross-Subsystem Dependencies

| Depends On | How | Notes |
|---|---|---|
| dlm | `mxfs_v5_dlm` opaque ctx in `mp->m_mxfs_dlm`; calls `mxfs_v5_dlm_ag_lock`, `mxfs_v5_dlm_inode_unlock`, etc. | All cluster I/O goes through dlm |
| pal | `mxfs_pal_*` for I/O, sleep, threads, mutex creation | Standard PAL surface |
| mxfs_clayer | `MXFS_BAST_YIELD_QUANTUM` macro from `yield_quantum.h` | One-line dep |

| Depended On By | How |
|---|---|
| pal/linux/xfs_super.c | Calls `xfs_init_mount_workqueues` (now allocates `m_mxfs_ag_bast_wq`); calls `mxfs_v5_dlm_init` at fill_super |

## Invariants

1. **No on-disk DLM unlock without a successful drain pipeline.** Phase 2 must complete `drain_meta_buffers` + `drain_alloc_buflist` + `drain_inode_buffers` + `blkdev_flush` BEFORE `mxfs_v5_dlm_ag_unlock`. Skipping any step lets peer read stale (Mode A regression family). Sess32 v0.3.141-142 violated this with bounded ail_push that proceeded to release on timeout — reverted.
   **The unmount path honours this since 0.69.3 (sess485, `D-UNMOUNT-AG-GRANTS-PUBLISHED-BEFORE-METADATA-QUIESCE-0483`, verification pending in chain 133).** Up to 0.69.2 `mxfs_dlm_ag_force_release_all` ran ONE of the nine steps (`drain_alloc_buflist`) and was called from `xfs_fs_put_super` a hundred lines *before* `xfs_unmountfs`, whose inactivation flush, inode flush and whole-log AIL push then wrote AGI/inobt/finobt and inode clusters for AGs already published — with a DLM that re-acquired grants nobody drained again, then with `m_mxfs_dlm == NULL`, where `__mxfs_ag_dlm_lock` answers `if (!dlm) return 0`. **Now:** (1) `xfs_unmountfs` is split (`xfs/xfs_mount.c`) into `xfs_unmountfs_prepare` — inodegc flush, blockgc/zone stop, AG unreserve, quota unmount, rt inodes, root+metadir irele (pointers NULLed), then `xfs_inodegc_stop` as the no-more-inactivation gate — and `xfs_unmountfs_finish` (inode reclaim, quota teardown, reserve return, log cover + unmount record); `xfs_unmountfs` = both, still used by the non-clustered path and the failed-mount unwind. (2) put_super's DLM block runs producers-stop → `xfs_unmountfs_prepare` → `mxfs_sb_summary_final_sync` (seal) → explicit `xfs_log_force` + `xfs_ail_push_all_sync` + `xfs_buftarg_wait` → `mxfs_iclus_purge_all` → `mxfs_dlm_ag_force_release_all` → `m_mxfs_dlm = NULL` → heartbeat join → `xfs_unmountfs_finish`. Inode reclaim stays after the DLM NULL on purpose (`xfs_reclaim_inode` calls `mxfs_dlm_evict` per inode; after the quiesce it frees clean inodes only). (3) `mxfs_dlm_ag_force_release_all` is two-phase: drain every AG (alloc buflist, inode clusters, AG meta) under held grants, one log force, the sess43 second meta pass, ONE `mxfs_blkdev_flush_epoch`, then flip+unlock per AG; `P482-UMOUNT-AGREL` gains `ags_drained` (expected 0) and `P485-UMOUNT-DRAIN` names any AG the drains still wrote. **Never move the release below `xfs_unmountfs_finish`**: the heartbeat is joined before it, so a grant held there is held by a node no longer proving liveness. Instrument: `P483-AGFREE-WINDOW` now carries `pre_wr=`/`pre_iclus_wr=` (writes between put_super entry and publication — the positive control), `aglock_after=` (`P485-AGLOCK-AFTER-AGFREE`) and `inodegc_after_stop=` (`P485-INODEGC-AFTER-STOP`); every after-publication field must read zero.
2. **bast_work_fn for an AG runs at most one at a time.** Routed through `m_mxfs_ag_bast_wq` ordered queue. Multiple parallel invocations starve xfsaild and saturate event-pool. v0.3.147.
3. **`pag_dlm_acquire_lock` MUST NOT be held across `mxfs_v5_dlm_ag_lock` CAW poll.** The CAW poll sleeps up to 120s; `mxfs_dlm_ag_meta_iodone` needs `pag_dlm_lock` to fire deferred releases the CAW grant may be waiting on. Holding deadlocks.
4. **AG-DLM grant validity = on-disk slot state.** `pag_dlm_cached=true` is a hint for fast-path acquire; the authoritative grant is the disk slot, not the in-memory flag.
5. **The AG-meta track hold is a ONE-SHOT token — released by writeback OR abort, never leaked (2026-07-21 fix).** Every logged AG-meta buffer gets an extra `xfs_buf_hold` + `pag_dlm_meta_pending++` from `mxfs_ag_meta_track` (idempotent per dirty epoch via `XFS_BLI_MXFS_AGMETA_TRACKED`). That hold's ONLY writeback releaser is `mxfs_dlm_ag_meta_iodone` (installed as `b_iodone`, which fires only in `__xfs_buf_ioend`). On a forced shutdown the dirty AG-meta buffers are aborted WITHOUT writeback (`xfs_buf_item_release` abort branch → `xfs_buf_item_done`, no ioend), so iodone never fires — the OLD code leaked the hold and wedged `xfs_buftarg_drain` at umount (agi/inobt/finobt stuck `b_hold=2`, PROVEN via the new P-HOLDRING dump). FIX: a one-shot `atomic_t bp->b_mxfs_agmeta_hold` armed by track, consumed (`cmpxchg 1→0`) by EXACTLY ONE of iodone (writeback) or **`mxfs_ag_meta_reclaim(bp, why)`** — called from `pal/linux/xfs_buf_item.c`'s abort branch (`why="shutdown/abort"`) AND, since 0.75.62, from `xfs_buf_item_finish_stale` (`why="stale"`): a btree block freed after being logged (`xfs_trans_binval` on a leaf merge / root collapse) completes through the stale path with NO ioend, and before 0.75.62 that leaked the hold + pending for the mount's life, so every later release of that AG spun to the Phase-3 2 s bound (P55-STUCKMETA `write_inflight=0 dirty=0 inAIL=0`) while the peer's 1 s request deadline expired (D-0923, reproducer `tests/agmeta_stale_leak_2node.sh`). Logs P-AGMETA-RECLAIM with `why=`. NEVER re-key AG-meta cleanup on `b_iodone` alone — abort AND stale paths don't run ioend. See `docs/history/pve-agi-wedge-root-agmeta-track-hold-leak-fix-and-pve1-hung.md`. **0.87.14 (D-0924) — the token is returned at the two choke points every tracked log item's life passes through, whatever route led there:** `xfs_buf_item_free` has one caller, `xfs_buf_item_relse(bip, why, ctx)`, which reclaims on every `XFS_BLI_NO_IODONE` retirement (put, stale, release-clean, shutdown/abort, the overlay's no-I/O retire arms, retire-no-bli); the only `XFS_BLI_IODONE_FOLLOWS` caller is `__xfs_buf_ioend`, whose epilogue after `bp->b_iodone(bp)` now reclaims (`why=ioend-unconsumed`, P-AGMETA-IODONE-MISSED names the callback that ran) if the callback left the token armed. No token ABA across that epilogue: the write holds the buffer lock until `xfs_buf_ioend`'s relse and a new epoch arms only from `xfs_trans_log_buf` under the transaction's buffer lock. `dbg_agmeta_iodone_skip=N` (test only) makes the callback leave the next N tokens armed so the epilogue is exercised. `mxfs_dlm_ag_force_release_all` prints `P-AGMETA-UNMOUNT-CENSUS ags= nonzero_ags= pending_total=` (and a `P-AGMETA-PENDING-AT-UNMOUNT ag=` line per non-zero AG) after the drains and flush — the per-AG quiescent conservation check; the module-wide identity `agmeta_acquires == agmeta_returns_iodone + agmeta_returns_reclaim` can balance while one AG is over and another under.
6. **A cached extent-tree (bmbt) image is valid only inside the tenure that read it, and the tenure that grows a tree lands it before it lets go.** Three mechanisms, all owner-keyed (a bmbt block's `bb_owner` is the inode, for the data and the attr fork alike), all in `xfs/xfs_mxfs_dlm.c`:
   - *Acquire:* `mxfs_dlm_reload_inode` re-reads the dinode (the tree's root) and runs `mxfs_dir_evict_bmbt_blocks` + `mxfs_dir_evict_bmbt_by_root` for every btree-format fork, file or directory (`reload_evict_file_bmbt`), so the lazy extent load cold-reads the peer's blocks. The walk's hold array is a batch, never a limit.
   - *Flush:* `mxfs_iflush_force_bmbt_durable` never destages a clean cached block while the fork's extents are unread — an unread fork was adopted from disk, so a clean block is at best what disk holds and at worst a pre-reload image (`iflush_unread_clean_skip`; `bmbt_write_unread` at the write chokepoint must stay 0).
   - *Release:* the EX release runs `mxfs_dir_bmbt_scan`'s check-and-flush loop (directories since sess133, regular files since 0.87.5, either fork since 0.87.6) until no owned block carries local work, and wedges rather than unlock after 30 s. Then, for every release (EX or PR) and for a grant leaving through reclaim, `mxfs_bmbt_tenure_end_evict` drops every clean cached bmbt image the inode owns before the wire unlock (`bmbt_rel_evicted`); a block it cannot lock in 30 s or that still carries local work wedges the release (`bmbt_rel_busy`, `bmbt_rel_localwork`). Why at release and not only at reload: a block freed by a peer and reused in another inode's tree keeps the old owner in this node's cache, so the acquire-side owner walk for the new inode cannot see it — measured as D-0975, a cache hit served for the new tree with no read, caught only by the btree owner check.
   - *Detector, not mechanism:* `xfs_btree_lookup_get_block`'s refusal path calls `mxfs_bmbt_lookup_bad_probe`, which prints the refused image's owner and level against the same address read at the coherence point (`P975-BMBT-LOOKUP-BAD`, counter `bmbt_lookup_bad`). A refusal on a clustered mount is a coherency defect, never a bad block, until the disk fields say otherwise.
   - *Not covered here:* buffers that recovery of a dead peer's journal slice leaves in the cache were read under no tenure; invariant 8 retires those (0.87.9).
7. **An inode grant is not released while this node's direct I/O on the inode is in flight.** An asynchronous direct read or write drops its IOLOCK ride, and with it the DLM holder count, when submission returns `-EIOCBQUEUED` with the bios still outstanding (`i_dio_count > 0`), so the holders gate alone cannot see it (D-0971, 0.87.7). The release pipeline (`mxfs_dlm_bast_process`, `xfs/xfs_mxfs_dlm.c`) therefore orders: close admission (BAST state parks new rides) → no ordinary holder at entry → `inode_dio_wait` → drain → terminal check → NL store.
   - *Wait only from a quiescent entry:* the pre-drain `inode_dio_wait` runs only when no holder was present at entry. A holder still admitted may be mid-submission and about to park on its own nested ILOCK, so waiting on it deadlocks; the holders gate aborts and re-arms instead, and the next pass enters with none. The wait precedes the log force so a completion's commits, which may still be in the CIL when the wait returns, are covered by the drain that follows (`rel_dio_waited`, `rel_dio_wait_max_us`, `P971-REL-DIO-WAIT`).
   - *Terminal guard, fail-closed:* under `i_dlm_lock` and before the NL store, a non-zero count keeps the grant and the BAST state and re-fires the pipeline at once (`rel_dio_defer`, `P971-REL-DIO-DEFER`). The post-store detector `rel_dio_inflight` (`P-REL-DIO-INFLIGHT`) is telemetry that must read zero; a release must never store NL first and defer after.
   - *Completion admission:* a direct write's completion (`xfs_dio_write_end_io`, `pal/linux/xfs_file.c`) takes ILOCK_EXCL for its unwritten conversion and size update after its ride is gone, while the pipeline is waiting for exactly that completion. iomap runs a completion that needs filesystem work on the direct-I/O completion workqueue, a kernel thread, and the cached-grant fast path in `mxfs_dlm_ilock_begin` admits a kernel thread under the still-EX mode as a counted holder (the v0.3.5 exemption the file yield gate keeps); the holders gate before the NL store then aborts and re-arms if it still holds (P15-REL-ABORT). Measured: every such completion ran on a kernel thread (`dioend_kthread`), and the ones that began during a release (`dioend_in_drain`) returned; `dioend_task` counts only the size-zero error completion iomap runs synchronously for a refused nowait first attempt, under the submitter's still-held ride. The backstop for a task-context completion, which iomap does not produce today, is the per-task registry (`xfs_diotask_enter/exit`, `pal/linux/xfs_aops.c`) keyed on task and inode: `mxfs_ilock_admit_ioend` admits a registered task as this inode's own nested EX holder under the still-granted mirror, the same way as the ioend worker, never as a general writeback privilege (`dioend_admit`). An O_DSYNC write's sync tail runs after `inode_dio_end` in iomap, so it acquires fresh and needs no admission.
   - *Polled direct I/O is refused* on a clustered mount (`-EOPNOTSUPP`, `dio_hipri_refused`): `inode_dio_wait` drives no polling, and the ring that would poll can be parked behind the release, so the mode is unsupported rather than half-supported.
   - *Unbounded, like the page-writeback wait:* a bio the device still owns is not over because a clock ran out, and the grant stays this node's until it is; the drain watch names a stall. A/B switch `rel_dio_wait=0` restores the release over in-flight I/O for a control arm.
8. **A dead peer's slice recovery retires the cache images it populated before it publishes.** The survivor's foreign-slice replay (`mxfs_xlog_recover_foreign_slice`, `xfs/xfs_log.c`; `xlog_recover_buf_commit_pass2`, `pal/linux/xfs_buf_item_recover.c`) reads every logged block through the survivor's own cache, applies the image and writes it; those images stay cached, clean, `XBF_DONE`, and were read under no inode tenure, so invariant 6's tenure-end eviction never sees them. After the peer returns, frees the blocks and rebuilds under a different inode number, the survivor's acquire-time eviction (keyed on the acquired inode) cannot see them either and the stale leaf is served from the cache (measured: 158 recovery images of a 20000-extent file; with the same inode number reused the reload evicts all 158, with a different one they are refused at the btree owner check). Mechanism (`mxfs_recov_image_evict`, `xfs/xfs_mxfs_dlm.c`):
   - *Provenance by producer, not by write:* while the recovery task replays (`mp->m_mxfs_freplay_task`), every buffer it reads is tagged `b_mxfs_recov_image` at the read (`xfs_buf_read_map`), whether the replay then rewrites the image or skips it as already newer; the queue site tags again for a cache hit on an untagged image (`recov_tagged`, `recov_queued`). Recovery readahead is off for a foreign replay (`xlog_buf_readahead`) so every recovery read is that synchronous, attributable one. The tag is cleared only by the retirement or by another task's fresh read (a tenure's image again); never by an I/O completion.
   - *Retirement before publication:* after the replayed images are home (`P226-FR-HOMEFLUSH`) and before `IMAGES_REPLAYED` is published and the dead holds are purged, the walk clears `XBF_DONE` on every clean tagged buffer of an extent-allocated class — bmbt, directory/da/attr/symlink, the AG btrees, and any ops the list does not know — with the same idiom as the tenure-end evict (never `xfs_buf_stale`, re-check under the buffer lock, local work refused). Inode clusters, AG headers, the superblock and dquots are explicit exemptions: fixed addresses, and a stale image of one is what every previous tenure of this node leaves, refreshed by their own acquire-time reloads (`recov_other_cached`, counted only).
   - *Fail closed:* a tagged buffer that cannot be locked in 30 s or still carries local work makes the recovery return a retryable error exactly as a home-flush failure does — nothing is published, the next election replays the slice and retires again (`recov_busy`, `recov_localwork`, `P-RECOV-IMAGE-EVICT`). `dbg_recov_evict_fail_after=N` injects that once for the retry arm. `recov_evict=0` keeps the census and skips the retirement (control).
   - *Detector:* a cache hit on a tagged image outside recovery is `recov_cache_hit` (`P-RECOV-CACHE-HIT`), which must read zero; the recovery task's own re-reads of images it populated are expected before retirement and counted apart (`recov_hit_in_recovery`).
   - *Not covered:* the intent-custody path is a separate producer with its own completion obligations; recovery responsibility moving between survivors mid-attempt (a milestone durable on one node does not empty another node's cache).
9. **The slots a recovery patches in an inode cluster are published on the recovery's authority, and its home flush lands them.** The survivor's replay applies a dead peer's inode items into its cached cluster and queues the write, but the inode-cluster publication mask (`mxfs_submit_partial_inode_write`, `pal/linux/xfs_buf.c`) knows only live tenures — logged this round, or held with a write grant — and dropped every replayed dinode as an un-owned passenger, refusing the write with no I/O while the buffer completed as landed (D-0976, 0.87.8: the victim's leaves landed, its dinode did not, and the rejoined victim shut down on the first extent read). The buffer carries `b_mxfs_recov_slots`, set at the inode-item replay, the unlinked-pointer patch and the icreate initialisation, honoured before every other slot rule, cleared at the write's completion; a foreign replay's first patch of a slot takes the platter's image of that slot as its baseline (`mxfs_recov_slot_refresh`), because the survivor's cached copy can predate the dead node's last flush and an image carries only the logged fields. Design record: `docs/foreign-replay-inode-ordering.md`; subsystem detail in `pal.md` (0.87.8).

## sess483 (0.69.0) — `P483-DIRTENURE`: creates per directory-grant tenure (`xfs_inode.{c,h}`)

The shared-directory create cost is now attributed and its mechanism has one open question. Measured sess483 (chain 129, P=32, one shared directory): mean cost per create is **193, 169, 550, 1558, 2151 ms** for F = 8/16/32/64/128 files per node. It **rises** with outstanding work, so it is neither a fixed admission being amortised nor a periodic batching quantum — both of those were the standing readings and both are dead.

**New surface**, in `struct xfs_inode` next to `i_dlm_epoch_src`: `i_dlm_cr_epoch` (unsigned long), `i_dlm_cr_n` (unsigned int), `i_dlm_cr_ms` (uint64_t). Updated at the end of a **successful** `xfs_create`, under the inode's existing `i_flags_lock`, gated only on `mp->m_mxfs_dlm`. When `dp->i_dlm_epoch` has moved — which is exactly when this node lost the parent's grant — the closed-out tally prints as `P483-DIRTENURE parent= epoch= creates= wall_ms= mean_ms= next_epoch= endsrc= comm=`, where `endsrc` is `i_dlm_epoch_src`, the `__LINE__` of the path that ended the tenure.

**Always counted, deliberately not behind a knob**: the print is bounded by grant losses, not by creates, so leaving it on costs a line per handover. **Known limitation, by construction**: a tenure's line is emitted by the FIRST create of the NEXT tenure, so the last tenure on any directory is never reported — one dropped sample per directory, always the final one.

**How to read it.** If creates-per-tenure falls toward 1 as F grows and cost-per-create tracks rotation/tenure, the tenure is collapsing under contention. If the count stays flat while cost climbs, the handovers are getting *slower* rather than more frequent and the root is in the bast/drain/publication path instead — a different bug. Note the unresolved discrepancy before accepting either: the `crash_consistency` trace reports eight waits per node for ~100 creates (tenure ≈ 12.5), which would predict ~120 ms per create, not the 1.5–2 s chain 129 measures.

## sess23 (ccloop c7ee71c6) — inode reference forensics (`xfs_icache.c`, `xfs_inode.{c,h}`)

### New surface
- **`mxfs_live_inodes` / `mxfs_live_inodes_lock` / `mxfs_live_inode_allocs`**
  (`xfs_icache.c`) — a global registry every `xfs_inode` joins in
  `xfs_inode_alloc()` and leaves in `xfs_inode_free_callback()` (the RCU
  callback, immediately before `kmem_cache_free`), so it mirrors the slab's
  live objects exactly. Knob `mxfs.live_inode_track` (default 1, declared in
  `xfs_mxfs_dlm.c` with the other params).
- **`mxfs_report_leaked_inodes()`** — called from `xfs_destroy_caches()`
  (pal/linux/xfs_super.c) after `rcu_barrier()`, i.e. exactly where the kernel
  reports "Slab cache still has objects". Emits `P202-LEAKED-INODE-AT-UNLOAD`
  per survivor plus `P202-LEAKED-INODE-TOTAL`, which **always** prints
  (`leaked=0 tracked_allocs=N`) so a zero is a measurement, not silence.
- **Per-inode attribution fields** on `struct xfs_inode`:
  `i_mxfs_live_link`, `i_mxfs_alloc_jiffies`, `i_mxfs_grab_line`/`_grab_file`,
  `i_mxfs_iget_ret`, and the reference-event ring
  `i_mxfs_refev_ip[]/_kind[]/_cnt[]/_head` (MXFS_REFEV_N=10).
- **`mxfs_igrab_tracked()` / `mxfs_iput_tracked()` / `mxfs_refev_rec()`**
  (`xfs_inode.h`, defined AFTER `XFS_I`/`VFS_I` so they can use them). A .c file
  opts in with `#define igrab(vi) mxfs_igrab_tracked((vi), __LINE__, <id>)`
  (ids: 1=xfs_mxfs_dlm.c 2=xfs_icache.c 3=pal/linux/xfs_iops.c
  4=xfs_filestream.c). `xfs_iget()` records `_RET_IP_` on success and
  `xfs_irele()` records every XFS-side release, so P202 can replay the ring.

### PITFALL — the wrappers must honour NULL
`iput(NULL)` and `igrab(NULL)` are legal. Dereferencing before the check is a
NULL deref (`XFS_I(NULL)` is `-offsetof(i_vnode)`), and it panicked every node
at mount from `mxfs_dlm_pr_sweep_work_fn`'s `iput(toput)` bail-outs. Both
wrappers now return early on NULL. See `pal.md` for the full incident.

### What the P202 evidence says about D-UNMOUNT-BUSY-INODES
Five captures, one signature: **exactly ONE** surviving inode, always a
DIRECTORY (`mode=040755`), `icount=1`, `i_state=I_REFERENCED` only,
`iflags=0x0`, `dlm_mode=3 (PR) dlm_state=1 (CACHED)`, `itemp=1 in_ail=0`,
`dentries=0`, `lru_linked=1`, grabbed by `xfs_iget_cache_hit()`'s `igrab`, last
iget caller `xfs_lookup+0x16c`.

Refuted with measurement — do not re-walk:
- the "ref intentionally leaked" path (`P142-DWORK-LASTREF`) fired **0 times**;
- no mxfs work/dwork/timer pending in any capture;
- no dentry holds it;
- `lru_linked=1` is NOT anomalous — `xfs_fs_drop_inode` -> `inode_generic_drop`
  returns 0 for a live hashed `nlink>0` inode, so XFS inodes do go on the VFS
  LRU.

`i_mxfs_iget_ret` is the LAST iget caller, not necessarily the leaked one
(nearly every inode's last iget is a lookup) — weak attribution. The reference
-event ring exists precisely to replace it and has not yet produced a capture.

### `xfs_lookup()` type-flip resolver — status
The 200-round × 10ms poll that waits for the in-core inode's type to match the
dirent is **not a correctness mechanism** (RULE-5 GPT review): it cannot
distinguish a stale dir image from a stale/old-incarnation inode image from a
durably inconsistent mapping. Keep `mxfs.typeflip_fail_unresolved=1` (never
publish a mismatch) as the safety measure, but the correct form is
parent-lock -> stable dirent + incarnation token -> inode metadata/lifetime lock
-> verify number+incarnation+type -> restart from the parent on an observed
transition -> `-EFSCORRUPTED` on a stable authoritative mismatch.

**Correction to sess22:** `cache_coherency`'s `rename_visibility` only creates
REGULAR FILES, so `dirent_ftype=1 (REG)` is CORRECT. The corrupt side is the
INODE (free + reuse-as-directory under a surviving dirent), not the dirent.

## Known Pitfalls

- **`_XBF_DELWRI_Q` collision:** `xfs_ialloc_inode_init` queues fresh cluster bufs to `pag_mxfs_alloc_buflist` with `_XBF_DELWRI_Q` set. xfsaild's `xfs_buf_delwri_queue` later returns false (already queued), so `xfs_inode_item_push` / `xfs_buf_item_push` return `XFS_ITEM_FLUSHING` and the items stick in AIL. Handled by the `_XBF_MXFS_ALLOC_QUEUED` flag (v0.3.148): bufs with both flags are skipped from `xfs_ail_push_ag_sync` waits because mxfs's Phase 2 drain handles them; bufs with only `_XBF_DELWRI_Q` keep waiting (xfsaild manages those). Skipping them all causes dir3 corruption.
- **ILOCK held across CAW poll:** `xfs_create` line 757-ish takes `xfs_ilock(dp, XFS_ILOCK_EXCL)` before calling `xfs_dialloc`, which deep inside hits `mxfs_ag_dlm_lock` CAW poll. Worked in current code (sess33 verified `xfs_dialloc` doesn't read parent_dir tree, so dropping ILOCK across it is safe). Pattern likely repeats in `xfs_bmap_btalloc` (file write path) — investigate before declaring multi-node general-correctness.
- **Adaptive quantum starts at 1, not at cap:** Starting at cap=32 was too aggressive — by the time first BAST arrives, 32 unlocks of dirty state already accumulated and Phase 2 drain exceeds peer's 120s CAW timeout. Initial=1 + doubling is the right shape.
- **Mode A on simultaneous mkdir** (separate from deadlock): when both nodes create entries in the same parent dir at the same instant, one node's view of the parent doesn't reflect the other's mkdir. Pre-create parents sequentially with `sync` between hosts.
- **The release drain's `S_ISREG` already-durable early-out swallows anything placed after it** (`xfs_mxfs_dlm.c`, the "Already-durable early-out" block): for a regular file that is neither in the AIL nor pinned, the drain does `goto reg_durable_done` — jumping past the reg-durable loop *and* past the debug injection points that live just before it (`mxfs_dbg_bast_pause`, `mxfs_dbg_relog_force_take`). A test that parks a task at its `IOLOCK_EXCL` admission dirties nothing, so if the preceding step ended in `sync` the file is clean when the peer's BAST arrives and the early-out is taken **every time**: the knobs cannot fire however they are armed, and the arm is silently vacuous. To exercise the drain body on a regular file, make the inode dirty at BAST time — a timestamp update works and does not block behind an `IOLOCK_EXCL` holder, because `xfs_trans_alloc_ichange` takes `ILOCK_EXCL` only. Note `P51-REL` is guarded by `S_ISDIR`, so its absence for a file is expected and is **not** a symptom. (sess479, chain 117.)
- **`P227-TOKENSUM classless=` counted valid classes until 0.64.37.** The class tally in `xfs/xfs_log_recover.c` switched on `MXFS_AUTH_CLASS_AG` and `_SB` only, so `_INODE` (3) and `_ICLUS` (4) landed in `default: n_none++` and were reported as classless — a foreign-slice replay with fully tokened rm transactions printed `classless=9`, which reads as "the authority fix did not work". Fixed with explicit cases plus `ino=`/`iclus=` fields. When two probes over the same data disagree, that disagreement is the cheapest root-cause signal available: `P273-SHADOW-EVAL` had been reporting `classless=0` for the same slice all along. (sess479.)

## Historical Bugs

- **sess26(ccloop) dir_reuse_coherency 8/tcp whole-block clobber — ROOT FOUND (capped gen-bump), lever `dir_gen_per_handoff` (DEFAULT 0), build `965BDBD3`**: PROVEN (RULE 4, dataclobber=1 detect run on a real loss: `bufgen==dirgen==379` on the clobbering writes) — the fast-path EX-grant epoch-handoff gen-bump (`mxfs_dir_epoch_adopt`, `xfs/xfs_mxfs_dlm.c` ~12119/12156) is CAPPED by `if (i_dlm_dir_gen <= i_dlm_dir_loaded_gen) i_dlm_dir_gen++`, so it bumps only ONCE per reload cycle. The 2nd..Nth intra-round fast-path handoff fails the cap → NO re-invalidate → a cached dir DATA block stays `bgen==dir_gen` and aliases a peer-superseded image as fresh → the read-path pre-read invalidation (`xfs_da_btree.c:3363`, `bgen != dir_gen`) never fires → holder RMWs/destages a stale base → **whole dir DATA block of a peer's dirents durably reverts** (round1 lost node2_f13-32.md5 contiguous). FIX (gated lever): `if (mxfs_dir_gen_per_handoff || dir_gen<=loaded_gen) dir_gen++` at both fast-path sites → i_dlm_dir_gen advances on EVERY cross-node handoff. SAFE: the master dir epoch advances only on a real cross-node handoff (a peer held EX), never while we hold EX continuously, so no spurious mid-tenure re-read. RESULT: loss reduced **whole-block (~20 entries) → SINGLE-entry (readdir=799)**. RESIDUAL (next session): the per-handoff re-read also re-reads LEAF blocks, bringing in a leaf NEWER than this node's in-core data-fork EXTENT MAP (peer grew the dir) → `!(flags & XFS_DABUF_MAP_HOLE_OK)` internal error (`xfs/libxfs/xfs_da_btree.c:2876`, 511×, trips `dmesg_clean`). OPPOSITE of sess20's stale-leaf hole (postread_leaf_only won't fix it); needs a COORDINATED extent-map refresh on the per-handoff invalidation (NOT leaf exclusion, which re-exposes sess20). sess68 (P68-MAPDIVERGE=0) proved maps agree at modify-PRELOCK — the hole is the per-handoff re-read window only. Keep `dir_gen_per_handoff` default 0 until leaf/map consistency is solved; build is keeper-equivalent at default. Decisive lesson: the clobber is NOT detectable at any async write/read chokepoint (gen doesn't advance on fast handoff = read-guard blind; write-time disk-compare is racy + can't distinguish a legit remove); the reliable fix is making the per-handoff coherency signal (i_dlm_dir_gen) actually fire every handoff. See `docs/history/progress-dir-gen-per-handoff-wholeblock-to-single-but-dabuf-hole.md`.
- **sess43 dir_reuse_coherency 2/tcp durable dirent loss — FIXED (criterion met)**: cross-node shortform→block CONVERSION divergence. Two nodes concurrently grow a *fresh* shared dir from shortform and each run `xfs_dir2_sf_to_block` independently for the same incarnation → the dir's logical block-0 lands at different physical blocks (node1 fsb15 / node2 fsb14) → split → cold verify orphans one block (readdir shortfall + leaf-hash holes). Proven non-perturbingly via the P42-SFCONV detector (two same-`i_gen` conversions). Fix (build `422E6DC6`, `xfs/xfs_mxfs_dlm.c`): (1) **`mxfs_dir_force_block = 1` DEFAULT** — multinode dirs are forced BLOCK at mkdir (single-node conversion only), structurally eliminating the concurrent conversion; (2) **P43 / P43B reload format-revert guards** — refuse a same-incarnation block→shortform reload revert at both reload sites in `mxfs_dlm_reload_inode` (live `dip` pre-spin + post-spin snapshot), covering the self-revert sub-case. Verified: 3 clean `PASS dir_reuse_coherency (nodes_pass=2/2)`, drc-FAIL=0, zero double-conversions over 72 rounds. (sess18 had found force_block alone ineffective on a 40-sessions-older build whose block-0 RMW still clobbered; intervening coherency fixes closed that gap.)
- **sess19(ccloop) inode-cluster FUA-read thrash — FIXED (perf, KEEP, build `15447D0C`)**: the sess38 per-inode cluster re-stale in `xfs_iget_cache_miss` (xfs/xfs_icache.c) fired on EVERY multi-node inode iget and `xfs_buf_stale`'d the WHOLE 32-inode cluster buffer → reading N co-resident inodes (a readdir+stat verify, or rm-rf) re-FUA-read that one cluster N× (proven: 59 distinct inode daddrs each FUA-re-read ~12×/round; igstale 5376/8rounds → 0). The sess38 stale only guards the cached-FREE→peer-ALLOCATED ENOENT case; so skip it when the cached cluster already shows THIS inode ALLOCATED (`mxfs_dinode_cached_allocated()` = valid di_magic + di_mode!=0 — the exact inverse of the bug). Content coherency is unaffected (refreshed at ilock by the inode-DLM reload). Param `inode_cluster_owned_skip`=1. Cut inode FUA ~30%; validated SAFE — full 8/tcp suite's cache_coherency/zero_silent_loss/strong_consistency/crash_consistency all 8/8. **Note: the 8/tcp criterion is NOT met — blocked by the mht tradeoff (dir_reuse needs high mht, tcp_dlm_scaling needs low mht); the dir-data-block handoff-reload durable dirent loss at low mht is the deep remaining work (see ccmemory sess19run-* memories).**
- **sess33 lock-inversion deadlock**: bast_work_fn's xfs_ail_push_ag_sync wedged because xfsaild's iop_push for inode items returned FLUSHING (DELWRI_Q collision), and for buf items the cluster buf was on `pag_mxfs_alloc_buflist` waiting for Phase 2 — circular. Fix: IFLUSHING-skip + `_XBF_MXFS_ALLOC_QUEUED`-skip in `xfs_log_item_in_ag` + iter>0 gate to ensure xfsaild has run before declaring drained. v0.3.148.
- **sess32 Phase 1 inode-bast used whole-AIL push** (cross-AG deadlock at 5×512MB+). Fixed v0.3.137: per-AG variant.
- **sess32 q=8 "corruption"** was actually transient symptom of AG-DLM contention starvation, not separate bug. Collapsed to single root cause in sess32 close.
- **sess26 SCSI CAW non-persistence under stress** (kernel scsi_execute_cmd). Sidestepped by sess27 TCP DLM transport (kept as fallback); also v0.3.128 manual-bio CAW path A reduces incidence.
- **sess21 LIO target dropping FUA bit** (read coherency). Worked around by `mxfs_buf_read_fua` (SCSI READ(16) FUA passthrough) + `_XBF_FUA_FRESH` freshness gate (v0.3.129).

## Files

Key MXFS-overlay files inside upstream-fork tree:
- `xfs/xfs_mxfs_dlm.{c,h}` — primary mxfs hook surface (3500+ LOC).
- `xfs/xfs_trans_ail.c` — added `xfs_ail_push_ag_sync` + `_bounded` variant.
- `xfs/libxfs/xfs_ag.{c,h}` — pag fields for DLM state.
- `xfs/libxfs/xfs_alloc.c` — mxfs_ag_dlm_lock at xfs_alloc_vextent_prepare_ag.
- `xfs/libxfs/xfs_ialloc.c` — `_XBF_MXFS_ALLOC_QUEUED` flag set at line ~441.
- `xfs/xfs_inode.c` — `xfs_create` re-acquires dp ILOCK after dialloc (v0.3.148).
- `mxfs_clayer/yield_quantum.{c,h}` — quantum constants (small).

## sess5 (ccloop a16ec5f2, 2026-07-02) — three landed root fixes + ABBA map
- `xfs_mxfs_dlm.c` ~12760: P5F-FRESHSRC-SELFCLOBBER-SKIP — FUA-fresh FREE image never adopted over a live in-core inode that is pinned/ili-dirty/in-AIL or holds a non-NL grant (P116 discriminator applied to the FRESHSRC path). Root of class-B dangler #1.
- `xfs_mxfs_dlm.c` ~9333 (inode-BAST cluster-buffer stale): now guarded by mxfs_buf_has_uncheckpointed_mods → P91-BAST-PROTECT. Staling with attached committed-not-written co-resident ili stranded IFLUSHING-in-AIL forever (P113 wedge, creates never destaged). Root of dangler #2 + multi-second BASTs.
- `__mxfs_ag_dlm_lock` slow path: P5D-PREWAIT-DEFERRED-BAST — before blocking on a peer-held AG with a CLEAN trans, fire t_mxfs_inode_unlocks (trans-deferred inode BASTs). Breaks the dialloc edge of the create-vs-create ino↔AG ABBA (the ilock_end Approach-A deferral had silently re-created the dir hold that v0.3.148's ILOCK drop removed).
- REMAINING (stack-proven, run36): dir-grow edge — xfs_dir2_grow_inode→xfs_bmap_btalloc blocks up to 61s on ONE peer-held AG with dirty trans + dir DLM EX held; needs bounded/rotating AG acquire (design in docs/history/end-abba-grow-stack-proven-design-next.md).
- AG-handoff wire probes (ungated): P5B-AGBAST-SEND (v5_mount.c), P5R-AGREL[-ENOENT|-STALEGEN], P5U-AGUNLOCK[-ENOENT] (dlm.c); dirwr-gated: P5N-AGBAST, P5W-AGBAST-BAIL/COMMIT, P10-INSTR ACQ/REL per AG.
- ilock_begin failure is VOID/silent: a 61s ino-DLM -110 lets the op proceed UNSERIALIZED → EFSCORRUPTED dirty-cancel shutdown (run35 test1). Needs error propagation.


## sess12(a9a03929) — pin-aware release abort (FIX-A), iget-miss cluster reload (FIX-B), forensic probe stack

### FIX-A — release abort must honor i_dlm_pin_count (xfs_mxfs_dlm.c ~10420)
bast_process's release-abort re-check tested only ex/pr holders + tenure gen.
FIX3's create pattern (EX begin → mxfs_inode_pin(dp) → iunlock → dialloc →
re-lock) leaves ex=0 pin=1 during dialloc; an idle-release already past its
entry check released the pinned grant (r10 round-4 t2: grant gen=10298 landed
.162703, pipeline entry .162838, pin .163130, P51-REL .164115 unlocked it).
Consequences: FIX3's ABBA fix silently no-ops (fence/defer_finish rc=-110
shutdown family) + concurrent dir-EX windows (dir_reuse same-slot double-add,
r7: two LADDs at aoff=2416 80µs apart on the same base). Now pin>0 aborts the
release; a PIN-ONLY abort leaves state=CACHED (BAST would push the FIX3
re-lock down the P109 EDEADLK storm) + arms i_dlm_bast_pending — the unpin
quiescent arm in mxfs_clayer/pinned_resource.c fires the deferred release.

### FIX-B — lookup-iget sticky-stale cluster buffer (xfs_inode.c retry_iget + mxfs_dlm_iget_miss_reload)
A dirent-resolved inum that igets -ENOENT/-EFSCORRUPTED on a multi-node mount
while peers iget it fine = this node's cached inode-cluster buffer (XBF_DONE
from the free-era read) serving a stale image; nothing on the miss path
revalidates (the node never acquires that AG). Fix: xfs_imap → incore buf →
if clean (not pinned/dirty/delwri/in-AIL) clear XBF_DONE|_XBF_FUA_FRESH →
bounded retry (≤3, 10ms×try). P12-IGETMISS-RELOAD names fires. Face: dlm_scaling
"nodeX completed quota got=0" (first op ENOENT on own fresh subdir).

### Probe inventory added (all ungated; find with `grep P12-`)
- P12-AGBAST-RX / P12-READOPT / P12-WORK(enter/bail1/bail2/COMMIT) / P12-ULBP:
  AG BAST pipeline visibility; perag gained pag_dlm_bast_pending_since,
  pag_dlm_readopt_n, pag_dlm_holder_pid/comm (stamped at all holders 0→1).
- P12-HOLDERTASK: sched_show_task of the stamped AG holder when a BAST sees
  page_ms>15s (cap 6/boot) — names non-DLM-waiting stuck holders.
- P36-STACK (dlm.c): dump_stack at the FIRST acquire-timeout retry (cap
  8/boot) via new mxfs_pal_dump_stack.
- P12-DLMTR ring: 1024-entry per-inode mode/state transition ring for
  mxfs_watch_ino; EVERY i_dlm_mode/i_dlm_state assignment in xfs_mxfs_dlm.c is
  wrapped with mxfs_dlmtr_rec(__LINE__); dumped by mxfs_dirdump (drc
  .mxfs_dirdump1 trigger). Grant-path transitions are otherwise silent in
  CACHED/ACQUIRING (P71 prints only in DEMOTING/BAST).
- P10-DIRDUMP-BLK now prints lba= (daddr+bt_sector_offset); the drc test dd's
  each dumped block raw (O_DIRECT) to /root/drc_blkdump_r<round>_rank<R>/.

### Field decode notes (hard-won)
- P50-RD `cnt=` is the block's ACTIVE-DIRENT count (not a read counter);
  `sum=` is a content checksum — a lost-dirent fork shows as 144 adds vs final
  count 143 with NO observed cnt regression when the loser fork was never read.
- MXFS_DLM_ISTATE: NONE=0 CACHED=1 BAST=2 DEMOTING=3 ACQUIRING=4.
- Grant-response status 10 = MXFS_ERR_UPGRADE_CONFLICT (mxfs_common.h) → local
  -EDEADLK → P109 self-demote+fresh-EX dance.  **Holding NL (D-0904)**: when the
  inode layer holds NOTHING (i_dlm_mode NL, state ACQUIRING, no iclus route, no
  demoter) the entry the master denies against is a phantom; the 0.75.6 arm
  (`P109-EDEADLK-NL`, xfs_mxfs_dlm.c ~34181) skips the demote wait, releases it
  and restarts the acquire (64-lap guard → shutdown).  On TCP the phantom can
  live ONLY on the remote master (a predecessor incarnation's shared bit on our
  heartbeat slot imported there as our PR; rejoin_residue s513a arm 2: 65 laps
  of `P-CONVBLK-DENY`, zero release traffic) — the local unlock finds no entry
  and sends nothing, so 0.75.11 also sends `mxfs_v5_dlm_inode_orphan_nak` (the
  FIX-20b gen-0 unconditional release, gated on no local entry of any state);
  `P109-EDEADLK-NL-RELEASE ino= lap= rc= nak_rc=` records both.
- rc=-35 in "DLM inode lock failed" = -EDEADLK (not EAGAIN).

## sess15(a9a03929) — FIX-H family: cleanup releases must not eat live grants
Root (r10 8/tcp drc, ms-decoded from ring snapshots): bast_notify's P135
"orphan" branch (in-core NONE/NL + mxfs_v5_dlm_inode_held) misreads the TCP
GRANT-COMPLETION WINDOW — the receive kworker links the mirror before the
blocked acquirer resumes, and inode_held reads that same local mirror — and
queues a serialized release that passes every abort check (entry_gen==rel_gen,
holders==pin==0 while the acquirer is still in its post-grant reload) and
wire-releases the just-granted tenure.  Master re-grants 0.7ms later →
true double-EX → same-offset dirent adds → durable one-dirent swallow.
Three layers landed (xfs_mxfs_dlm.c):
1. P135-GRANTWIN-PARK (bast_notify): held==1 && grant_gen!=0 → park the BAST
   (bast_pending + MHT dwork, bastq_src=13) instead of queueing the release.
   grant_gen==0 keeps the CAW disk-slot orphan semantics.
2. P15 recheck backstop: orphan_live = entered-with-mode==NL && live gen &&
   !p_self_demote → abort (state=NONE for pure-orphan, bast_pending, 25ms
   dwork re-arm bastq_src=14) with 4-strike same-gen escalation →
   P15H-STRANDED-RELEASE (a never-consumed grant IS released for liveness).
3. CRITICAL EXEMPTION: the P109 EDEADLK self-demote (bastq_src=6) enters with
   the same signature and MUST release — blocking it wedged the cluster
   (r13: rc=-35 ×1009, LKTIMEOUT cascade).  i_dlm_self_demote discriminates.
Fields added: i_dlm_orphan_gg / i_dlm_orphan_strikes (xfs_inode.h).
Validated: 8/tcp 17/17 ×6, 4/tcp ×3, 2/tcp ×4/5, 1/tcp ×3 (builds 3C674F70 /
3AD15DA9).

### P15I-CRCFAIL probe (pal/linux/xfs_buf.c __xfs_buf_ioend)
On read-verify failure (EFSBADCRC/EFSCORRUPTED, multi-node): per-512B-sector
crc32c fingerprint of the FAILED image (capped 16).  Armed for the 2/tcp r3
crash_consistency face: inobt 0x7fc2b8 CRC-failed an instant after
P126-XFSAILD-SKIP-AGMETA staled the same dirty in-AIL buffer, yet the platter
block was later fully valid — compare P15I sector CRCs against the raw disk
(clyde ~/disk.img, xfs_data_offset from tools/chk_mxfs -v) to
separate torn in-core mix from durable-garbage-later-repaired.  Suspect #1:
the P126 discard of committed (in-AIL) AG-meta (tension with the sess43
BB54A138 invariant).

## sess16(a9a03929) — set-lock DLM ordering INVARIANT + hot-gate cost (build B48AC2C8, criteria met)

### INVARIANT (FIX-L3): never block on a cross-node DLM acquire while holding any inode rwsem
`xfs_lock_inodes` / `xfs_lock_two_inodes` (xfs/xfs_inode.c) now run a
Phase A that acquires EVERY set member's inode-DLM grant first —
ascending ino, mode via `mxfs_setlock_dlm_mode` (the xfs_ilock mapping),
each HELD until the caller's `xfs_iunlock` — then Phase B takes rwsems
via `xfs_ilock_nowait` only, with backoff releasing rwsems RAW
(`mxfs_iunlock_rwsems_raw`, keeps the DLM hold).  Why each shape is
forced (both alternatives were built and failed in-cluster):
- Blocking begin under a held member rwsem (pre-L) = k1 ABBA: the held
  child can't `iflush_cluster` (needs ILOCK_SHARED nowait) → its AG BAST
  drain stalls (`P67-AG-BAST-STALL`, `ilocked=` field added) → the peer
  our dir-conversion waits behind starves 60s+ → rc=-110 shutdowns.
- begin+end-then-retry (L1) = grant ping-pong livelock: ilock_end at
  zero holders fires the pending peer BAST inline and forfeits instantly.
- dirs-first Phase A (L2) = convoy: remove holds the shared dir EX
  across its cross-node CHILD acquire → 8-node drc create collapse.

### FIX-K: `mxfs_dlm_is_single_node` is LOCKLESS (dlm/dlm.c) — keep it that way
It is the gate at the top of every hot hook (xfs_buf.c, ilock begin/end,
readdir, trans paths): ftrace measured 2,276,687 calls in ONE paired
rsync leg; the old global mutex was the single_node_paired ~5% residual.

### Diag tooling (in-tree)
`tests/tooling/paired_perf_diag.sh {ftrace|perf|stats}` — per-leg
function-profiler / perf / diskstat instrumentation for native-vs-mxfs
gaps.  `tests/tooling/fio_vs_xfs_baseline.sh` now position-balanced
rounds (XM MX MX XM, time_based writes, trimmed mean) like paired.
Streak evidence: `tests/results_sess16_streak/` (12 runs, 0 FAIL).

## sess7(ccloop 46efd8b6) — LIVE-fork destroy landmine + dwork strikeout (v0.10.31)

### INVARIANT: a destroyed fork must read as fully empty
`xfs_idestroy_fork` (libxfs/xfs_inode_fork.c) now zeroes `if_broot_bytes`
when freeing `if_broot`.  Upstream only destroys forks at teardown, so a
stale byte count is never re-read; mxfs's reload/adopt
(`mxfs_dlm_reload_inode` → `xfs_idestroy_fork` + `xfs_inode_from_disk`)
destroys and rebuilds LIVE dir forks.  A dir that had converted
extents→btree (`if_broot_bytes` = 1-rec root size) then reloaded from an
extents-format disk image kept `{if_broot=NULL, if_broot_bytes=S1}`; the
next extents→btree conversion's `xfs_bmap_broot_realloc(ip, fork, 1)`
hit the `new_size == old_size` nop path, returned the NULL broot, and
`xfs_bmbt_init_block` wrote NULL+4 → Oops 0002 killed the creating task
IN PLACE holding dir i_rwsem + i_lock + i_dlm_ex_holders → node-wide dir
wedge → 15-peer starvation (dir_reuse@16 killer, test9 2026-07-10).
`P80-BROOT-TORN` WARN-and-heal at `xfs_bmap_broot_realloc` entry
(libxfs/xfs_bmap_btree.c) catches any other producer of the torn state.
Same landmine class as the documented `if_data`/`if_bytes` one
(xfs_mxfs_dlm.c:16305 comment) — when adding fork-reset paths, reset the
SIZE fields with the pointers.

### P36 dwork STRIKEOUT (i_dlm_dwork_strikes, xfs_inode.h)
`mxfs_dlm_bast_dwork_fn`'s busy branch re-arms every ~8ms while
ex/pr/pin holders are in flight.  A holder that never drops (leaked by
an oops-killed task) made that an infinite spin holding an iget ref →
unmount leaked the inode ("Objects remaining on __kmem_cache_shutdown")
→ post-rmmod bio completions panicked the node (netconsole Oops 0010 in
blk_done_softirq).  Now 2500 consecutive busy re-arms (~20s) within one
deferral episode → P36-STRIKEOUT: log, drop ref, stop re-arming;
`i_dlm_bast_pending` stays set so ilock_end/unpin refire or peer ~1s
BAST retries re-arm a fresh episode.  Strikes reset ONLY on a fresh
episode (bast_pending 0→1, 6 sites) + dwork-quiescent + inode init —
NOT on repeat BASTs, else 1s retries would defeat the bound.

### kcore live-forensics pattern (no module reload needed)
`gdb -batch mxfs.ko` (DWARF) → struct offsets; `/proc/kallsyms` → static
ring/param addrs; python ELF-parse `/proc/kcore` → read the mxfs_dlmtr
ring, or scan the direct map for an ino's xfs_inode and dump DLM
counters + rwsem owners (leaked-lock attribution).  Scripts:
sess7 scratchpad `rdring.py`, `findino.py` (memory
docs/history/root-broot-bytes-oops-and-wedge-chain.md).

## Release-pipeline observability probes (sess7 ccloop 8ba7ae5c, 0.10.118-120)

`mxfs_dlm_bast_process` (xfs_mxfs_dlm.c) gained two always-on, capped
(20000) probes bracketing the inode-release endgame, added to prove the
iter_13/14 lost-final-shrink and kept for future forensics:
- **P146-RELDUR** (right after the reg/dir durable-flush loop's
  P-REG-DURABLE-FAIL): ino, in-core `if_nextents`, `inode_peek_iversion`
  (chg), i_size/i_disk_size, `flushed`/`p2_loop_wrote`/`rerr` (the loop's
  outcome arms), IN_AIL, pincount, `ili_fields`, comm, realns.  A release
  that prints `flushed=1 wrote=0 rerr=-11 ili_fields=0x0` while carrying
  state newer than the platter = the clean-but-never-written signature
  (the P150 pre-fix smoking gun).
- **P147-PREUNLOCK** (immediately before both
  `mxfs_v5_dlm_inode_unlock_gen` arms — anchored + P6ZC no-anchor): same
  identity fields at the instant the on-disk unlock makes the peer's read
  legal.  P147.chg > P146.chg for one release = a local op mutated the
  dir between durable flush and unlock (a hole that was NOT observed —
  the iter_14 root was the read-clobber, see pal.md P150).
- P105-REL-DIRINODE high-ino arm: capped pr_warn (was ratelimited — the
  ratelimit dropped exactly the storm releases under investigation) and
  now prints chg.
Volume: per DIR-inode DLM release only — measured safe in cc/pm/dlm_scaling
storms.  Contrast P56-CORESIDENT-DIR-SKIP (pal/linux/xfs_buf.c) which fires
per partial-cluster WRITE: it must stay pr_warn_ratelimited (un-ratelimiting
it cost dlm_scaling@32 its 50 ops/s floor — see docs/history/printk-volume-is-a-perf-criterion.md).

## sess5 (ccloop-4dd7) — s_remove_count shadow ledger + drain RCU fix
- ALL nlink writes on xfs inodes route through `mxfs_set_nlink`/`mxfs_drop_nlink`/
  `mxfs_inc_nlink` (xfs_inode.h) maintaining `MXFS_IF_RMC_ACCT` (bit 23) = "this inode's
  nlink-0 state holds +1 in sb->s_remove_count". Unpaired 0→N decs scream (P9-RMC-*).
  Corpse rule: I_CLEAR inodes adopt nlink RAW (accounting closed by __destroy_inode);
  `xfs_reinit_inode` sets i_state=0 BEFORE the restore to re-open accounting. Root #6:
  the sess40 reuse-reload ran from_disk on destroyed corpses → counter -1 → per-op WARN
  storm at fs/inode.c:289 (= the suite-soak 833-hit failure) + permanent remount-ro EBUSY.
- `mxfs_dlm_ag_drain_meta_buffers`: never sleep inside rhashtable_walk_start..stop (RCU).
  The write path stops/resumes the walk around blocking lock+bwrite; whole walk repeats
  until a pass writes nothing (≤8, P-DRAIN-PASSCAP). Invariant 1 coverage is now ≥ the
  old single pass.
- Deferred-deadshell CREATE verdict (xfs_iget_recycle): when the cluster buffer is
  P91-protected, the DISKLIVE reject verdict side-reads the platter (P-CR63-SIDEREAD)
  instead of trusting the kept (possibly pre-free) cached bytes — b70r1 -117 shutdown root.

## v0.11.81 — ilock_end holder bookkeeping is unconditional (2026-07-25)

**INVARIANT (P125 root fix, ring-proven):** `mxfs_dlm_ilock_end`
(xfs_mxfs_dlm.c) must run the ex/pr holder-count decrement UNCONDITIONALLY —
the `!m_mxfs_dlm` / `is_single_node` gates sit AFTER the bookkeeping and
gate only the multi-node machinery (BAST fire, flush arming). The old
head-gates leaked one holder whenever membership collapsed to single-node
(peer death) or the DLM was torn down (umount) between an op's begin and
end; leaked `i_dlm_ex/pr_holders` block the reclaim gates and feed the
busy-inodes-after-unmount / VFS_BUG_ON(I_FREEING) teardown family.
P71-UNDERFLOW prints are multi-node-gated (single-node unpaired ends are
expected — ilock_begin's bypass never incremented).
Forensics kept in-tree: the `mxfs_dlmtr` watch-ino ring records ex/pr
counts per event (`MXFS_DLMTR_H` annotations at every holder mutation);
P125-EVICT-SUSPECT prints the EX-admission stamp (exh_pid/comm/age) and
auto-dumps the ring when `mxfs.watch_ino` matches the inode.
Deterministic repro (kept for regression): converged 2-node, hard-kill
peer, `touch` on survivor (blocks through gate+death), umount → pre-fix
P125 2/2, post-fix 0/2.

## v0.11.87-93 — FIX-26 writepages admit + AG orphan-NAK detection (ccloop c7ee71c6 sess6, 2026-07-25)

`xfs/xfs_mxfs_dlm.c`:
- `mxfs_ilock_admit_ioend` WIDENED (FIX-26): admits `xfs_task_in_writepages()`
  tasks (bdi flusher / sync / fsync — they hold FOLIO LOCKS across
  ->map_blocks' delalloc-convert `xfs_ilock(EX)`) through the BAST/DEMOTING
  demote-wait under a still-granted EX/PR mirror, exactly like the FIX-25
  ioend admit (nested EX, ex_holders-counted, release aborts at holders gate).
  Without it: permanent AB-BA vs the bast drain's `filemap_write_and_wait`
  (`__folio_lock`) — captured live on test8 (P73 ino=10485894 req=5 mode=3
  state=3=BAST work_busy=3 every 30s, 70+ min; every later run's create-wave
  `sync` then wedged behind the dead flusher).  P25 print: `src=ioend|writepages`.
  **INVARIANT (0.75.43, D-0918): an admit is booked in the counter the
  requested mode's `mxfs_dlm_ilock_end` decrements.**  FIX-27 widened the
  admit to the submitter's SHARED request (`xfs_map_blocks` ILOCK_SHARED)
  but the site still did `ex_holders++` for it; the PR unlock underflowed
  `pr_holders` (`P71-UNDERFLOW mode=PR un=xfs_map_blocks`) and one EX hold
  leaked for the inode's in-core life, deferring every later BAST on the
  file forever.  Measured 2/tcp 0.75.41 (s523h/s523m): writer never released
  the hot file, peer's rm held the parent in its hand-off relock, writer's
  next lookup waited for the parent, D-0912's live-holder wait parked both
  nodes for 8 min (476/479 deadlines), prep could not unmount either.  Any
  `P71-UNDERFLOW` in multi-node is a mispaired begin/end and must be chased
  to its begin site — a leaked EX on a dir has the same consequence.
- `mxfs_dlm_ag_bast_notify`: orphan-grant NAK detection — unheld shape
  (`holders==0 && !pag_dlm_cached && !bast_scheduled` && bast pending >3s)
  → `mxfs_v5_dlm_ag_orphan_nak` outside `pag_dlm_lock` + `P5N-AG-ORPHAN-NAK
  src=bast-rx`.  Companion + full anatomy in dlm.md v0.11.92 section.
- EX-flow fact worth keeping: the mode==EX fast path serves EX requests even
  in state=BAST (drain hasn't pre-cleared mode yet) — only sub-EX-mode
  requests park in the demote-wait.  bast_process pre-clears mode→NL early
  (~12362-12390, RELFLUSH set first), so its own drain writeback converts
  delalloc at mode=0 via the demoter-bypass (P26PRE dem_cur=1 = normal).

`xfs/xfs_aops.h`: + `bool xfs_task_in_writepages(void)` (FIX-26; impl in
pal/linux/xfs_aops.c — see pal.md same-date entry).

## v0.11.95-98 — FENCE-V1 dir-block write fence + leaf-rebuild format gate (ccloop c7ee71c6 sess7, 2026-07-25)

The crash_consistency@8/tcp torn-da3 root (sess6-C dossier) is CLOSED:
20/20 rung green at srcver 02D5804CDD34C15FF16DF06.

`xfs/libxfs/xfs_dir2_leaf.c` — **THE root fix**:
- `mxfs_dir_rebuild_leaf_from_data` now gates on
  `xfs_dir2_format(args,&frc) == XFS_DIR2_FMT_LEAF` before its
  `xfs_dir3_leaf_read(geo->leafblk)`.  Ungated it (a) probed LEAF_OFFSET on
  BLOCK-form dirs via `xfs_dabuf_map` WITHOUT HOLE_OK → corruption machinery
  (mark_sick + "Corruption detected" + P14-DABUF-HOLE + ms-long FUA hole
  probes) on every armed create (= Defect B's original signature), and
  (b) mid leaf→node split could relog a STALE LEAF1 image of the block
  becoming the da3 root — the committed/AIL stale image xfsaild + drains then
  wrote at any gmode = the sess6 torn-block producer family (Defect A).

`xfs/xfs_mxfs_dlm.c`:
- FENCE-V1 dir-drain task registry (~:11334): `mxfs_dirdrain_{enter,exit,
  set_mode}` + `mxfs_task_in_dir_drain()` (returns true only for an
  EX-outgoing bracket).  All 6 `mxfs_dlm_bast_process` call sites bracketed;
  `set_mode(p_held_mode)` stamped at bast entry.  v1.1: the sanction is
  ATTRIBUTION-ONLY — the fence never allows on it (P97 relfence orders
  publication before unlock, so sub-EX drain writes are republishes).
- `mxfs_dir_flush_one_daddr` FUA arm gated on `!dbp->b_mxfs_fence_skipped`:
  a fence-suppressed "write" must not have its stale bytes FUA-republished
  (raw SCSI passthrough bypassed the fence and races holder bios at the
  target — the 185647Z residual torn reads).
- `mxfs_danode_crcfail_probe` (~:17322) — P-DACRC/P-DACRC-RAW forensics at
  the instant a multinode da3 read fails CRC: per-sector crcs + lineage crc
  (same crc32c-past-48 key as P-DIRWR) of the failing image + immediate
  plain and FUA raw re-reads → torn-on-LUN vs torn-in-flight vs
  cache/platter divergence, matchable against the P-DIRWR write timeline.
  Hooked from `xfs_da3_node_read_verify` (CRC-fail + alien-magic branches).

`xfs/xfs_buf.h`: + `bool b_mxfs_fence_skipped` (one-shot verdict, set by the
fence's suppress arm, cleared when a dir write passes the fence; consumed by
the FUA arm above).

Facts worth keeping:
- The fence's suppress = complete-as-success without I/O (P122 idiom):
  wseq stamps at ioend so `mxfs_dir_data_durable` converges; bli-free
  buffers also staled+!DONE (next access cold-reads).  Log-obligated
  (bli-dirty / IN_AIL / pinned) sub-EX writes are ALLOWED + P-FENCE-AILLEAK
  census (zero observed since the gate).
- P123 still fires occasionally during GREEN runs (dir_reuse 19:55: leaf1
  lseq=0 done=0 has_bli=0 kworker) — the fence is load-bearing against a
  residual sub-EX republish producer (suspected same family as the transient
  readdir undercount, open task).
- P146V-UNLANDED + P5U-AGUNLOCK + P25 src=writepages firing during green
  runs = the heal arms working as designed, not failures.

## sess10 (ccloop c7ee71c6, 2026-07-26, v0.11.104-108) delta
- xfs_inode.c xfs_lookup P95 block: reused-ino reloads are now BOUNDED-BLOCKING (≤200×10ms)
  for both typeflip (until in-core ftype == dirent ftype; P95B print) and sametype (until
  i_dlm_stale clears; P95C) — lookup must never return an unconverged stale incarnation
  (Shape-1 root fix; lost creates via ENOTDIR + empty reads).
- xfs_inactive ifree: mode/gen disk read SKIPPED under MXFS_IF_LOCAL_UNLINK &&
  mxfs_inact_dlm_locked (sentinel 0xFFFF; B1/B2 inert by design) — the last synchronous
  per-unlink target round-trip; dlm_scaling@32 15→34 ops/s.
- xfs_mxfs_dlm.c mxfs_dbg_disk_di_mode: primary read now coherent plain-bio; FUA is the
  instr-gated P103-FUA-DIVERGE secondary.

## sess13 (ccloop c7ee71c6, 2026-07-26, v0.11.115-117) delta
- xfs_trans_ail.c xfs_ail_push_ag_sync_bounded: D1 wedge probe — mxfs_rwsem_owner_peek on the
  stuck ino's i_lock; P67-STALL-OWNER line per stall-abort (item lsn, AIL min, l_tail_lsn,
  grant heads, owner identity, mxfs_ilk last-locker) + P67-STALL-OWNER-STACK throttled
  sched_show_task of the holder (30s).
- libxfs/xfs_dir2_sf.c xfs_dir2_sf_verify: refuses sfp==NULL (was a PANIC: RIP +0x26 CR2=1,
  test6+test12 dual crash — torn-fork window, root OPEN). libxfs/xfs_inode_fork.c
  xfs_ifork_verify_local_data prints P171-SFNULL forensics (ilk last-locker = mutator id).

## sess22 (ccloop c7ee71c6, 2026-07-29, v0.11.172-178) delta

### THE FIX — `mxfs.reload_demote_wait_ms` (default 50), `xfs_mxfs_dlm.c`

`mxfs_dlm_reload_inode()` used to ABANDON the reload whenever another task held
`ip->i_dlm_demoter` (`P34J-RELOAD-DEMOTE-BAIL`).  Its own comment promised
"the caller retries once the demote completes" — **no caller ever did.**  That
unimplemented half was the escape hatch for the silent mkdir loss:

    P65-EPOCH-CONVGATE      asks for reload+adopt (peer converted the dir)
    P34J-RELOAD-DEMOTE-BAIL abandons it because a release drain is active
      -> i_dlm_dir_valid_epoch stays behind the master dir_epoch
      -> P32E-DIREPOCH-FENCE (xfs_inode.c) then SKIPS EVERY FLUSH of whatever
         the operation goes on to commit (seen 3x for one inode: from mkdir,
         from xfsaild, from a kworker)
      -> the release drain exits flushed=1 with pending=17 durable=12
      -> P177 discards the change at the next adopt.  mkdir(2) returned 0.

Now it WAITS, bounded, in 1 ms steps, then proceeds
(`P198-RELOAD-DEMOTE-WAITED`).  On timeout it falls back to the original bail,
so a drain blocked on a lock we hold costs only the bound — never a deadlock.
Sleeping is legal here (the function does `xfs_imap_to_bp` further down).

Paired, fresh-prep-per-pass, 60-round `sf_mkdir_storm` at 32 nodes:
fixes OFF -> 3, 4, 4, 1 durable losing rounds (P32E 6/7/9/3, P34J bail 936/874/641);
fixes ON -> **0 across 7 runs** (P32E 0, P34J bail 0, P198 waited 617/567/497).
Wait cost: mean 4.06 ms, 2.3 s total cluster-wide per 120 s storm.

**STILL OPEN** — `P195` fires 1-7x per run even with the fix: a tenure still
mutates an epoch-stale base and then recovers.  The remaining work is to adopt
at EX ACQUIRE, before the tenure is exposed to the operation.

### P32E-DIREPOCH-FENCE (xfs_inode.c) — its stated premise is FALSE

The fence's comment claims "our own real changes were landed by our release
drain before the peer could acquire, so nothing of ours is lost by skipping."
Captured counter-example: in-core `nlink=3 size=22` vs disk `nlink=2 size=6` —
our just-committed dirent was in that fork and nowhere else.  The publication
obligation counters (`i_mxfs_pub_pending_seq` vs `i_mxfs_pub_durable_seq`) are
exactly the test for that premise.  **P32E is the drop site**; its firing count
tracks durable losses closely.

### New probes and one new inode field

- **`P196-UNLOCK-OBLIGATION-CLASS`** (in `mxfs_dlm_bast_process`, beside P188).
  Classifies each open obligation at the WIRE UNLOCK as `NODRAIN` / `REDIRTY` /
  `INFLIGHT` / `UNCOPIED` by snapshotting the counters at drain exit.
  **Every occurrence measured reads `UNCOPIED` with `drain_ran=1
  drain_flushed=1`** — the drain returned success on an inode whose committed
  change was never staged into any outgoing image.  Consequence: a
  drain-to-zero wait CANNOT close this barrier, and `mxfs.pub_obligation_enforce`
  just re-runs a flush that P32E fences further down.  **That is the real reason
  sess20's re-arm livelocked** — retire "add a wait before unlock" as the fix
  shape for this site.
- **`P197-P6-PREMISE`** (at the P6-MIDTENURE-RELOAD-SKIP decision) + new field
  **`i_mxfs_dirty_ns`** (`xfs_inode.h`, stamped in `xfs_trans_log_inode`
  beside `i_mxfs_dirty_seq`).  Tests P6's "modified under the CURRENT EX
  tenure" claim against wall clock instead of a stamp comparison.
  **`premise=ok` in 60/60 and in both loss captures** (`dirty_age_ms=6
  tenure_age_ms=6`).  `i_mxfs_ex_grant_seq` IS correctly re-stamped —
  do NOT re-chase "the tenure stamp was carried over"; the staleness is about
  the EPOCH, not the tenure identity.

### REFUTED, kept at default 0: `mxfs.dir_ex_divert_on_demote`

Diverting a dir EX modify to the slow path while `i_dlm_demoter` is set made
things WORSE: P195 = 11 with it on vs 5 with it off (durable losses 0 in both).
The forced slow-path acquire takes longer, giving peers more time to advance
the dir epoch before we look.  So the demoter-active fast-path serve is NOT the
producer of P195.  Code and lever retained because the divert-gate comment is
the evidence for what the producer is not.  Do not re-enable without a
measurement that moves P195 DOWN.

---

## `i_dlm_demoter` is an OWNED, NESTABLE claim (sess25, ccloop c7ee71c6)

It used to be a bare `ip->i_dlm_demoter = current` / `= NULL` pair at every
release site.  That is a single non-nestable slot shared by
`mxfs_dlm_bast_work_fn`, `mxfs_dlm_bast_dwork_fn`, the P72 orphan reclaim and
the EDEADLK self-demote — and two of them running on one inode meant one
stored itself over the other's LIVE claim and then NULLed the slot on exit.
The stranded owner's trailing `xfs_irele` (last ref → `evict` →
`xfs_inactive` → `xfs_attr_inactive` → `xfs_ilock`) then lost the "demoter is
exempt (it must re-enter during its own drain)" exemption and parked in the
demote-wait **forever**.  Captured on 3 of 32 nodes at once.

**Always use the macros; never assign the field directly.**

- `MXFS_SET_DEMOTER(ip)` — `cmpxchg` claims only an unowned slot, or re-claims
  its own (`depth++`).  A foreign live claim is **never** overwritten; the
  refusal is reported by `P74-DEMOTER-CONTEST`.
- `MXFS_CLEAR_DEMOTER(ip)` — only the owner releases, and only the outermost
  nesting level clears.

`cmpxchg`, not `i_dlm_lock`: the call sites disagree about whether that
spinlock is held, so taking it inside the macro would deadlock some callers.

### Forensics

Every claim/clear/park is recorded in a per-inode ring
(`i_dlm_demev_*`, `MXFS_DEMEV_N`) and replayed by `P73-WAITSTALL` as
`P73-DEMEV[k] SET|CLEAR|WAIT|SET-REFUSED|CLEAR-NEST|CLEAR-REFUSED line= pid=
state= cookie=`.  That ring is what rooted the defect; a point-in-time
snapshot cannot, because NULL destroys exactly the information needed.

### `mxfs_dlm_bast_process` flushes TWICE — the two sites are not equivalent

`i_dlm_drain_site` records which one is active (printed by P47 as `dsite=`):

- **site 1** — the early page flush, `i_dlm_mode` still granted.  A colliding
  writeback submitter is nest-admitted, so this site cannot form the ABBA
  cycle.
- **site 2** — the `S_ISREG` durability flush, run **after**
  `ip->i_dlm_mode = MXFS_LOCK_NL` and before the wire unlock.  Every
  nest-admit fails here, so a submitter parks holding a folio and this flush
  blocks on it.  `wake_up_all(&ip->i_dlm_wait)` is issued before it so parked
  submitters re-evaluate the admit immediately rather than on the 3 s poll.

### Still open (structural)

Two release drains can still run concurrently on one inode (72
`P74-DEMOTER-CONTEST` in a single 32-node run).  The owned claim makes that
survivable, not impossible.  The structural fix is to hand the
potentially-final `xfs_irele` to a worker holding no DLM state, after the
release completes and state has left DEMOTING.  Note also that
`xfs_irele(ip)` followed by touching `ip` is a lifetime hazard in its own
right.

## ccloop c7ee71c6 sess26 — demoter claim (two slots) and its instrumentation

`i_dlm_demoter` + `i_dlm_demoter2` are the release-drain claim slots. Two
concurrent drains on ONE inode is normal (`bast_work_fn` vs `bast_dwork_fn`),
measured 30-152 times per 32-node run, so both get an owned, nestable slot;
neither can clear the other's.

**INVARIANT — `mxfs_foreign_demoter()` must self-exempt FIRST.** Any "is a
foreign drain active, should I defer?" test returns false when `current` owns
EITHER slot, before considering whether the other slot is occupied. Getting this
wrong (deferring while I am myself a drain) took cache_coherency to 0/32 with a
60 s timeout, strong_consistency to 25/32 and posix_multi to 1/32. See ccmemory
`demoter-predicate-self-exemption-invariant`.

`mxfs_is_demoter()` = "am I a drain?" (either slot).
`mxfs_foreign_demoter()` = "is a drain other than me live?"  Do not use one for
the other's question.

### Probes / levers added

| name | what it does |
|---|---|
| `mxfs.demoter_dump` | writes `P75-DEMOTER-CLAIM` + `P75-DEMOTER-LEGACY` + `P79-RACEBAIL` censuses to the log |
| `P76-DEMOTER-FOREIGN-CLEAR` | a non-owner clear, with both slot pids — distinguishes the benign initializer reset from a real collision |
| `P77-WEDGE-PRECOND` | a claim-theft victim reached the demote-wait (the wedge precondition) |
| `P78-UNCLAIM-INJECT` | TEST-ONLY `mxfs.bast_irele_unclaim_inject` fired; prints `i_count` and `state` |
| `P79-RACEBAIL` | race-bail total / resolved / unresolved + retry latency |
| `mxfs.demoter_legacy_clobber` | A/B: restores the pre-fix unqualified claim; counts its own exposure (`legacy_steal`, `legacy_clear_live`) |

Harness: `tests/demoter_claim_census.sh <n> [label]`.

**Choose the kernel-log source PER NODE; neither is reliably longer.** Measured
minutes apart on one build: test19 dmesg 1824 lines/112 s vs journalctl -k 59067;
test5 dmesg 95460 lines/1407 s vs journalctl -k 73686. A `dirent_durability` run
is 116-124 s, so on a heavy-logging node the dmesg window is shorter than the run
— but journalctl is shorter on quiet nodes. Take whichever still holds the last
`MXFS_DIRENT_WINDOW` marker and report `win_src=`.

### P6 mid-tenure reload skip — INVARIANT: never swallow a peer notification

`mxfs_dlm_reload_inode` has a branch that clears `i_dlm_stale` and returns
WITHOUT reloading when a directory was dirtied under the current EX tenure
(`P6-MIDTENURE-RELOAD-SKIP`). The premise is true; the inference "so the platter
has nothing to teach us" is FALSE when a peer published since.

`i_dlm_stale_src` records who set the staleness. Sources **2, 5, 7, 8 are all
peer-driven**, and at src=8 `MXFS_IF_DIR_RELOAD` has already been CLEARED before
the reload call — so skipping destroys the notification outright. Gated by
`mxfs.p6_honor_src_mask` (default `0x1A4`); `mxfs.p6_epoch_override` covers only
src==3 and cannot help here because losing windows show `epoch == entry_epoch`.

Instruments: `P81-P6-SRC` (per-src histogram + `repeat_ge8`/`repeat_max`), and
per-inode `i_dlm_p6skip_n` (consecutive skips with no real reload — the
staleness-livelock counter, reset by a real reload and at inode init).

**Two pitfalls, both paid for:**
- **Do NOT "fix" this by disabling the skip.** `mxfs.p6_midtenure_skip=0` keeps
  correctness but takes `dirent_durability` from 120s to a 240s/240s TIMEOUT.
  It is a hot path; narrow WHEN it applies instead.
- **One run does not exercise every source.** The first mask (0x104) covered only
  srcs 2 and 8; srcs 5 and 7 appeared only in a 3-run accumulation. Read the
  histogram across several runs before concluding a source set is complete.

## ccloop c7ee71c6 sess27 — INODE INCARNATION: generations are RANDOM (v0.11.234-237)

### THE INVARIANT (this is the load-bearing one)

**`di_gen` can NEVER order two incarnations of an inode number.** XFS assigns
`VFS_I(ip)->i_generation = get_random_u32()` for a new v3 inode
(`xfs_icache.c:1902`). So for any two images of the same inode number:
`a < b` means nothing, `a > b` means nothing, and `a == b` is only a
*probabilistic* identity check (2^-32 collision). Any guard whose premise is
"a lower generation means the disk is stale" is a coin flip on genuine reuse.

Two guards in `mxfs_dlm_reload_inode()` compare in-core vs on-disk images:
- `RELOAD-SIZE-DROP-SKIP` — already gated on `di_gen == incore_gen` (sess103).
- `RELOAD-TYPEFLIP-STALE-SKIP` — used `disk_gen <= incore_gen` until sess27.

### THE DEFECT AND FIX (D-DIRENT-INODE-TYPE-MISMATCH, RESOLVED)

When the coin came up wrong, the node **kept a DEAD incarnation** and its
release drain **PUBLISHED that corpse** over the peer's live inode — durable
namespace corruption agreed by all 32 nodes. Captured end to end for ino
10485888: created DIR gen ...535, freed (`freed_gen=...536`), reused as a
REGULAR FILE with new random gen ...492; a peer read that CORRECT image, logged
`RELOAD-TYPEFLIP-STALE-SKIP incore_mode=040755 disk_mode=0100644 expect_ft=0`,
and 2.5 s later republished the pre-free DIR image.

Fix: **`mxfs.typeflip_skip_same_incarn`** (default 1) requires
`disk_gen == incore_gen`. `0` = legacy `<=`, kept only as a negative control.

`expect_ftype == XFS_DIR3_FT_UNKNOWN` is the dangerous case: the sess96
dirent-agreement escape hatch cannot engage, so the gen comparison is the only
discriminator. Reloads from release/BAST paths always arrive that way.

### PITFALL — an exposure counter must be KNOB-INDEPENDENT

`P208-TYPEFLIP-REUSE` counts the dangerous subset (different incarnation, lower
random gen) and prints `action=keep|adopt`. The first cut gated it on the fix,
so the arm that REPRODUCES the corruption reported zero exposure and a passing
control could not be told apart from a control that never entered the state.
Always count exposure in both arms. This is what made the A/B interpretable:
the outcome tracks EXPOSURE, not the arm label (a control run with `P208=0`
passed; controls with 432 and 552 failed).

### PITFALL — do not read "disk" through the buffer cache to judge the cache

Every prior verdict here concluded "the DIRENT is the corrupt side" because it
compared in-core against a `disk_mode` read **through the buffer cache** — the
same path under suspicion — so both sides agreed circularly. `P207-COHERENT-TRUTH`
reads the platter with a **plain bio** (`mxfs_dbg_disk_di_mode_coherent()`,
`xfs_mxfs_dlm.c ~30081`) and showed the platter itself holding the pre-free
image. The decisive fact is the generation: **a live inode can never carry a
generation older than its own free.**

### STILL OPEN — publication without write authority (D-INODE-CLUSTER-...)

The equality gate stops this node from RETAINING a corpse; it does not
establish authority to publish. The physical write unit is the **16KB inode
CLUSTER** (`P170-CLWR` prints 21+ `ino:mode:gen` triples per write) while
locking is per-INODE, so one slot's write republishes whatever is cached for
every neighbouring slot. `P56-CORESIDENT-DIR-SKIP` already masks un-logged
DIRECTORY slots — precedent, and evidence the general case is unguarded.

### DEAD CODE FOUND — `mxfs.create_baseline_trackers` has never executed

The sess21 block in `mxfs_dlm_grant_local_new()` (`xfs_mxfs_dlm.c ~27477`) is
gated on `S_ISDIR(VFS_I(ip)->i_mode)`, but its only caller is
`xfs_iget_cache_miss()` under `XFS_IGET_CREATE` (`xfs_icache.c:1885`), where the
inode was just allocated and **`i_mode` is still 0** — the mode is set later by
`xfs_init_new_inode`. Probe `P209-CREATE-BASELINE` placed inside the block read
**0 on every node**. Even if reached, its `if (bgg)`/`if (bep)` guards read DLM
values for an inode created *without* a real acquire (deferred publish), so both
are 0 anyway. Treat the knob as inert; its sess21 A/B compared identical code.


---

## sess28 (ccloop c7ee71c6) — cross-incarnation epoch compare, and a readdir pace defect

### `mxfs_dir_epoch_superseded()` is now THE dir-epoch staleness predicate

Declared in `xfs_mxfs_dlm.h`, defined in `xfs_mxfs_dlm.c` next to
`mxfs_dir_epoch_incarn_gate`. **Both** consumers must go through it:

| consumer | file | what it does with a true result |
|---|---|---|
| `P32E-DIREPOCH-FENCE` | `xfs_inode.c` (`xfs_iflush` path) | SKIPS the dir flush |
| `P194`/`P195` gate | `libxfs/xfs_dir2.c` (`xfs_dir_lookup`) | adopts, or reports P195 |

A raw `cur_ep > ip->i_dlm_dir_valid_epoch` anywhere else is a bug: the CAW
`dir_epoch` is keyed by RESOURCE (the inode number) and survives the inode being
freed and re-created, so the comparison spans incarnations.

The predicate: returns false when `i_dlm_unpublished` (no grant for this
incarnation at all); on an incarnation mismatch it **re-bases** the baseline onto
the live incarnation, but **only while `i_mxfs_self_created` holds** — which this
tree defines as "created by this node and no peer BAST has ever arrived", so no
peer update can be laundered. It may mutate `i_dlm_dir_valid_epoch`/`_incarn`,
under the same tenure protection its other write sites use (these fields are not
covered by `i_dlm_lock` anywhere).

### `i_mxfs_self_created` is RE-ARMED on a cache-hit create

`xfs_create`'s success path sets it every time, including a create that recycles
an in-core inode (`P128-REARM-UNPUB`). That is correct — a new incarnation — but
it means the flag says nothing about the *previous* incarnation's peer history.
Pair it with `i_dlm_dir_valid_incarn`, never read it alone as "no peer ever
touched this inode number".

### Where a fresh self-created directory actually publishes

Four sites clear `i_dlm_unpublished` with a real grant. Measured share at 2/caw
(P210 by site): **site 2** async publish worker ×19 (reused-create dirs only),
**site 3** `mxfs_dlm_publish_drain_loop` BAST-driven ×4, **site 4** the sess107
unpublished-modify backstop in `mxfs_dlm_ilock_begin` ×2. Site 1
(`mxfs_dlm_publish_inode`) ≈ 0 — `xfs_create`'s call was removed for cost.
`mxfs_dlm_inode_lock_routed`'s routed arm never applies to directories
(`mxfs_iclus_routed` is `S_ISREG`-only).

**Sleeping-mutex constraint, solved without a side table:** the grant-gen /
dir-epoch queries take `grant_meta_lock` (`dlm/dlm_caw.c:1120`). At the async
worker the stamp point is under `spin_lock(&mp->m_mxfs_unpub_lock)` — hoist the
QUERY above the spinlock (the EX grant is already held, so nothing can move) and
do only scalar stores inside it.

### readdir of a peer-created directory costs ~1.2 s (`D-READDIR-PEER-CACHED-DIR-PACE`)

Measured 32/caw: `stat` 4 ms/op, `open(O_DIRECTORY)` 45 ms/op, `rmdir` 120 ms/op,
**`opendir`+`getdents` 1240 ms/op** — against 4 ms/op for identical children the
reader created itself. Peer-side release is instantaneous (`P51-REL drain_ms=0`).
The reader shows ~3 reload attempts per directory dominated by
`P173-RELOAD-SELFREAD`: readdir holds `ILOCK_SHARED`, so `mxfs_dlm_reload_inode`
can never take the write side, bails without rebuilding **after** reading the
cluster buffer, and leaves `i_dlm_stale` set so the next access repeats it.
Harness `tests/shared_unlink_pace.sh`.

**ROOTED AND FIXED (same session).** `xfs/xfs_dir2_readdir.c:1005` retries the
reload **200 times with `msleep(1)`** — ~1.2 s — and it can *never* succeed on
this path, because `xfs_readdir` holds `ILOCK_SHARED` and the reload's write
acquire is blocked by that same task (the sess14 `P173-RELOAD-SELFREAD` bail).
The loop body even re-arms `i_dlm_stale` before each attempt.
`mxfs.readdir_reload_retry_selfread` (ships 0) skips the retry in exactly that
case; the loop's own documented exhaustion behaviour (consistent-stale, flag
left set, `MXFS_IF_DIR_RELOAD` armed) is preserved. Same-build A/B: **1210 ms →
5 ms per getdents, 242x**, correctness board green at 8 and 32 nodes.

**Do NOT widen the P173 spin** (sess14 measured that as a livelock) — the answer
is to *not retry* when the caller is the blocker.

**Method note for this file:** three measurements were refuted en route —
attributing a `rm -rf` batch wall to the unlink, using `exec 9<"$dir"` as an
open test (bash returns EISDIR on a directory), and suspecting the pre-readdir
loop at `pal/linux/xfs_file.c:1888` (its probe `P95D-READDIR-WAIT` is in the
module and fired zero times). Time each syscall separately, from a program that
actually performs it.


---

## sess29 — THE DEMOTER CLAIM THAT OUTLIVES ITS CRITICAL SECTION (root, fixed)

`i_dlm_demoter` / `i_dlm_demoter2` mean "a release drain is in progress; defer to
it". Every claim in the tree is SET and CLEARed inside one function (spans 6-75
lines) except **one**:

- `mxfs_inode_dlm_defer_bast` claims and appends to `tp->t_mxfs_inode_unlocks`;
- `mxfs_trans_drain_inode_unlocks` (from `xfs_trans_free`) clears — and has
  exactly one exit that skips the clear, the **P152-TRANSDRAIN-PUNT**, taken
  when the committing task still owns ILOCK-EXCL. It *deliberately retains* the
  claim so that task stays exempt across its post-commit `xfs_iunlock`.

**Nothing ever ended that retention.** The dwork that inherits the release finds
slot 1 held, lands in **slot 2**, and clears slot 2 only. `mxfs_foreign_demoter()`
then stays true for the life of the in-core inode: every reload pays
`mxfs.reload_demote_wait_ms` and abandons with `i_dlm_stale` set (224-354 bails
on ONE inode vs 1 on healthy nodes). Decisive counter: **`P215-DEFER set=2
clear=0 retain=2`** — on those nodes every deferral punted and the inline clear
never ran, so the retained path is the NORMAL path.

**Second propagation step:** the inode is freed *still claimed*;
`xfs_inode_alloc` → `alloc_inode_sb` → `kmem_cache_alloc_lru` does **not zero**
the object; and the initializer's `MXFS_CLEAR_DEMOTER` **refuses a non-owner
clear** — so the next inode on that memory is born stranded with a dead task's
stamps.

**Fix (0.11.251):** the retention is ended by its **owner** in
`mxfs_dlm_ilock_end` — the exact unlock it exists to cover, so no grace and no
foreign clear. `i_dlm_punt_n[2]` *counts* retained acquisitions (the claim
nests; one tp can defer the same inode twice, so both entries can punt — a bit
cannot express it). The sweep (`mxfs_demoter_punt_reclaim_check`, grace 5000 ms)
is a **net only**: an age-based foreign clear cannot *prove* abandonment,
because `xfs_iunlock` does `up_write` BEFORE `mxfs_dlm_ilock_end`. Plus
`mxfs_dlm_inode_final_release()` before `kmem_cache_free` and a forced clear at
init.

Also fixed two real **use-after-free reads** of `ip->i_dlm_demoter->pid` — both
slots are bare `task_struct *` held **without a reference** and dangle once the
holder exits. **Never dereference them; print the stamped scalars.** Slot 2 had
no stamps at all, which made `P34J` report slot 1's stale site for a slot-2
strand — a probe for an OR-predicate must name which disjunct is true.

Harnesses: `tests/demoter_strand_census.sh`, `tests/demoter_punt_ab.sh`.

## sess29 — INODE-CLUSTER WRITE AUTHORITY: where the gap is

The physical write unit is the whole 16 KB inode **cluster**; the coherency
protocol locks per **inode**. In `pal/linux/xfs_buf.c`'s per-slot masking loop,
FREE and NL slots are skipped and a DIRECTORY slot is never written unless
logged this round (P56-CORESIDENT-DIR-SKIP) — but the branch commented
**"held non-dir inode -> write it"** writes unconditionally from the cached
buffer. Detector `P218-CLUSTER-*` (0.11.253) measured, over one board-equivalent
workload at 32 nodes: `unlogged_written=73097` (denominator),
**`no_write_tenure=2970`**, `gen_mismatch=33`, **`no_incore=68277`**.

⚠ **`ip` CAN BE NULL in that branch** — `is_nl` is `(ip && ...)`, so
`!is_free && !is_nl` admits `ip == NULL`. Dereferencing it there is a NULL deref
in the writeback path; it killed one node per run for three runs and presented
as `cache_coherency 0/32 NO_TERMINAL_RECORD` plus a next-boot mount hang with
`reservation conflict`, i.e. it looked exactly like a storage fault.

## sess32 (session 14, 0.11.272-280) — recovery gates + release-barrier enforcement
- **Foreign/adopted replay gates** (`xfs_log_recover.c`, `xfs_inode_item_recover.c`,
  `xfs_log_priv.h`): `xlog_is_mxfs_untrusted_replay()` = FOREIGN_REPLAY || new
  ADOPTED_SLICE (bit 6, set in `xfs_log_mount` when `mp->m_mxfs_slice_adopted`).
  Untrusted replay: intents skipped (P226), untagged buf/dquot/quotaoff/icreate
  images skipped (P223), inode records di_changecount-gated. Knobs
  `mxfs.foreign_replay_untagged_apply` / `mxfs.adopted_slice_full_replay`
  (both 0 = safe default). Defect: D-FOREIGN-REPLAY-UNGATED-IMAGES.
- **Release-barrier ledger + enforcement** (`xfs_mxfs_dlm.c` ~12850-12990 +
  anchored unlock tail ~16570-16800): `pending!=durable` now counted at both
  unlock tails (`obligation`) and every epoch bump (`epoch_obligation`), typed
  prints P220-{UNLOCK,EPOCH}-LEDGER-OPEN. `mxfs.relbar_enforce` (default 1,
  0.11.280): open ledger at the anchored unlock → ≤2 durable passes
  (`__mxfs_dlm_dir_inode_durable`/`mxfs_inode_cluster_durable`) else DEFER via
  the LIVE-SKIP -ESTALE requeue (P228-RELBAR-DEFER). NOTE the wrapper scope
  brace `}	/* sess32 rb_defer scope */` before the p15h_reap epilogue.
  noanchor arm NOT yet enforced; admission interlock + dir-DATA certificate
  pending (see ccmemory sess32 RELBAR notes).
- **Stale-stage mask default-ON** (0.11.272, `stale_stage_skip=1`); unlanded
  arm fails closed (P224 + shutdown, `stale_stage_unlanded_shutdown=1`). P222
  print now carries stage_mode/ili_f/ili_lf/pend/dur.

## sess37 (ccloop c7ee71c6, 2026-08-01, 0.11.313-317) delta

### xfs_mxfs_dlm.c
- **Bast-arm gate (313, D-DWORK-TEARDOWN-LASTREF class fix)**: static
  `mxfs_bast_arm_queue{,_delayed}()` wrappers — ALL 25 per-inode bast work/dwork
  queue sites route through them; refuse under mp->m_mxfs_arms_off (set at
  put_super under m_mxfs_arm_lock); queued-false = caller drops the arm's igrab
  ref (existing contract). P6S-ARM-REFUSED.
- **mxfs_dlm_evict retention (316)**: clean PR grant + nlink>0 + not unmounting/
  shutdown + mxfs_evict_retain_pr ⇒ NO wire unlock at evict (P6R-RETAIN); peer
  demand releases via noino BAST path; free boundary safe (free needs EX). EX
  never retained. Killed the 32-way barrier-aligned dc unlock CAS storm.
- P6G strand site: rel_stale_inject knob (311) forces teardown-era strand verdict
  (never fires in practice — post-withdraw drains abort first; kept for A/B).
- bast_process entry bail (13365 family) means P6G region reachable only in
  shutdown-set-not-yet-unmounting window.

### xfs_bmap_util.c (317)
- `xfs_can_free_eofblocks` tail peek now takes raw `down_read_nested(&ip->i_lock)`
  (NOT xfs_ilock) — in-core-only answer; via xfs_ilock it paid a full DLM wire
  acquire per EVICTED inode (reclaim calls it for every inode).

### xfs_stubs.c (312)
- `xfs_file_ioctl` stub now implements exactly XFS_IOC_GOINGDOWN (0x8004587d):
  capable+get_user+xfs_fs_goingdown. Everything else stays ENOTTY by design.
  xfs_io -x shutdown NEVER worked on mxfs (FSGEOMETRY probe ENOTTY) — use
  tests/mxfs_shutdown.sh. GOINGDOWN → P-WITHDRAW voluntary death.

### xfs_mount.h (313)
- New: spinlock_t m_mxfs_arm_lock; bool m_mxfs_arms_off (bast-arm gate).

## sess38 (0.11.319-320) — CREATEINT resolution
- xfs_inode.c: `mxfs_createint_dir_armed(ip)` (exported; declared xfs_inode.h
  near the CREATEINT define) = knob+dlm+S_ISDIR gate + registry consult; the
  ONE consult for every lock-mode computation in the armed window.
  xfs_ilock_data_map_shared: consult once, tag AFTER base mode final (leak B).
  mxfs_ilock_map_recheck: new_mode preserves PRIREAD|CREATEINT (leak C).
  xfs_mxfs_dlm.c consumer_refresh: SHARED|CREATEINT when armed, one mode var
  both lock+unlock (leak A). Probes P-CI-A/B/C + P-CI-ARM (cached_dlm_mode at
  arm — discriminates pre-arm cached PR from in-window leaks).
- VERDICT (same-build A/B 32/caw dir_reuse): mechanism correct (rc=-35
  create-path 0 on instr nodes) but NET PACE LOSS (6 vs 7 rounds) — serializes
  refresh+evict+FUA-reread inside dir-EX while the EDEADLK self-demote it
  avoids is already drain-free (dir_pr_release_fast=1). create_intent_ex
  DEFAULT 0 since 0.11.320 (pal/linux/xfs_aops.c).
- NEW DEFECT D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN: runtime
  xfs_iunlink_reload_next (xfs_inode.c:4906) on a peer's in-flight unlinked
  inode; droplink rc=-117 → dirty xfs_trans_cancel in xfs_remove → shutdown.
  Hypothesis: shared AGI bucket's in-core linkage (i_prev_unlinked etc.)
  survives AG-DLM handoffs → stale stitching. Evidence tests/logs/sess38_shutdown_g10/.

## sess45 (ccloop c7ee71c6, 2026-08-02, 0.11.361-362) delta

- **P195 Option B — adopt at EX acquire (0.11.361, D-DIRENT-PUBLISH-STALE-BASE
  CLOSED)**: new `i_dlm_base_valid` bit (xfs_inode.h) publishing the
  (valid_epoch, cached_grant_gen) baseline via `mxfs_dir_base_stamp`
  (WRITE_ONCE pair + smp_store_release) / `mxfs_dir_base_invalidate`.
  Knob `mxfs.dir_adopt_at_acquire=1`. Fast-path gate in `mxfs_dlm_ilock_begin`
  (S_ISDIR/EX block): sentinel(!valid) + epoch-!= legs arm the standard
  reload pipeline (dir_ex_stale_refresh + dir_ex_handoff); gen movement is
  COUNT-ONLY (sess63 resurrection evidence). Stamp ONLY at the reload
  install-complete point with PRE-read epoch/gen; invalidation at
  bast_process release drain (pre wire-unlock), reload commit point,
  phantom-EX bail, inode init + BOTH create-reuse funnels
  (reset_inode_for_create / rearm_unpublished — these never reset the sess28
  baseline quadruple before; knob-gated resets added). Creator publish stamp
  SUBORDINATED (P210 state=2). Counters: P216-B-STATS in the P6-DIRPATH dump.
  Verified: boards green 32+8, 24 aged dirent_publish loops (predicted ~3
  hits, got 0), sf_mkdir_storm 60r/32n clean, ONE arm fleet-wide during the
  storm (backward-epoch reset — the != contract case), no pace regression.
- **Six missing-braces bugs fixed** (valid_incarn stamped unconditionally,
  flipping "no baseline" into "live baseline of 0"): xfs_mxfs_dlm.c evict
  syncs ×2 + old reload commit stamp; xfs_da_btree.c:3801;
  xfs_dir2_data.c:2238; xfs_dir2_node.c:2090; xfs_dir2_leaf.c:1200.
- **NEW CRITICAL D-RSYNC-RENAME-DIRTY-CANCEL-MASS-SHUTDOWN-361**: 17/32
  independent `xfs_trans_cancel(DIRTY)` in xfs_rename under rsync_paired
  (known stale-base dirent-erasure family; the pre-dirty revalidate guarded
  src always but target only for RENAME_EXCHANGE — rsync's temp→existing-
  final replace path was unguarded). 0.11.362 containment (GPT-ruled):
  P217-RENAME-TGT-PREFLIGHT full target-expectation check (both polarities,
  strictly pre-dirty, WARN_ON_ONCE) returning **-ESTALE** → do_renameat2
  retry_estale re-walks + retries (vanished target degrades to a successful
  plain rename); P217-RENAME-DIRTYCANCEL probe at out_trans_cancel (errno,
  dirty bit, pre/post src-dir image cookie); `mxfs.reload_stamp_at_commit`
  micro-revert lever (pre-sess45 stamp timing) for the amplifier A/B.
- **run.sh**: NO_TERMINAL kill sweep now captures each node's last
  `mxfs-CCph` kmsg marker → `last_phase_census[...]` appended to the reason
  (node stdout tails are lost to ssh buffering; kmsg is not).
- **Dispositions today**: D-CACHE-COHERENCY-UV-COUNT-MISS-2332 DISPROVED
  (one degraded member reproduces rank1's uv exp=128 got=124 exactly —
  faildist[1x1,343x1]; healthy fleet 23×/11× green same day).
- **Hostload confounder reconfirmed**: external game-server burst (load 55)
  produced an all-32 NO_TERMINAL cascade lap; hostload stamp is the
  discriminator (real events today were at 19-27).

## sess46 (ccloop c7ee71c6, 2026-08-02, 0.11.363-369) delta

- **Routed open-unlink protection** (D-INODE-CLUSTER-PUBLISH item 1 / D-CROSSNODE-OPEN-UNLINK CAW arm):
  iclus+open_tracking coexistence implemented per GPT C9-ordering. Key surfaces:
  `mxfs_iclus_disk_release` (xfs_mxfs_dlm.c, THE cluster-release choke point: normal/bast_notify/
  selfclear all gate on `mxfs_iclus_publish_open_bits`), `mxfs_iclus_open_admit` (+ slow-path
  same-mode conversion in `mxfs_dlm_open_protect`, probe P95-OPEN-CLUSTER-CONVERT),
  `mxfs_dlm_caw_open_set/open_probe` (dlm_caw.c; dup-merge `caw_open_set_dedup`; probe classes:
  found/authoritative-absent/defer), `i_mxfs_open_setting` (xfs_inode.h). Matrix 9/9 ×2.
- **Publication ownership rule**: for any inode where `mxfs_dlm_iclus_covered(ip)` (CONFIG predicate,
  not the sticky bit) — P90/per-inode publish is EXCLUDED; the sweep owns bits. Fresh creates sit on
  mode-0-era per-inode LOCAL grants until their next acquire (sticky lands then); FIVE defects in
  sess46 all traced to machinery gating on the sticky bit or ignoring local grants:
  covered_active + fan_out now count/arm covered-REG local grants (dirs excluded — dir-131 EDEADLK
  family), and the -EDEADLK selfclear skips the acquiring ino (else its own ILOCKed grant starves
  the escape → 0x8 shutdown under host-load bursts; seen test7/29 @368, fixed 369).
- **P95-OPEN-STALE-INCARNATION** (all configs): open whose ilock-ride adopted a peer-freed image
  (P116) now -ESTALEs (VFS re-walk → ENOENT) instead of serving the tombstone ('' reads).
- **caw_repair_slot preserved-fields hazard**: repair was WIPING open_holders (memset + selective
  restore). Any new slot field that must survive repair needs an explicit restore line there.
- Verification pending at session end: 369 knob=1 full board, knob=0 regression board, soak.
- sess46 tail (0.11.373): NEW OPEN D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372 (ship config, fresh fs,
  xfs_ifree -117 → 0x1 shutdown on test2 during matrix; 3 repro attempts clean; ledger has protocol).
  P-DIFREE-CORRUPT probe family now covers EVERY -EFSCORRUPTED exit under xfs_difree (finobt-getrec
  added).  On ANY node shutdown: `dmesg > /root/<tag>.dmesg` on that node BEFORE re-prep — module
  reload clears the ring (test2's -117 forensics were lost this way).

## sess47 (0.11.374-377) — reap-ifree fix + iunlink probes
- **mxfs_ifree_unlinked_preflight** (xfs/xfs_inode.c, before xfs_inactive_ifree's
  xfs_ifree): when xfs_inode_unlinked_incomplete (reap-after-reclaim zombie),
  walks the recorded slot bucket (raw rcu radix probes — RECLAIMABLE shells are
  legit hops), rebuilds i_prev_unlinked, and PINS the predecessor via
  mxfs_iunlink_pin_member (igrab if VFS-live; xfs_iget recycle if reclaimable;
  -EAGAIN if mid-evict — waiting would ABBA through the held AG DLM). Any
  failure = clean-cancel skip (zombie durable, reap retries). Pin released
  AFTER AG DLM drop. Closed D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372.
- xfs/libxfs/xfs_inode_util.c xfs_iunlink_remove_inode: every exit now
  self-names (P-UNLREM-INCOMPLETE at entry when prev==0, P-UNLREM-NOPREV at
  the previously-silent mid-list -EFSCORRUPTED, -LOGSELF, -BACKREF).
- xfs/libxfs/xfs_ag.h: new pag_mxfs_inocl_wr_epoch (inode-cluster sibling of
  pag_mxfs_meta_wr_epoch; mxfs_agmeta_ops still deliberately excludes
  clusters).
- Deterministic repro: tests/reap_midlist_repro.sh (scenario A reclaimed-chain,
  scenario B igrab/local-fd-live predecessor).
- Reap worker context (xfs_mxfs_dlm.c:31240): restores bucket+authority flag
  but the inactive-side DLM EX acquire STRIPS the authority flag again —
  anything keying on LOCAL_UNLINK post-restore must use i_unlinked_bucket
  (survives) instead.

## sess48 — A-prime iunlink store v4/v5 + the two proven fossil roots (0.11.387-394)

- **Mount-level iunlink store** (`xfs/xfs_mxfs_dlm.c` ~31400-31700, struct
  `mxfs_iunl_rec`): (ino, gen, committed next_agino, daddr, boffset, agno,
  wr_epoch).  Record at iunlink-item precommit (`xfs_iunlink_item.c`
  success path only); overlay at FIVE sites (cold fill + reverify +
  coherent reread in pal/linux/xfs_buf.c; WRITE submission pre-verify_write
  = site 4; post-merge in mxfs_iflush_cluster_merge_dirs = site 5); retire
  is PAYLOAD-VERIFIED at write completion (stamp wr_epoch only if the
  completed image carried the value; different-gen slot also stamps);
  records are AG-TENURE-SCOPED — `mxfs_iunl_store_purge_ag` before all
  four `mxfs_v5_dlm_ag_unlock` sites (GPT ruling: (ino,gen) is unsound
  cross-tenure; nu has no ordering).  Overlay refuses on live-inode skew
  (P-IUNLSTORE-LIVESKEW; icache radix peek — coherent because every nu
  writer and overlay site holds the cluster buffer lock).  Telemetry:
  OVERLAY/WRSITE/FOSSILWR/GENSKEW/RELLEAK/AGPURGE/LIVESKEW/QUERY +
  P-IUNL-DISCRIM (plain-vs-FUA A/B read; FUA leg off under fua_disable).
- **Root #1 (fixed 391)**: mxfs_iflush_cluster_merge_dirs's bli_dirty
  save/restore of di_next_unlinked reverted checkpointed iunlink writes
  in-core (BLI detach ⇒ restore skipped ⇒ platter fossil installed ⇒
  xfsaild destaged it).  Restore removed (it also skipped CRC recompute —
  nu IS in the di_crc region — and could revert foreign slots); site 5
  overlay replaces it.
- **Root #2 (fixed 394)**: fossil nu SURVIVES INODE REUSE — iflush stamps
  the new di_gen but never writes nu, so a lost remove's dead chain value
  rides under a current gen, blinding all gen-keyed defenses.  Fix:
  P-CREATE-NUFIX in `libxfs/xfs_inode_util.c xfs_inode_init` (multi-node):
  a just-allocated ino provably has nu==NULLAGINO; clear+CRC+4-byte
  buffer log in the create transaction when the platter disagrees.
- **P53 diagnostics**: `xfs_iunlink_item.c` P53 block now calls
  `mxfs_iunl_store_query_print` — every fatal names the record state.
- Soak tooling: `tests/iunl_soak_sweep.sh <mark>` (per-cycle dmesg
  markers via /dev/kmsg; dmesg persists across preps — never raw-grep).

### 0.11.427 — authority token v2 (foreign-replay step 5.2)

The buffer-log authority trailer is now **40 bytes, version 2**
(`struct mxfs_blf_authority_v2`, `xfs/libxfs/xfs_log_format.h`).  v1 (24B) is
still parsed — an upgraded node may replay a log written by a v1 node — but
**v1 normalizes to status UNSET and must never gate an apply/skip decision.**

New fields over v1: `be64 mba_resource` (wide enough to name an inode, not
just an agno), `be64 mba_owner_epoch` (the EMITTING MOUNT'S INCARNATION —
impossible before D-MOUNT-INCARNATION-CONSTANT-ZERO closed in sess91),
`be32 mba_owner_node`, and `be32 mba_flags` whose low 8 bits are an explicit
**status** (VALID / NOT_REQUIRED / UNPROVEN / MISLABELLED / MIXED /
INCOMPLETE / WRITE_AUTH / UNSUPPORTED).  Bits 8-31 are reserved and MUST BE
ZERO — that is what lets a later wire addition be *rejected* by an older
enforcing node instead of silently misread.

**THE SIZE-MACRO TRAP.**  Trailer presence must be size-stable or the CIL
shadow buffer overruns (silent corruption).  ONE macro, `MXFS_BLF_AUTHORITY_SIZE`,
is used on both the size-estimate side (`xfs_buf_item_size_segment`) and the
emission side (`xfs_buf_item_format_segment`).  Never add a second emit-size
macro, and **never use that macro to size a PARSE** — the parser meets both
versions and must size from the version field it read
(`mxfs_blf_authority_size(version)`).

`mxfs_blf_parse_authority()` returns `enum mxfs_auth_parse`
(NOT_BUF / UNTAGGED / MALFORMED / OK) and fills a normalized
`struct mxfs_auth_view`.  The old pointer-or-NULL conflated untagged,
malformed and not-a-buffer, so report-only mode could not measure any of them.

**Identity capture is all-or-nothing and DOMINATES classification.**
`mxfs_v5_dlm_mount_identity()` → `mxfs_disklock_mount_identity()` returns
{slot, node_id, incarnation} or false with all three zeroed.  On failure the
token is forced to class NONE / status INCOMPLETE with identity zeroed: a
record that cannot be bound to an emitting incarnation must not carry a class
that looks like proof.  Do NOT read `ctx->node_slot` instead — it is 0 in a
fresh context and 0 is also a valid claimed slot (the MDS); the disklock's
`local_slot` is -1 until claimed and therefore can tell them apart.

Rig-verified through a real node death (32/caw, victim test9): every replayed
token `v=2`, `oepoch` a real nonzero incarnation, `slot` matching the dead
slot the replayer independently named, `malformed=0`, and the status field
discriminating VALID from MISLABELLED.  Producer-side `P228-TOKCLASS
incomplete=0` over 16384 tokens.

**Still report-only.**  The ATOMIC-SKIP taint scan and the P223 gate are
byte-identical so the `foreign_replay_ab.sh` arms stay comparable.
Enforcement is step 5.4, and proto_gen is deliberately unbumped until then.

## Publication obligation: pending / durable / the fenced-flush chokepoint (sess382)

The per-inode publication obligation is `i_mxfs_pub_pending_seq !=
i_mxfs_pub_durable_seq`. `pending` increments in `xfs_trans_log_inode`
(`libxfs/xfs_trans_inode.c`); `flush_seq` is stamped at the copy-in inside
`xfs_iflush`; `durable` is promoted from `flush_seq` at `xfs_iflush_finish`
(`xfs_inode_item.c`). An open obligation blocks the DLM release.

**The trap.** `xfs_iflush` has **eleven** "safe skip" fences that return
`error = 0; goto flush_out;` *without* reaching the `flush_seq` stamp —
P119-NONEX-FLUSH-SKIP, P17B-EPOCH-GHOST-SKIP, P25-RESURRECT-SKIP,
P32F-NXSHRINK-FENCE, P32D-DEADINCARN-SKIP, P32E-DIREPOCH-FENCE,
P67-IFLUSH-OWNER-FENCE, P65-IFLUSH-FENCE, P14-SFSIZE-DESYNC,
P32-IFLUSH-NXSHRINK, plus the P189 arm in the release drain itself. Each says
"reload on next acquire" and sets `i_dlm_stale`. **Any new fence you add here
must go through the same chokepoint**, or it will leave an obligation nothing
can close.

**The chokepoint** is at the `flush_out` label: returning success without having
stamped `flush_seq` while an obligation is open sets `i_mxfs_pub_fenced`. That
flag is the ONLY signal the release path has that a flush was fenced rather than
landed. Consumed by `mxfs_dlm_bast_dwork_fn`, cleared when the obligation
resolves.

**Two invariants that cost a mount when broken:**
1. `i_dlm_stale` is honored only by **access** paths (`xfs_iget`/lookup,
   readdir). Before sess382 it had no release-path consumer at all, so an
   abandoned publication was reconciled only if a local reader happened to touch
   the inode inside the 60 s no-progress bound — otherwise `mxfs_inode_wedge`
   pinned the grant and force-shut-down the whole mount.
2. The drain's own re-log (P146V-UNLANDED) must NOT create a new obligation.
   It re-logs the same core purely to get it flushed; `i_mxfs_pipe_relog` marks
   that caller and suppresses the `pending_seq` bump. Counting it made the
   obligation uncloseable (measured: pending 6 → 730 with flush frozen at 6).

### The unlink publication obligation (PUBOB) and the durability gate (sess387-389)

`MXFS_IF_PUBOB` is armed by this node's own `xfs_iunlink` insert
(`libxfs/xfs_inode_util.c`, `mxfs_pubob_arm`, per-mount list) and means "the
home dinode owes a nlink=0 conversion before any AG release publishes the
list".  It is discharged on a confirmed home write (`MXFS_IF_PUBOB_FLUSHED` set
at copy-in, `mxfs_pubob_discharge` in `xfs_iflush_finish`), on list removal
(`P82-REM`), lazily by the AG-release audit when the home already reads
nlink=0, or cancelled (`P177-PUBOB-SUPERSEDED`) when a reload adopts a
DIFFERENT incarnation.  Reclaim refuses a PUBOB inode (`P88-PUBOB-RECLAIM-
REFUSED`): the shell is the only repair authority.

**The sess389 chain (one measured root, three launderings), all fixed in 0.19.40:**
1. `xfs_iflush` P119 discarded a committed conversion on a **PR**-held inode
   (an unlink can commit at PR after a mid-drain re-acquire, `P15-REL-ABORT`).
   Fix F1: `P55B-PUBOB-PR-FLUSH` — owned PUBOB + nlink==0 + PR + same
   incarnation + live same-type slot + in AIL → `mxfs_cores_commit_flush=true`
   (WRITE under the P55 exclusion argument; P244 fences PR through completion).
   Never widen this to generic `pending != durable` (ruling).
2. `mxfs_iflush_agino_target` returned 0 on `xfs_inode_clean` (laundered item).
   Fix F2: clean+PUBOB → `mxfs_pubob_relog_core` (tr_ichange, `pipe_relog=1`,
   ILOCK EXCL nowait + deadline, raw un-take) → restart → flush; the helper
   self-sanctions (`MXFS_IF_DLM_RELFLUSH`) when PUBOB so the AG-release audit
   (inode at NL) is not laundered again; second clean sighting → `-ENOMSG`
   (`P245-CLEAN-MISMATCH`).  Probes `P245-RELOG`, `P245-RELOG-FAIL`.
3. `mxfs_dlm_reload_inode` discharged the ledger (durable=pending) even when it
   KEPT the in-core because it was AHEAD of the platter (P3-REFUSE-OLDER-DISK /
   P34F / P184).  Fix F3: `reload_kept_ahead` → no discharge
   (`P177-KEPT-AHEAD-OBLIGATION-OPEN`); `P-RELOAD-IDENTICAL` now also requires
   `di_nlink` equality.
4. The sess19 `MXFS_IF_LOCAL_UNLINK|ADOPTED_UNLINK` clear ran at reload ENTRY,
   so the sess382 reldefer reload of our own live unlink stripped freer
   authority and `xfs_inactive` B3 skipped the ifree (`torn-live-no-local-
   unlink`).  Fix F4: the clear runs only in the real-adopt branch (after
   `xfs_inode_from_disk`, `!reload_identical`).

Sweep: `tests/fleet_pubob_counters.sh N` (one dmesg pass per node).  Expected
zero: P88-PUBOB-UNREPAIRED, P87-PUBLISH-DEFER-EXHAUSTED, torn-live on local
unlinks, P88-RECLAIM-REFUSED, P-IUNL-LOGSAME, P245-CLEAN-MISMATCH.  Known
residual: P119 at NL on an unlinked inode still fires when the same node's
inactivation removes it ms later (harmless end state); the ifree FINAL
mode=0 write at NL is also skipped (freed-shell family, `P-CR63-SHELL`).

**Dir-epoch staleness:** every consumer must call `mxfs_dir_epoch_superseded()`,
never a raw `cur_ep > i_dlm_dir_valid_epoch` — the raw form compares a dead
incarnation's handoff lineage against a live incarnation's baseline. Sites:
`libxfs/xfs_dir2.c` (P194/P195 gate), and the P32F and P32E arms in
`xfs_inode.c`.

**Adding a field to `struct xfs_inode`:** `xfs_inode_alloc` uses
`kmem_cache_alloc`, **not** zalloc. Reset it in the explicit init block in
`xfs_mxfs_dlm.c` (near `i_mxfs_pub_pending_seq = 0`) or a recycled inode
inherits the previous incarnation's value.

## sess385 (2026-08-21, 0.19.17) — THE AG-RELEASE INODE PUBLICATION STAGE

Read this before touching `mxfs_dlm_ag_bast_work_fn` Phase 2 or either drain.

### The invariant that was missing

A peer never replays our journal; it reads only HOME BLOCKS. So
`xfs_log_force(SYNC)` publishes nothing. **A log force is not an inode home-block
flush.**

The two halves of `xfs_iunlink` travel by different mechanisms:

| carried by | reaches medium via | covered before sess385? |
|---|---|---|
| `agi_unlinked[bucket]`, `di_next_unlinked` | buffer log item | yes — the drains |
| `di_nlink = 0` (from `xfs_droplink`) | **inode log item -> `xfs_iflush`** | **NO** |

`xfs_iflush` normally runs from xfsaild, asynchronously. Nothing in the AG
release path forced it, so we published an AGI whose unlinked bucket head
pointed at a dinode still reading LINKED. The acquirer's
`xfs_iunlink_reload_next` sees `i_nlink != 0`, returns `-EFSCORRUPTED` **inside
an already-dirty rename transaction**, and the fs shuts down. Measured: 11 of 65
published heads bad on an all-PASS lap; publisher and victim matched on one
incident (same AG, same agino, 3.2 s apart).

The generalisation, which is the thing to remember: **any field carried by the
inode log item is journal-only at AG unlock** — `di_mode`, uid/gid, `di_size`,
timestamps, `di_nblocks`, extent counts, flags, `di_gen`, `di_forkoff`, local
fork contents, embedded btree roots. Ordinary inode content is covered by the
per-inode DLM (`mxfs_ail_drain_inode_to` really does wait for the item to leave
the AIL). The AG DLM is different because the AGI unlinked list lets a peer
dereference an inode's home dinode **without ever taking that inode's DLM lock**.
That is why the AG release must publish those pointees.

### What Phase 2 does now

    log_force(SYNC); msleep(3); log_force(SYNC)
    drain_alloc_buflist                 <-- moved earlier
    drain_inode_buffers                 <-- moved earlier; now CONVERTS then writes
    blkdev_flush                        <-- barrier: pointees durable
    drain_meta_buffers                  <-- AGI (the pointer) only now
    blkdev_flush
    log_force(SYNC); drain_meta_buffers  (sess43 second pass)
    Phase 3 meta_pending wait; flush; unlock

Pointee before pointer. The old order wrote and flushed the AGI first.

### `drain_inode_buffers` — three traps, all paid for

1. It had none of the AG-META drain's hardenings: it skipped `_XBF_DELWRI_Q`
   (the v0.3.31 bug), skipped on failed trylock (the v0.3.27 bug), and had no
   pinned/BLI fallthrough. These bit harder here than for AG-meta, because the
   normal route a dinode takes to its cluster buffer IS xfsaild
   (`xfs_inode_item_push` -> `xfs_iflush` -> `xfs_buf_delwri_queue`) — so the
   skipped buffer was the COMMON case. Nothing else waited for it either:
   Phase 3 waits on `pag_dlm_meta_pending`, which counts **AG-META** buffers only.
2. **Do NOT copy the meta drain's write predicate.** For an AG-meta buffer
   `b_li_list` carries the buf log item, which iodone releases, so the predicate
   self-clears. For an INODE cluster buffer `b_li_list` carries the INODE log
   items, which **survive the write** — `xfs_trans_log_inode` attaches them at
   first dirty. Copying it made the predicate permanently true: the drain
   rewrote the same buffer every pass and hit the pass cap on 133 of 423
   releases (meta drain: 0). Correct predicate is
   `_XBF_DELWRI_Q || xfs_buf_ispinned(bp) || bp->b_log_item`, **re-evaluated
   under the buffer lock**. Fixing it took PASSCAP 141 -> 0 and writes 1095 -> 19.
3. That same `b_li_list` is why the conversion needs no radix-tree walk: it IS
   the set of inodes to convert. `xfs_iflush_cluster(bp)` is the non-blocking
   converter — `xfs_ilock_nowait(SHARED)`, skips what it cannot get, which keeps
   this out of the whole-AG `ail_push` deadlock that killed the two previous
   attempts (a sibling in the AG can be ILOCK-EXCL-held by a thread blocked
   behind this very worker). Skipped inodes are retried by the
   pass-until-quiescent loop. **On failure it has already unlocked AND released
   the buffer and shut the fs down — do not touch `bp` again and do not drop the
   reference; that path consumed it.**

`xfs_bwrite` already calls `xfs_force_shutdown(SHUTDOWN_META_IO_ERROR)` on write
failure, so switching off `xfs_buf_delwri_submit` bought the fail-closed property
for free: a write we cannot complete can no longer be followed by an unlock that
publishes stale metadata.

### Probes (leave them on)

- `mxfs.inode_drain_probe=1` -> `P85-INODE-DRAIN-CENSUS` (anomaly-only),
  `P85-INODE-DRAIN-WRITE-FAIL`, `P85-INODE-DRAIN-PASSCAP`.
- `mxfs.agi_publish_audit=1` -> `P86-AGI-UNLINKED-PUBLISH` (per bad head),
  `P86-AGI-PUBLISH-TOTALS` (<=1 per 30 s).
- `mxfs.publish_inodes` (default 1) A/B's the conversion stage itself.

Both were made anomaly-gated after a per-release line at 32 nodes deadlocked the
HOST — see `docs/history/clyde-ext4-jbd2-wedge-shared-lun-on-root-fs.md`.

### sess385 Part D — publication ENFORCEMENT at the unlock point (0.19.20)

`xfs_iflush_cluster` is non-blocking by design (`xfs_ilock_nowait`), which is
what keeps the conversion stage out of the whole-AG `ail_push` deadlock — but it
means an inode whose ILOCK is held elsewhere is simply skipped, and if it is
still skipped at the pass cap we would unlock and publish a split anyway.
Invariant 1 forbids that.

So `mxfs_p86_agi_unlinked_publish_audit()` (called immediately before
`mxfs_v5_dlm_ag_unlock`) is now **verify → repair → re-verify**:

- head's home dinode reads `nlink == 0` → `joint_ok`, done.
- reads LINKED **and** `radix_tree_lookup` finds it with `i_nlink == 0` → **SPLIT**:
  ours. Retry a targeted conversion for that one inode up to
  `mxfs.publish_retries` (default 3): `log_force(SYNC)` → `xfs_imap` →
  `xfs_buf_incore` (blocking, **INCORE-only**) → `xfs_iflush_cluster` →
  `xfs_bwrite` → `blkdev_flush` → re-FUA-read. Logs `P87-PUBLISH-REPAIRED`.
- reads LINKED and **not in our cache** → **BADHEAD**: we have no authority to
  repair it; most likely another node created that head. Report only.
- survives repair → `P86-AGI-UNLINKED-PUBLISH`, and with
  `mxfs.publish_refuse_unlock=1` a `SHUTDOWN_META_IO_ERROR` instead of the
  unlock. **That param defaults to 0** — shipping an unmeasured cluster-wide
  shutdown path would be a RULE 4 violation, and #474 shows the cost of an
  uncontained one. Measure the repair rate, then flip it.

**LOCK ORDER — the trap this created, caught in review before any rig run.**
The first cut ran the repair while still holding the AGI buffer locked. That
deadlocks: with `flags=0`, `xfs_imap` *still* falls through to `xfs_imap_lookup`
— an inobt btree read that reads the AGI — whenever `blocks_per_cluster > 1` and
`inoalign_mask == 0`; and `xfs_log_force` can drive an AIL push that wants the
AGI too. The audit now **snapshots all 64 bucket heads into a local array and
drops the AGI buffer before doing anything else.** Nothing can change the list
underneath it: we still hold the AG DLM EX and `pag_dlm_demoting` is set.

If you add anything to this audit, keep it outside the AGI buffer lock.

## sess386 (0.19.23-24) — dialloc reserve bound + AGI-skip hygiene + P87 repair probes

- `mxfs_dialloc_reserve_ino` (libxfs/xfs_ialloc.c): its CAW acquire is now
  genuinely bounded (retries×1s deadline via `mxfs_v5_dlm_inode_lock_retries`;
  the CAW branch previously ignored `retries` — measured 474 leg A: create held
  the AGI buffer across a minutes-long `caw_wait_for_grant`).
- `xfs_dialloc_try_ag`: `-EAGAIN` from `xfs_dialloc_ag` now exits via
  `out_release` (brelse AGI + immediate AG DLM unlock). It used to fall through
  to `mxfs_ag_dlm_unlock_deferred` and leak the LOCKED AGI + held AG grant into
  the rest of the create. A skipped AG modified nothing, so immediate release is
  the same contract as the `!pagi_freecount` skip.
- `xfs_dialloc`: after the partition-relaxed pass fails, up to 4 jittered
  re-sweeps (`P-DIALLOC-SWEEP-RETRY`, kernel-only) before returning -ENOSPC —
  transient cluster contention must not surface as ENOSPC.
- `mxfs_p87_publish_repair` (xfs_mxfs_dlm.c): every failure arm now logs
  `P87-REPAIR-FAIL arm=imap|noincore|nolist|iflush|bwrite|reread-linked`.
  Measured on 0.19.23: repair converts only ~1/3 of splits (tally SPLIT=2 of 3
  attempts at 584 heads) — the arm data decides the next fix.

## sess390 (ccloop c7ee71c6, 2026-08-22, 0.20.1-0.20.2) — noino fence is CONVOY-AWARE; nonblock AG acquire never parks in the demote window

Two roots measured at the 25-AG geometry (7 node slots sharing home AGs; rig LUN
normally 64 AGs), both fixes apply at every geometry.

### The no-inode release fence and intent items (`mxfs_noino_drain_fence`, xfs_mxfs_dlm.c ~21300)
- The fence pushes the WHOLE AIL to a snapshot target.  An EFI (XFS_LI_EFI =
  0x1236 = 4662 in P-AILMIN dumps) has no `iop_push`: xfsaild treats it PINNED
  and it leaves the AIL only when its EFD commits, which needs the AGF of each
  extent's AG — a per-AG CAW acquire.  A defer chain whose owner is blocked on a
  peer-held AG therefore freezes the fence's AIL min for the whole AG wait
  (13 s measured), while the truncating inode's own log item re-logs past the
  target on every `xfs_trans_roll`.  sess389's "relfence wedge at 25 AGs" was
  exactly this: 8 stalls × 2 s → `P-NOINO-DRAIN-STUCK` → shutdown.
- RULE-5 ruling (`docs/rulings/noino-fence-convoy-intents-lifecycle.md`):
  do NOT exempt intents (an un-done intent is unfinished work whose continuation
  commits after the target); instead attribute the freeze.  Landed 0.20.1:
  `pag_mxfs_agwait_inflight` / `pag_mxfs_agwait_since_ns` (xfs_ag.h) bracket the
  BLOCKING `mxfs_v5_dlm_ag_lock` in `__mxfs_ag_dlm_lock`; `mxfs_noino_freeze_is_convoy()`
  maps the frozen min (EFI → extent AGs, BUF → daddr AG, INODE → ino AG) to an
  in-flight local AG wait and such stalls are NOT charged against
  `MXFS_NOINO_STALL_TRIES` (probe `P-NOINO-CONVOY ino= try= min= item= ag= agwait_ms=
  frozen= chargeable=`); the `MXFS_NOINO_MAX_TRIES`=45 hard wall is unchanged and
  bounds everything.  `P-AILMIN` now prints `EFI nextents= ag0= agwait_inflight=`.
- INVARIANT kept: the fence still never unlocks undrained; it only stops calling a
  bounded convoy a wedge.
- STILL OPEN (ruling items): lifecycle routing — `xfs_iget(XFS_IGET_INCORE)` returns
  -EAGAIN for INEW/IRECLAIM/INACTIVATING (and -ENOENT for NEED_INACTIVE nlink==0),
  so a BAST for an inode mid-inactivation takes the noino path and can release the
  grant between the last EFD and `xfs_inactive_ifree`; and closing local
  re-adoption once a BAST is pending (the pace root under AG sharing).

### `__mxfs_ag_dlm_lock(nonblock=true)` must return -EAGAIN during the demote window (0.20.2)
- `mxfs_ag_dlm_wait_demote()` was called at entry BEFORE `nonblock` was honoured,
  so `mxfs_ag_dlm_trylock` from a defer chain PARKED while this AG was mid-demote.
  Stack-proven (test17): rsync's `iput` runs inactivation INLINE
  (`xfs_inode_mark_reclaimable → xfs_inactive → xfs_inactive_truncate →
  xfs_defer_finish → __xfs_free_extent → mxfs_ag_dlm_trylock → wait_demote`) holding
  ILOCK_EXCL on the just-unlinked inode; the demote's publication stage needed that
  ILOCK to land nlink=0 → `P87-TARGET-TIMEOUT stage=ilock ocomm=rsync` ×2/pass →
  `P86-AGI-UNLINKED-PUBLISH` split published under protest; peer waited 11.4 s.
- Now: `if (nonblock && pag->pag_dlm_demoting) return -EAGAIN` (`P-AGTRY-DEMOTING`,
  stat `trydemote=` in the DLM cache line), so the existing -488 seam
  (`P271-AGWANT` in `__xfs_free_extent`) relogs the intent, rolls, drops the ILOCKs
  and blocks holding nothing.  All five trylock call sites already treat -EAGAIN as
  "peer-held".  Same shape as the sess388 `P-AGTRY-LOCALBUSY` fix — the rule is:
  **a nonblock AG acquire never sleeps, for any reason.**
- Measured 0.20.2 @25 AGs, 3 laps: 0 wedge, 0 shutdown, 0 split, 0 P87 ilock
  timeout, 0 dirty-cancel (0.20.1: 24 splits / 48 timeouts in 3 laps).  Pace at
  25 AGs remains a defect (PACE-388: rsync lap 2-3 > 60 s).

### 0.21.x (sess390) — noino lifecycle classes; the AG re-adoption gate (inert) and why
- `xfs_icache_ino_lifecycle()` (xfs_icache.c/.h): reference-free in-core state probe
  (rcu + radix + i_flags_lock + ino re-check): ABSENT / LIVE / RECLAIMABLE / INEW /
  IRECLAIM / INACTIVATING / NEED_INACTIVE / VFS_TEARDOWN.  `__mxfs_dlm_bast_notify`
  consults it when `xfs_iget(XFS_IGET_INCORE)` fails with anything but -ENODATA; with
  `mxfs.noino_lifecycle_requeue=1` (default) an INEW/IRECLAIM/INACTIVATING/
  NEED_INACTIVE/VFS_TEARDOWN inode parks the BAST in a 20 ms delayed work
  (`mxfs_noino_lc_work_fn`, per-ino dedup hash, `noino_lifecycle_max_ms` wall,
  `P-NOINO-LIFECYCLE{,-DONE,-TIMEOUT}`) instead of running the whole-AIL fence
  against a grant a local lifecycle op still uses; RECLAIMABLE/ABSENT fence as
  before.  Measured: RECLAIMABLE dominates (7091/lap), active classes ~0.
- `__mxfs_ag_dlm_lock(mp, pag, nonblock, demand, resfree)`: the cached fast path
  has a knob-gated admission gate (`mxfs.ag_readopt_window_ms`, default -1 = OFF).
  Both attempts to arm it failed at 25 AGs (`docs/history/readopt-close-two-failures-latch-design.md`): blocking
  waiters wedged ILOCK holders; pinned re-adoption livelocked/starved peers.  The
  re-adoption storm is the UNLOCK-side race (P12-ULBP schedules the worker async; a
  re-adopter wins 0→1 first) — the next design latches the handoff at the last-
  holder unlock and brackets `mxfs_ag_dlm_wait_demote` as an AG wait.
  `mxfs_ag_dlm_lock_resfree()` = RESOURCE_FREE class (pregrant, P271 seam: hold
  nothing, may wait for a handoff).  RULE: a nonblock AG acquire never sleeps;
  a blocking acquirer that may hold ILOCKs never waits at an admission gate.

## sess392 (2026-08-22, 0.22.0-0.23.1) — handoff latch landed; dialloc try-reserve; 25-AG pace met

### The AG handoff latch (0.22.0-0.22.4, xfs_mxfs_dlm.c)
- `mxfs_ag_handoff_commit()` — at the LAST-HOLDER UNLOCK (ULBP branch of
  `mxfs_ag_dlm_unlock`) with a BAST pending past the quantum, the unlock itself
  commits the handoff under `pag_dlm_lock` (cached=false, demoting=true) and
  queues the worker via `mxfs_ag_bast_queue()`; no 0→1 re-adoption can win the
  race any more (`P12-LATCH by=unlock`, `LATCHED-ENTER`, `LATCHED-PHASE2`).
  Blocking acquirers park in `mxfs_ag_dlm_wait_demote` (bracketed as an AG wait
  for the convoy-aware fence); nonblock get -EAGAIN.
- TRAPS paid for this session, all in `pag` handoff state:
  1. `bast_scheduled` must be cleared by `mxfs_ag_demote_clear()` (0.22.1):
     0.22.0 set it at commit and never cleared it, so every later BAST saw
     sched=1 and only the 30 s P275 watchdog requeued the worker.
  2. `bast_pending` must be cleared at RELEASED / deferred-release / iodone
     completions (0.22.2) — a BAST rx during a drain otherwise survives into
     the next tenure.
  3. `P12-STALE-HINT` (0.22.4): a multicast BAST hint recorded with NO tenure
     (rx_ns < acq_t0) is dropped at the fresh grant; otherwise the next tenure
     is "closing" at its first unlock → one-op tenures (fleet b2c sum 1037 s →
     60 s).
- Instrumentation: `P12-HANDOFF ag= b2c_ms= q= wq= r2e= e2a= a2c=` (rx→queued,
  queued→enter, rx→enter, enter→armed, armed→COMMIT); unratelimited
  `P12-HANDOFF-TAIL` when b2c>1000 ms; the `handoff:` block in the DLM stats
  line (`b2c_gt500`, `latch_unlock`, `postlatch_adopt` — target 0, `stale_hint`).

### dialloc try-reserve + candidate rotation (0.23.0, xfs_ialloc.c + dlm/v5_mount.c)
Proven lap-2 root at 25 AGs: `xfs_dialloc_ag` picked the SAME just-freed,
peer-noino-held inode every pass and sat in a 1 s bounded inode reserve while
holding the AG EX (the peer's release fence queued on our AG); excess wall ≈ 1 s
× count.  RULE-5 ruling: `docs/rulings/dialloc-try-reserve-candidate-rotation.md`.
- `mxfs_v5_dlm_inode_reserve_try()` (dlm/v5_mount.c): NOQUEUE reserve, optional
  DEMAND (sticky revoke on the holder's slot).  The old 1 s queued reserve and
  `P-DIALLOC-RESV-BUSY` are gone.
- `mxfs_dialloc_pick_in_rec()`: rotates candidates within the finobt/inobt
  record on a WORKING COPY; per-AG cooldown ring `pag_resv_cool` (500–1000 ms
  jittered) + continuation cursor `pag_resv_cursor`, both under `pag_resv_lock`
  (xfs_ag.h/.c).  ≤8 probes / 4 ms per AG visit then -EAGAIN
  (`P-DIALLOC-RESV-EXHAUST`); a full finobt lap with nothing reservable →
  `P-DIALLOC-RESV-SWEPT` (rs->swept).
- `xfs_dialloc` tail: a failed full sweep that SAW contention (contended / cool
  / budget_exhausted / swept) backs off OUTSIDE every lock (5–200 ms jittered,
  doubling) and escalates to DEMAND (`P-DIALLOC-SWEEP-RETRY`); it is NEVER
  ENOSPC and (0.23.1) NEVER relaxes the ownership partition.  A sweep with zero
  contention = genuinely full partition → relax, then ENOSPC as before.
- Stats: `resv:` block in the DLM stats line (`try ok cont cool err exh adv
  sweeps backoff_ms demand probe_us probe_max_us grow`); `mxfs_resv_stat_*`.

### agcount < nodes ownership fold + grow-on-swept (0.23.1)
- `mxfs_ag_inode_owned()`: stride L = min(m_mxfs_log_node_count, m_maxagi).
  With 25 AGs / 32 slots the slots ≥ 25 previously owned NOTHING and ran every
  create in the RELAXED pass, wandering into any AG that momentarily returned
  -EAGAIN — measured lap 5 on 0.23.0: six "exclusive" nodes allocating in
  test7's AG 16 → the AGI unlinked-bucket cross-node shutdown (#3 family).
  Now every AG has 1–2 FIXED owners; unchanged when agcount ≥ nodes.
- `xfs_dialloc_try_ag`: on -EAGAIN with rs->swept (every free inode peer-held
  but the AG has room) GROW a fresh chunk (`xfs_ialloc_ag_alloc` + roll) and
  retry once (`P-DIALLOC-RESV-GROW`, stat `grow`) instead of spilling.
  0.87.23 (D-DIALLOC-REPICK-STORM): both carve arms pass
  `mxfs_dialloc_carve_gate` — ONE carve per `xfs_dialloc` call
  (`rs->grows`, spent after `xfs_ialloc_ag_alloc` succeeds, before the roll;
  a second is refused with `P-DIALLOC-CARVE-BOUND` and the AG handed back
  `-EAGAIN`), because the create's reservation pays for one chunk and a roll
  carries only the remainder; `swept` is reset per AG visit and stays the
  vote "no usable candidate this lap" (a full cooling/held lap, or the
  pubpend storm exit) — voting it only on peer contention was tried and hung
  the create whose sole free number is refused for good (nothing carved,
  sweep backed off forever, parent ILOCK held, node power-cycled).
  `P-DIALLOC-GROW-RES` prints each carve's
  `blk_res/blk_res_used`; `P-TRANS-BLKRES-OVERRUN` (xfs_trans.c) names the
  task and counts at the reservation guard before the shutdown.  Design:
  `docs/free-publish.md` "One inode-chunk carve per allocation".
- Measured (25 AGs, 32/caw): 0.23.0 laps 1–5 rsync_paired 20/35/36/41/34 s,
  shared nodes within 2× of exclusive every lap; 0.23.1 lap 1 19 s (fleet
  6–13 s).  Acceptance series continues (ruling: ≥10 overwrite laps <60 s,
  within 2×, zero foreign-AG spill) — see D-RSYNC-LAP-PACE-AG-SHARING-388.
  Harness: `tests/ag_handoff_lap_sweep.sh LAP [label]` (needs D385_OUT;
  one d385 TREATMENT lap + fleet counter sweep + per-node rsync walls).

## sess395 (2026-08-22, 0.23.2-0.23.3) — the insert-path fossil: EMPTY-bucket insert must sanitize i_next_unlinked and the buffer nu

### Invariant (new, multinode only)
`xfs_iunlink_insert_inode` (xfs/libxfs/xfs_inode_util.c) is entered ONLY by
inodes that are provably not on any unlinked list (droplink's fresh nlink->0,
O_TMPFILE / EEXIST-loser creates, the orphan scan after its 64-bucket walk), so
on entry `ip->i_next_unlinked == NULLAGINO` AND the in-buffer dinode's
`di_next_unlinked == NULLAGINO` must hold.  Upstream assumes both; in MXFS
neither is guaranteed: `xfs_inode_from_disk` (the ONLY writer of
i_next_unlinked, xfs_inode_buf.c) imports whatever the platter slot carries,
and the platter slot carries a dead chain value whenever a prior life's
removal NULL never landed home (xfs_iflush never rewrites nu; cluster writes
skip un-logged passenger slots; the gen-keyed iunl store gives no graft across
incarnations).  Measured: `P-CREATE-NUFIX` fires 29-111x per node per lap on a
FRESH fs after one rsync lap — platter fossils are the norm.

### The hole and the measured kill (0.23.1 test10 / 0.23.2 test27)
sess388's `P-IUNL-FOSSIL-RESET` reset the in-core fossil only when it EQUALED
the bucket head.  With an EMPTY bucket (head == NULLAGINO, the common case for
per-slot buckets) the fossil was kept, upstream's empty-bucket path logged no
dinode, and the head-remove of that inode repointed the bucket at the fossil —
a freed number that the next create re-allocates as a LIVE linked file.  Every
later REM in the bucket then chains to it; P86-AGI-UNLINKED-BADHEAD (head reads
LINKED, not in cache, nothing to repair); the first insert that walks the
bucket with that head evicted from cache dies in `xfs_iunlink_reload_next`
(P84-UNL-RELOAD-LIVE -> -EFSCORRUPTED in a dirty txn -> shutdown).  Ingress
named on 0.23.2: `P-IUNL-FOSSIL-INGRESS ... caller=xfs_iget_cache_miss`.

### Landed 0.23.3 (RULE-5 ruling docs/rulings/iunlink-insert-fossil-reset-f1-f4.md)
- `mxfs_dinode_nu_clear(tp, ip, probe, why)` (static, xfs_inode_util.c): the
  NUFIX idiom (read cluster buffer via xfs_imap_to_bp, if !XBF_STALE && magic
  && nu != NULL: set NULL, CRC, xfs_trans_inode_buf, 4-byte xfs_trans_log_buf).
  Used by `P-CREATE-NUFIX` (create txn) and `P-IUNL-NUFIX` (insert txn).
- F1: insert entry resets a non-NULL in-core next for ANY head
  (`P-IUNL-FOSSIL-ENTRY ... reset to NULLAGINO`, carries cert=).
- F2: empty-bucket branch calls the helper BEFORE `xfs_iunlink_update_bucket`
  and, if it cleared, `mxfs_iunl_store_record(... NULLAGINO ...)` so a stale
  platter re-read is overlaid with the committed NULL.  Reservation: same
  class as the non-empty case (`xfs_calc_iunlink_add_reservation` already
  covers one inode-cluster buffer); lock order AGI -> cluster buffer is the
  iunlink-item precommit order.
- NOT landed: F3 (sanitize at xfs_inode_from_disk for LINKED images — only
  after F1/F2 verify, with an effective-linkedness predicate: in-core not a
  list member), F4 (online clear of a fossil head: detection-only; legacy
  fossil heads need a scrub, not an online clear).
- Probes: `P-IUNL-FOSSIL-INGRESS` (xfs_inode_buf.c, LINKED image with non-NULL
  nu, %pS caller, cap 300), `P-IUNL-FOSSIL-ENTRY`, `P-IUNL-NUFIX`.

## sess396 (2026-08-22, 0.23.5-0.23.6) — F2's early buffer lock is an ABBA; the insert transition now carries an INSERT-mode iunlink item

**Measured (0.23.5, no injection, lap 5, test25):** NON-empty bucket insert:
`P-IUNL-FOSSIL-ENTRY fossil_next=0x9dc head=0x163b fix=1 — reset` → upstream
`xfs_iunlink_log_inode` captured `old_agino=NULL` → precommit
`P53-IUNLINK-MISMATCH old_ptr=0x9dc old_agino=0xffffffff next_agino=0x163b`
(buffer dinode nlink=1, nu=0x9dc) → `-EFSCORRUPTED` → `Corruption of in-memory
data (0x8) at __xfs_trans_commit` → withdraw.  F1 alone made the non-empty case
worse: before it, old==buffer==fossil and the apply overwrote the fossil.

**Ruling (docs/rulings/insert-mode-iunlink-item.md)
and landing 0.23.6:**
- `struct xfs_iunlink_item.insert` + `xfs_iunlink_log_inode_insert()`
  (xfs_iunlink_item.[ch]; `__xfs_iunlink_log_inode(..., insert)` shared body).
  INSERT mode: forces an item even for NULL→NULL; precommit
  (`xfs_iunlink_log_dinode`) requires `old_agino==NULLAGINO`
  (`P-IUNL-PRECOMMIT-INSERT-BADOLD` else → strict path), skips the write when
  the buffer already reads `next_agino`, otherwise overwrites whatever the
  buffer carries (`P-IUNL-PRECOMMIT-INSERT-FOSSIL` when non-NULL).  Every
  non-INSERT item keeps upstream's strict `buffer == old_agino` check.
- `xfs_iunlink_insert_inode`: non-empty branch uses the INSERT item (multinode
  + `iunl_fossil_fix`), empty branch REPLACES F2's early
  `mxfs_dinode_nu_clear` + store-record with a forced INSERT item (NULL→NULL);
  `P-IUNL-NUFIX` no longer fires from the insert path.  F1 unchanged.
- **INVARIANT (ruling):** never take a cluster buffer dirty (xfs_imap_to_bp(tp)
  + log) BEFORE the sorted precommit.  `xfs_trans_run_precommits` sorts items
  precisely so cluster-buffer acquisitions are ordered; an early dirty lock is
  an unordered prefix → real ABBA (T1 holds A dirty, later needs C transiently
  at its inode-item precommit; T3's sorted iunlink precommit holds C dirty and
  waits for A).  `P-CREATE-NUFIX` (sess48, create txn, xfs_inode_init) did
  this too — CONVERTED in-tree for 0.23.7 (pending build+measurement): the
  create transaction now adds a forced INSERT-mode NULL→NULL item
  (`xfs_iunlink_log_inode_insert(..., site=2)`); fossils found there print
  `P-IUNL-PRECOMMIT-INSERT-FOSSIL site=create`; `P-CREATE-NUFIX-CORE` names a
  non-NULL in-core value at create (should never fire: creates never read the
  platter dinode into core), `P-CREATE-NUFIX-ITEMFAIL` an item-creation error.
  `mxfs_dinode_nu_clear` now serves only the fault injector.
- Injector `iunl_fossil_inject` now fires on empty AND non-empty inserts
  (prints `head=`), odd counts also stamp the buffer (test-only; that stamp is
  itself the early-lock pattern).
- The iunl store record written in the apply path is "precommit-applied", not
  committed (pre-existing sess47 semantics) — noted by the ruling.

## sess398 (2026-08-22, in-tree for 0.23.7) — create-item stacking, cert ownership, injector matrix

- **O_TMPFILE stacks two iunlink items for one inode in one transaction**
  (`xfs_create_tmpfile`: `xfs_icreate` → `xfs_inode_init` adds the create-path
  INSERT NULL→NULL item (site 2), then `xfs_iunlink` adds the insert item).
  Handled: `__xfs_iunlink_log_inode` no longer warns `P-IUNL-CERT-STACKED` when
  the standing cert is `{NULL→NULL}` under a new INSERT item, and
  `xfs_iunlink_item_release` retires the certificate ONLY if it still equals
  this item's `{old→next}` (the later item's cert supersedes the earlier and
  must survive the earlier item's precommit release).  Any other stack is
  still the sess203 alarm.
- **Injector matrix** (`iunl_fossil_inject`, test-only): `inj % 5` → 0 core
  fossil only; 1 core==buffer; 2 buffer only (core NULL — the 0.23.5 test25
  natural shape); 3 core A != buffer B; 4 buffer already == new head
  (non-empty only, else mode 2).  Line: `P-IUNL-FOSSIL-INJECT ... mode= core=
  bufv= buf=`.  Expected with fix=1: one `P-IUNL-FOSSIL-ENTRY` per core plant,
  one `P-IUNL-PRECOMMIT-INSERT-FOSSIL` per buffer plant (modes 1-3), mode 4
  silent; never P53/INSFAIL/shutdown.

## sess398 (2026-08-22, 0.23.8) — synthetic re-logs need EX tenure: `mxfs_dlm_relog_authorized()`

**Measured (0.23.6 natural lap 6, ledger D-RELEASE-DRAIN-RELOGS-DEAD-INCARNATION-
WITHOUT-TENURE-TYPEFLIP-398):** test18's orphan BAST drain (held_mode=0) on ino
12590567 — a dir it had created (gen 415329758) that a peer had removed+freed
and test27 had re-created as a FILE (gen 348095055) 2 s earlier.  The drain's
tenure verify refused (`P-ICD-TENURE-REFUSE`, `i_dlm_icd_refused`), then the
`P146V-UNLANDED` "clean-but-unlanded" arm re-logged the dead dir core anyway
(`P58-DIRPIN-NONEX dlm_mode=0`), the slot became LOGGED, and the next cluster
write (`P56-DIRWRITE relflush=1 logged=1 write=[]`; the P218 passenger filter
only drops UN-logged slots) landed the empty-dir image over the live file →
dirent=file / dinode=dir cluster-wide → `P201-TYPEFLIP-UNRESOLVED-FAIL` -ESTALE.
P146D (needs the dirent-validated dead-incarnation marker) and P189 (needs gen
equality) both missed.

**Fix (RULE-5 ruling, sess398):** `mxfs_dlm_relog_authorized(ip, site, disk_gen)`
(xfs_mxfs_dlm.c, just before `mxfs_dlm_bast_process`) gates EVERY synthetic
re-log — the P146V arm and the P182 shortform pre-merge (gate runs BEFORE the
in-place 3-way merge).  Authorized iff `mxfs_v5_dlm_inode_held_rawmode() >=
EX` and `!i_dlm_icd_refused`.  Refusal prints `P146V-NOAUTH-REFUSE site= held_mode=
foreign=`: foreign platter gen → `i_mxfs_dead_incarn_gen = disk_gen` +
`i_dlm_stale` (src 100), drain breaks with flushed=true (nothing of ours
exists to land); same gen → `i_dlm_stale` (src 101) + `i_dlm_icd_refused`,
flushed stays false (NOT durable; next-acquire merge re-lands).  **INVARIANT:**
never manufacture a transaction on an inode without EX tenure; gen
(in)equality is never an exception.  P58-DIRPIN-NONEX stays as the hard
diagnostic (pin is too late to enforce).  Follow-up (ruling): a write-side
tenure/epoch provenance token on logged slots is the durable backstop.

**0.23.8 measurement → 0.23.9 correction (sess398):** the first gate also vetoed
on `i_dlm_icd_refused`; that flag is STICKY (cleared only by a real destage
write, xfs_mxfs_dlm.c ~7479 — the write the P146V re-log itself used to
produce), so it refused 24-43 legitimate same-gen repairs per node on the hot
shared dirs at a verified EX hold (`P146V-NOAUTH-REFUSE held_mode=5 foreign=0`).
Now: authority = `mxfs_v5_dlm_inode_held_rawmode() >= EX` only; a foreign
platter gen under EX is authorized only with `i_mxfs_self_created` (our own
unlanded create), else refused + write-poisoned.  New detector
`P-RELFLUSH-NOTENURE` at the durable-loop entry (RELFLUSH token granted after
the tenure verify refused) — the logged-slot write filter (`P219`/`P222`,
pal/linux/xfs_buf.c ~3944) exempts `rf=1`, which is how the 0.23.6 clobber
write got through; measure before enforcing.

## sess399-400 (0.23.10-0.23.12) — AGI unlinked-list REMOVE needs AG-DLM tenure; pagi re-sync on every AGI read

- **INVARIANT (sess399, D-AGI-FREECOUNT-BTREE-DIVERGENCE-STALE-AGI-RMW-399): every
  AGI modification runs under the AG DLM.**  `xfs_iunlink_remove()` has three
  callers — `xfs_inode_uninit` (under `xfs_ifree`'s lock), `xfs_dir_add_child`
  (the `linkat(AT_EMPTY_PATH)` of an O_TMPFILE, `xfs_dir2.c` ~1578) and the
  rename-whiteout path in `xfs_dir_rename_children` (`xfs_dir2.c` ~2048).  The
  last two ran with NO tenure until 0.23.11; now bracketed exactly like
  `xfs_iunlink` (lock before `xfs_read_agi`; error → `mxfs_ag_dlm_unlock`;
  success → `mxfs_ag_dlm_unlock_deferred(tp)`).  `P-IUNL-RM-NOTENURE`
  (`xfs_inode_util.c` xfs_iunlink_remove) is the standing precondition alarm —
  any firing names a new un-tenured AGI writer.
- Why it mattered: an un-tenured AGI log item sits in the AIL undestaged with no
  release drain owed; after a peer tenure, the read hook's protect branch
  (`xfs_mxfs_dlm.c` mxfs_ag_meta_invalidate_stale, P77 PROTECT-in-AIL) keeps
  the stale image, the RMW against freshly read inobt/finobt leaves yields
  `agi_freecount` ±1, and the release publishes it.  +1 on a full AG = every
  create −117 (`finobt_near i!=1&&j!=1`); −1 = `P-DIFREE-CORRUPT finobt-mismatch`
  shutdown.  Layer-2 alarm `P-AGMETA-PRIORTENURE-UNDESTAGED-INAIL` now fires
  (log+stack) if a prior-tenure, clean, unpinned, undestaged AG-meta buffer
  reaches that protect branch.
- **Lock-edge note:** create/linkat/whiteout take AG(inode) → AG(dir); `xfs_remove`
  (non-dir) takes AG(dir) → AG(inode) (removename before droplink).  That cross
  edge PRE-EXISTS this fix; mxfs has no global ascending-agno policy (GPT
  flagged the class — separate hazard).
- **`xfs_read_agi` now rebuilds `pagi_freecount/pagi_count` when
  `XFS_AGSTATE_AGI_INIT` is clear** (0.23.12).  A fresh tenure clears the bit
  (`xfs_mxfs_dlm.c` ~39315, only when the on-disk AG gen advanced); upstream
  rebuilt only in `xfs_ialloc_read_agi`, so `xfs_iunlink`/`xfs_iunlink_remove`/
  `xfs_difree` as the tenure's first AGI user left `pagi_freecount` at the prior
  tenure's value until the next `xfs_ialloc_read_agi` (in-core ±1, self-healing,
  but the exact state that feeds `finobt_near` −117 if it reaches dialloc).
- **Oracle pitfall:** `chk_mxfs` on a LIVE LUN is not a consistency oracle for a
  HELD AG (owner's in-core image is authoritative; btree and AGI writes can land
  seconds apart mid-tenure — E4 AG 23).  Use `tests/agifc_churn_experiment.sh`
  with `AGIFC_UMOUNT=1` (clean fleet unmount before chk); the per-op audits are
  `P-AGIFC-MISMATCH` (7 sites, `xfs_ialloc.c` mxfs_agifc_audit, predicate
  agi==ibt==fin==pagi), `P-AGIFC-RELEASE-MISMATCH`, `P-AGIFC-MOD` ledger.
- **`xfs_link` pre-acquires sip's AG** (0.23.13) via `mxfs_trans_preacquire_inode_ags(tp,&sip,1,&sip,1)`
  when `sip` nlink==0 (O_TMPFILE linkat) — same protocol as `xfs_remove`'s victim
  and `xfs_rename`'s whiteout wip, so the `xfs_dir_add_child` AG-DLM bracket nests on the
  cached fast path and never blocks on a grant with ILOCKs held.  Probe
  `P400-LINK-CLEANRETRY` counts the -EAGAIN clean retries.

## 2026-08-23 (sess401): per-op dir publish gate — `mxfs_dir_op_needs_publish`

The synchronous parent-dir publish on create/remove/rename
(`mxfs_dlm_dir_inode_durable` = log force + iflush cluster + sync bwrite,
~1.7 ms on the rig) was gated per call site on
`!dp->i_mxfs_self_created || dp->i_dlm_dir_gen > 0`.  PROVEN sess401: a
brand-new self-created dir has `i_dlm_dir_gen == 1` after its first lock
acquire (`P133-REMOVE durable=1 self_created=1 dgen=1`), so the gate fired for
every directory ever used and the node-private carve-out never applied — every
unlink/create/rename in a private dir paid the publish.  Now one helper,
`mxfs_dir_op_needs_publish(dp)` (xfs_mxfs_dlm.c, next to `dirop_sync_barrier`),
used by `xfs_create`, `xfs_remove`, `xfs_rename` (src+target): a self-created
never-BASTed dir skips the per-op publish regardless of `i_dlm_dir_gen`
(`i_mxfs_self_created` is cleared on any peer BAST, reload, reclaim — the
handoff drain publishes at release).  Knob `dirop_virgin_skip` (1 default, 0 =
legacy), shadow counter `dirop_virgin_skips_n`.  Invariant unchanged: a dir a
peer has touched always publishes per op.  Measured: unlink 2.27 → 0.48 ms,
tmpfile churn iteration p50 5.0 → 3.2 ms.  `tests/tmpfile_churn_ftrace.sh`
is the per-callee breakdown instrument (function_graph; needs
`options/function-fork`).

### Clean-release marker log item (0.24.0, sess403)
- `xfs/xfs_relmark_item.{c,h}` — `XFS_LI_MXFS_RELMARK` (0x12c0), `struct mxfs_relmark_log_format`
  (64 B: class, resource, lineage, grant epoch, owner slot/node/incarnation). Producer
  `mxfs_relmark_publish()` = tiny `XFS_TRANS_NO_WRITECOUNT` txn + `xfs_trans_set_sync`; called by
  `mxfs_ag_relmark_before_unlock()` (AG bast worker + deferred release worker, identity saved by
  `mxfs_ag_handoff_commit` into `pag_mxfs_rel_epoch/lineage`) and `mxfs_inode_relmark_before_unlock()`
  (both `mxfs_v5_dlm_inode_unlock_open` arms of `mxfs_dlm_bast_process`; identity captured at the
  terminal store).  Invariant: marker durable BEFORE the unlock CAS; release irrevocable after it
  (`P-RELMARK-REINSTALL-REFUSED` in `mxfs_inode_authority_install_durable_ex_locked`).
- Consumer: pass-1 table `log->l_mxfs_relmark_tbl` (untrusted replay only); `mxfs_shadow_eval_token`
  returns `MXFS_RI_VERDICT_{REFUSE,APPLY,REDUNDANT}` stored on `xlog_recover_item.ri_mxfs_verdict`;
  admitted txns skip REDUNDANT buf images (`P227-FR-REDUNDANT-SKIP`). `MXFS_PROTO_GEN` 5→6.
- Not marked (fail-closed at replay): ICLUS cluster-release path, unmount release_all, the
  ag_meta_iodone no-flush fallback. Counters: debugfs inode-authority file, `relmark` block.
- Fallible acquire sites (D-0958, `mxfs_ilock_fallible`): open, getattr, read envelope + IOLOCK
  ride, splice, readdir (four stages), and since 0.84.10 the write path's first IOLOCK ride
  (`xfs_ilock_iocb_write` in `pal/linux/xfs_file.c`: buffered/DAX/direct first ride, NOSEC relock,
  EOF-zeroing re-take; `P958-WRITE-REFUSED stage=`), and since 0.84.11 xfs_create's (mkdir's)
  first acquire of the parent (`ILOCK_EXCL|PARENT` after `xfs_trans_alloc_icreate`, before
  `xfs_dialloc`; a refusal cancels the CLEAN reservation via `out_trans_cancel`,
  `P958-NAMESPACE-REFUSED op=create|mkdir`, helper `mxfs_namespace_refused`), and since 0.84.12
  the rest of the namespace class: xfs_remove/xfs_link's pair inside `xfs_trans_alloc_dir`
  (`mxfs_lock_two_inodes_fallible`: both inodes registered around `xfs_lock_two_inodes`, the
  pair released and the clean reservation cancelled on a refusal), xfs_rename's set
  (`mxfs_lock_inodes_fallible` around `xfs_lock_inodes`, cancel via the dqattach-failure path),
  xfs_symlink (as create). A refused set member does not stop the other members' acquires
  (one budget per faulted member). 0.84.13: the lookup (consumer refresh + the directory read
  inside xfs_dir_lookup, which asks `mxfs_acqfall_refused` after its lock and returns before
  reading a block; `P958-LOOKUP-REFUSED stage=refresh|dir`) and the two direct-write retries
  (`stage=unaligned-excl-retry|atomic-cow-retry`: under IOMAP_OVERWRITE_ONLY the first mapping
  spans the whole request or answers -EAGAIN before any bio, so the retry follows zero bytes).
  0.84.14: the write's timestamp update — `xfs_file_write_checks` calls
  `mxfs_kiocb_modified_fallible` (registers the inode around `kiocb_modified`), and
  `xfs_vn_update_time` (`pal/linux/xfs_iops.c`) asks `mxfs_acqfall_refused` after its
  `xfs_ilock(ILOCK_EXCL)` and cancels the clean `tr_fsyncts` reservation on a refusal
  (`P958-WRITE-REFUSED stage=timestamp`).  Why: a direct write whose data grant is a cached PR
  fast-paths its shared ride, so the timestamp's EX is the FIRST request it sends (s596d) — the
  retry's own ride sits behind it.  A page fault's `file_update_time` is unregistered and waits.
  Harness: the O_DIRECT writer is parked by `tests/dio_unaligned_pwrite.py` (a shell cannot open
  O_DIRECT; opening inside the armed command lands the refusal on open — s596d), and
  `live_holder_wait.sh HOLDER=pr` makes H keep a clean PR beside W's so the timestamp EX is the
  request that meets the paused release.
  Harness trap: a DIRECTORY holder that still caches PR takes its own PR-to-EX upgrade through
  the self-demote release drain (-EDEADLK), so a `dbg_rel_pause` armed before the holder's own
  re-dirty parks the holder for the whole pause (s595b); for a directory arm AFTER the re-dirty.
  A socket-level DLM fault under the 40 s grace self-heals (s594c: disconnect, reconnect, re-send
  dedup by acq_seq) — the unbounded class is a message-level discard on a healthy socket.
- Verifying the REDUNDANT_CLEAN verdict on a real image needs the released image INSIDE the
  victim's replay window, which a live node never leaves behind on its own: the release drain
  lands the image before the unlock and the destage kick empties the AIL within ms, so the on-disk
  tail moves past it (s593h: window = the two markers, txn=0 buf=0 relmarks=2). Test knob
  `mxfs.dbg_ail_pin_ino=<ino>` (`xfs_inode_item.c`, honoured by `xfs_inode_item_push` → LOCKED and
  by the `xfs_iflush_cluster` loop → skip, `P-AILPIN-HOLD`) keeps one inode item in the AIL so the
  tail is pinned behind everything logged after it; `tests/tcp_death_replay.sh TDR_FALSE_APPLY=3`
  drives it. Never set it on a node meant to survive.

## sess405 (0.26.0) — foreign-replay verdict from the FENCE-TIME MANIFEST (xfs_log_recover.c)

`mxfs_shadow_eval_get` loads the victim's sealed manifest once
(`mxfs_v5_dlm_victim_manifest_load`, `P-RMAN-LOAD`) when the descriptor is
FENCED and builds an open-addressed `{type,id}` index (`man_idx`).
`mxfs_shadow_manifest_lookup` answers "held {lineage, epoch} at fence time"
from it: absent entry → `-ENOENT` (not_held), `NO_CAW` manifest → `-ENODEV`
(manifest_err, the pre-manifest TCP behaviour); on a hit the live slot is read
ONCE as the CURRENT-SAFETY check — bit absent / lineage / epoch changed →
`P-RMAN-POSTSEAL-MUTATION`, read error → `P-RMAN-LIVECHECK-ERR`; both set
`se->rman_abort`.  Under enforcement `xlog_recover_items_pass2` then returns
-EIO (`P-RMAN-ABORT`; verdict reason NONE → retryable, slice dirty, nothing
purged) and `mxfs_fr_enforce_preflight` aborts when the manifest did not load
(`P-RMAN-LOAD-ABORT`).  Report-only mode (enforce off / uncapable) keeps the
live-read path.  One `P-RMAN-EVAL` summary per untrusted log next to
`P273-SHADOW-EVAL` (whose format is unchanged — harnesses parse it).

## sess407 — FSWIDE terminal halts foreign replay (D-FSWIDE-TERMINAL-REPLAY-CONTINUES-407)
- `mp->m_mxfs_quar_fswide` is now a global "no further replay" state, not only an
  AG/inode enforcement input: `mxfs_dlm_foreign_replay_work_fn` skips claim/replay
  (no re-arm, `P-RMAN-FSWIDE-HALT` ratelimited) after the terminal classification
  step; `mxfs_xlog_recover_foreign_slice` (xfs_log.c) refuses at entry with
  verdict reason NONE (nothing published for that slot); the per-transaction
  verdict in xfs_log_recover.c (next to P-RMAN-ABORT) aborts an in-flight foreign
  slice -EIO at a transaction boundary.  Mid-slice stop is restartable (crash
  semantics).  Observed cause: mutate2 on 0.26.2 — one victim MUTATED-TERMINAL,
  the other replayed complete 5 s later on the same node (RULE-5 ruling: not
  allowed).  PITFALL: the publisher imports its own FSWIDE verdict immediately,
  so the gate must sit in the loop, not only in the import callback.

## sess408 (0.26.4) — pre-replay whole-manifest verify (D-RMAN-MUTATED-SLICE-REPLAYED-BEFORE-VERIFY-408)
- `mxfs_fr_enforce_preflight` (xfs_log_recover.c) now live-reads EVERY sealed
  manifest entry (`mxfs_v5_dlm_victim_live_read`, same holds/epoch/lineage/
  mode/slot_idx comparison as the per-record check and `mxfs_v5_dlm_rman_verify_live`)
  after the manifest loads and BEFORE `xlog_recover`.  Any mismatch →
  `P-RMAN-POSTSEAL-MUTATION site=prereplay` + `P-RMAN-PREREPLAY-VERIFY … mutated=N`,
  `se->rman_abort` + `l_mxfs_rman_mutated`, return -EIO → `mxfs_xlog_recover_foreign_slice`
  (xfs_log.c ~1097) promotes to -EFSCORRUPTED + AUTHORITY_MUTATED FSWIDE terminal
  with NOTHING replayed.  Undecidable live read → `P-RMAN-LIVECHECK-ERR site=prereplay`,
  retryable (reason NONE).
- WHY: the per-record current-safety check only covers entries the replayed
  records reference; the pre-purge verify runs after the slice is applied.  On
  0.26.3 mutate2 the test hook cleared an UNREFERENCED entry → slot 17 replayed
  complete (616.13 s) and MUTATED-TERMINAL came from prepurge (616.157 s): "slice
  stays frozen" was false.  On 0.26.2 the same arm mutated a referenced entry and
  aborted mid-replay — which entry the hook hit decided the outcome.
- PITFALL (harness): the terminal arm expects frc=0 (sess407 ruling).  That holds
  on 0.26.4 only with BOTH this verify (mutated slot not applied) AND the FSWIDE
  halt (other victim not claimed).  `rpost` counts `P-RMAN-POSTSEAL-MUTATION`
  regardless of site; `P-RMAN-PREREPLAY-VERIFY` is a new line (not yet a sweep
  counter).

## sess408-409 (0.26.5-0.26.6) — di_changecount continues across incarnations (D-FREPLAY-VICTIM-INODE-CORE-NOT-APPLIED-BUCKET-TO-ZERO-CORE-408)

Full write-up: `docs/foreign-replay-inode-ordering.md`.

- Foreign replay orders inode images by `di_changecount` (per-node slices make
  LSNs incomparable); `xfs_inode_init` used to restart it at 1 per
  allocation, so a reincarnation's creation image was judged OLDER than the
  previous incarnation's freed core and SKIPPED while the same transaction's
  inobt/AGI/bucket buffer images applied (bucket -> mode-0 core; chk shows it).
- `xfs_inode.h`: `i_mxfs_prev_changecount`.  `xfs_icache.c`:
  `mxfs_iget_create_prev_changecount(mp, pag, tp, ip)` (static) — fresh
  cluster read at iget CREATE (sess38/sess91 stale discipline, TRYLOCK),
  called from the `xfs_iget_cache_miss` v3 CREATE branch AND from
  `xfs_iget_recycle` (the dominant churn path; value = max(platter,
  in-core i_version)).  `xfs_inode_init`: iversion = prev+1.
- API change: `xfs_iget_cache_hit(pag, ip, tp, ino, flags, lock_flags)` and
  `xfs_iget_recycle(pag, ip, tp, deadshell_create, create)` gained `tp` /
  `create` (internal, static).
- RULE 0: the read is skipped when the cached cluster buffer carries the
  current `pag->ag_dlm_tenure_id` (stamped into `bp->b_tenure_id` at the
  fresh read — unused on cluster buffers otherwise).  Counters
  `mxfs_ccprev_reads/_tenure_hit/_nostale` in the `mxfs DLM cache:` stats
  line and `FUA-COUNT`.
- Oracles: `tools/chk_mxfs` ERROR on bucket member with free core (sess408)
  and `P-ALLOC-FREE-CORE` (inobt-allocated, mode 0; sess409);
  `P77-FRINODE` line carries disk/log mode+gen; `tests/tmpfile_churn_kill.sh`
  captures `$OUT/p77.txt`.
- Harness fixes: `d385_publication_verify.sh arm_prep` now FAILS (exit 3)
  when prep_cluster fails (it used to run the workload on an unprepared
  cluster); `tmpfile_churn_kill.sh` outer prep bound 335 s > d385's
  PREP_TIMEOUT 320 s (200 s orphaned a still-running prep under the next lap).

## sess410 — log_inject_ioerr (0.26.12), D-409 verification knob

- `xfs/xfs_log.c` module knob `mxfs.log_inject_ioerr` (int, consumable, 0=off): fails the next N
  iclog write completions with -EIO inside `xlog_ioend_work` (logs `P-LOG-INJECT-IOERR`), so the mount's
  FIRST shutdown comes from `xlog_force_shutdown` ("shut down due to log error") rather than
  `xfs_do_force_shutdown`.  Exists because this build has no `DEBUG`, so the upstream
  `XFS_ERRTAG_IODONE_IOERR` errortag is compiled out.  Driven by `tests/fence_live_node.sh` with
  `FLN_INJECT=logioerr` (withdraw marker = `P-WITHDRAW-QUEUE`, expected within 10 s of the injection,
  then `P-WITHDRAW —`, HB stop -> peers fence + replay the slot).  TEST ONLY.

## 2026-08-23 (sess411, 0.27.0): foreign-slice snapshot + stabilization (D-527)

`mxfs_xlog_recover_foreign_slice()` no longer lets recovery read the
victim's slice live.  After the enforcement preflight (and BEFORE the
one-shot injection knob is consumed), `mxfs_xlog_slice_snapshot()`
(xfs_log_recover.c, beside xlog_do_io) captures the whole slice into
`log->l_mxfs_slice_snap` and accepts it only after `fr_stab_passes`
(default 2) consecutive zero-diff full-slice re-reads, interval
`fr_stab_interval_ms` (2000), deadline `fr_stab_deadline_ms` (45000).
While set, `xlog_do_io()` serves recovery READs from the snapshot and
mirrors WRITEs into it before writing through — head/tail scan and both
passes see ONE immutable image.  Deadline/alloc/read failure → retryable
abort (-EBUSY/-ENOMEM, verdict reason NONE, slice stays dirty, later
election retries); NEVER a fallback to live reads, NEVER terminal from
an unproven image.  Probes: P-FRSTAB-STABLE / -UNSTABLE / -NOT-QUIESCED
/ -ALLOC / -IOERR / -RANGE.  Snapshot freed in xlog_dealloc_log.
Why: D-527 — post-certification landings of the victim's admitted
writes + CRC-valid previous-life twin records in the holes + recovery's
unknown-tid slack tolerance = silent item loss, false TORN, FSWIDE
quarantine.  Doc: docs/foreign-replay-slice-snapshot.md.  Open: adopted
-slice mount replay not snapshotted yet; Phase-4 record incarnation
stamp not built.

## Compat shims (xfs_platform.h) — contract fidelity rule (sess412, D-528)

`xfs/xfs_platform.h` back-fills post-6.8 block APIs for the 6.8 guest
kernel.  A shim MUST copy the upstream return contract verbatim:
`bio_add_vmalloc_chunk` returns BYTES ADDED (0 = bio full),
`bio_add_vmalloc` returns bool (true = whole region added),
`bdev_rw_virt` rejects vmalloc addrs (-EIO).  The pre-0.27.1 alias
`bio_add_vmalloc_chunk -> bio_add_vmalloc` (0-on-success) inverted
`xfs_rw_bdev`'s chain loop into an unbounded beyond-EOD read storm
(ledger D-528; docs/foreign-replay-slice-snapshot.md postmortem).
All `xfs_rw_bdev` callers with vmalloc buffers ride on this: the D-527
slice snapshot, `mxfs_freplay_slice_digest`, and every `xlog_do_io`
recovery read/write.  Kernel reference tree: /src/linux (tracks
upstream; 7.1.0-rc7 as of 2026-08).

## Recovery assembly strictness + the kvrealloc trap (sess412, 0.27.2-0.27.4)

- `mxfs_kvrealloc` now takes `(p, oldsize, newsize, gfp)`. The old 3-arg
  form passed oldsize=0 to 6.8's 4-arg `kvrealloc`, which copies exactly
  oldsize bytes — every record-straddling log region lost its head during
  recovery (D-530: the whole churn di_magic/-117/type-0 family, foreign
  AND own-crash). Any future compat around a copying allocator must carry
  the true old size.
- `xlog_recover_commit_trans` runs `mxfs_xlog_validate_trans_assembly`
  (both passes, before reorder): every item complete (ri_cnt==ri_total,
  valid first region + known type) AND sum(ri_cnt) == the writer's
  `th_num_items` (xlog_cil_build_trans_hdr num_iovecs). Refusals return
  -EILSEQ → published as ASSEMBLY-DISCONTINUITY (kernel reason 5, wire
  reason 6; accept-lists: publisher dlm/disklock.c ~4428 AND import
  xfs_mxfs_dlm.c ~49952 — extend BOTH when adding a reason). Probes:
  P-FRASM-DISCONT, P-FRASM-COUNT, P-FRASM-ITEM, P-FRASM-UNKTID (unknown-
  tid slack skips, counted on the xlog, first 8 logged).
- NEVER use -EUCLEAN as a distinct error class in XFS code: EFSCORRUPTED
  IS EUCLEAN (errno 117). The sess412 fln7 publish-retry loop was that
  mistake.
- Whole-txn untrusted-replay verdict (D-529 fix, 0.27.5):
  `mxfs_classify_untrusted_txn` (xfs_log_recover.c ~3810) runs EXACTLY
  ONCE per transaction, at commit entry (pass 2, untrusted replay only,
  before reorder), over the COMPLETE r_itemq; the MXFS_TXNV_* verdict
  (libxfs/xfs_log_recover.h) is cached in trans->r_mxfs_verdict and
  every 100-item pass-2 batch consumes it. INVARIANT: never re-derive
  ADMIT/SKIP/SBCLEAN per batch — the pre-fix per-batch form could
  partially apply a mixed-authorization >100-item txn (the tear).
  Classification lines (P227-FR-ENFORCE-ADMIT / -ATOMIC-SKIP /
  -SBCOUNTER-CLEANSKIP / P227-SNLOCAL-ACCEPT) now carry the txn's REAL
  item count. Fault injection: `dbg_fr_taint_items_over` knob
  (xfs_mxfs_dlm.c) forces the refusal arm for txns above N items
  (P-DBG-FR-TAINT-INJECT); verification harness
  tests/d529_whole_txn_verify.sh (arm A regression / arm B injection,
  both assert per-lsn classification uniqueness — same lsn with two
  item counts = the per-batch split signature).

## ccloop c7ee71c6 sess414 — INCARN_STALE poison-time revocation (D-512 cycle 1, 0.28.0)

Per the sess413 GPT ruling: setting MXFS_IF_INCARN_STALE only gates NEW ops;
resident PTEs of the dead incarnation stayed readable/dirtyable until a lookup
happened to run the retire arm. Now `mxfs_incarn_poison(ip)` (xfs_mxfs_dlm.c
~24094, prototype in xfs_mxfs_dlm.h) is THE ONLY way the flag is set (3 reload
sites + the dbg knob): it publishes the flag then queues an igrab-holding
revocation worker on `m_mxfs_inode_bast_wq` behind the `m_mxfs_arms_off`
teardown gate. The worker takes `IOLOCK_EXCL|MMAPLOCK_EXCL` in one xfs_ilock
call (no ILOCK → no DLM admission; the exclusive acquisition IS the drain of
gated ops holding either shared), re-asserts the flag, zaps every PTE
(`unmap_mapping_range` even_cows) and DISCARDS the page cache
(`truncate_inode_pages` — dirty G1 must never flush through the dead bmap),
then DONTCACHE+prune so the last iput evicts. P34H-INCARN-REVOKED marks
completion. Gate-set completions: fsync (file+dir, BEFORE
file_write_and_wait_range), xfs_vm_writepages/xfs_dax_writepages skip-submit,
and -ESTALE rechecks in direct/buffered/read/seek/xattr iomap_begin (the
under-the-op's-own-lock recheck). The live ioctl surface is the
GOINGDOWN-only stub (xfs_stubs.c) — pal/linux/xfs_ioctl.c is NOT in Kbuild
and has a pre-existing guard(super_write) compile break; a gate was added
there anyway for if it ever returns. Flag clear site: ONLY
XFS_IRECLAIM_RESET_FLAGS. Verification: `dbg_incarn_poison_ino` self-clearing
param (xfs_file.c, fires at open) + tests/d512_ref_matrix.c +
tests/d512_incarn_gate_verify.sh. NOT YET: component 7 cluster reuse barrier
(cycle 2).

## sess415 — D-512 cycle 2: reuse-barrier containment arms (0.28.1)

Full state machine + open holes: docs/reuse-barrier.md. Ruling: docs/rulings/d512-cycle2-reuse-barrier.md.

**P-D512 drain-error fail-stop** (mxfs_dlm_bast_process, drain site 1): the
release drain's `filemap_write_and_wait` and `invalidate_inode_pages2` rcs
(previously discarded) now refuse the on-disk unlock via the existing abort
gate. Writeback failure = P-D512-REL-DRAIN-WBFAIL + xfs_force_shutdown (peer
must never adopt a platter missing this tenure's data; shutdown withdraws per
D-409). Invalidate residue = P-D512-REL-DRAIN-INVFAIL + CACHED/bast_pending
dwork retry (`i_dlm_bastq_src=22`) — an unrevokable pinned folio pins the
grant. Drain site 2 (post-mode=NL, ~18900) is still unchecked — ledgered.

**P-D512-DIRTY-MISMATCH** (freshsrc reload branch, next to
P34E-FRESHSRC-SELFAHEAD-SKIP): a DIRTY shell meeting a VERIFYING, LIVE
(mode!=0), different-di_gen FUA-fresh image is a proven reuse-barrier
violation → mxfs_incarn_poison + SHUTDOWN_CORRUPT_INCORE fail-stop. The
self_ahead "platter is behind us" keep still applies to FREE+diffgen+dirty
(the sess116/P5F creator case — a genuine peer free must BAST us first, so
free+dirty can only be our own undestaged alloc). Both arms are dormant
asserts: any P-D512-* fire on a healthy board is a defect signal.

## sess419 (2026-08-28, 0.29.1-0.29.3)

- `mxfs_fr_token_enforce_set` (xfs_mxfs_dlm.c) refuses arming under `icluster_dlm=1`
  (cluster-routed tenures have no RELMARK; `mxfs_relmark_iclus_unmarked`) — default-on gate
  item 2 of D-FOREIGN-REPLAY-UNGATED-IMAGES.  Test: `tests/f2_iclus_refusal.sh`.
- `mxfs_sb_mutation_refuse(mp, what)` (xfs_mxfs_dlm.c; prototype xfs_mount.h): cluster-mode
  gate for every runtime NON-counter whole-superblock producer (growfs data/log, setlabel,
  log-incompat add/clear, quota mount/quotaon/off, reset_sbqflags, dalign, features2 repair,
  NLINKBIT add, m_update_sb mount/remount-rw).  `P-SB-MUTATION-REFUSED what=`.  D-0133.
  On the shipped module only `-o sunit/swidth` is reachable from userspace (ioctl surface and
  quota are excluded by Kbuild; LARP needs DEBUG).  docs/superblock-cluster-mode.md.
- `mxfs.dbg_purge_victim` (write-only knob, xfs_mxfs_dlm.c): non-elected survivor runs the
  normal disklock purge path via `mxfs_dbg_mp->m_mxfs_dlm` (D-PURGE-NONATOMIC test arm 1).

- **sess426 D-0346 (P34H poisoned-shell retirement)**: `xfs/xfs_inode.c` ~1562: before `d_prune_aliases`
  the retire loop now prints `P34H-POISON-ALIAS ino= dentry=%pd d_count= children= d_flags=` per alias.
  Board evidence (11/32 nodes, fence_during_write): the previous incarnation's directory shell stays
  cached with i_count=2 through 5 retries → lookup -ESTALE.  Hypothesis: cached child dentries pin the
  alias (d_prune_aliases only drops unused aliases) → fix shape is per-alias `d_invalidate`.
  Reproducer `tests/dir_recreate_estale.sh`.
- **sess426 release pipelines (0.36.1)**: `ip->i_mxfs_rel_instance` (atomic) stamps each P282 release
  pipeline instance on entering RELEASING (`cert->rel_instance`); `mxfs_inode_relcert_finish` resets
  `rel_state` to ACTIVE only for the current instance, else `P283-REL-FINISH-SKIP` (D-DUP-RELEASE
  invariant 4).  Duplicate concurrent pipelines stay legal (sess305 ruling) — never serialize them.

## FREE-PUBLISH invariant (sess427, D-0351) — `docs/free-publish.md`
- A peer may select an inode as free under a newly acquired AG grant only if the free dinode (`di_mode=0` at the freed incarnation's new gen) is already durable. Enforced at the AG-grant handoff by the sess387 obligation machinery extended with a FREE kind: `struct mxfs_pubob {kind UNLINK/FREE_PENDING/FREE, gen, epoch}`; `xfs_inactive_ifree` sets `ip->i_mxfs_freeob=1` before `xfs_ifree` (the `xfs_iunlink_remove` discharge then TRANSITIONS the entry instead of dropping it), `mxfs_pubob_free_commit(mp, ip, pag_mxfs_grant_epoch)` after the commit.
- `xfs_iflush` P55C (before the P119 non-EX guard): classifies the platter image against `{gen, epoch}` — already-free → discharge; exact predecessor (`di_gen == gen-1`, mode != 0) → write under the audit's retiring token (RELFLUSH + `pag_dlm_demoting` + `pag_mxfs_rel_epoch`) or the publication-write gate `mxfs_ag_pubwrite_begin(pag, epoch)` (same tenure; the release commit zeroes the epoch then `mxfs_ag_pubwrite_quiesce`s before its drain), else keep DIRTY (`-EAGAIN`, never laundered) + strike; foreign gen → never write, `i_mxfs_dead_incarn_gen`, discharge.
- Audit `mxfs_p86_agi_unlinked_publish_audit`: FREE_PENDING defers; FREE is read off the LUN, classified, published via `mxfs_p87_publish_repair` and re-verified; unpublishable frees → `pag_mxfs_freeob_split` → the release worker defers up to 8×2 s more, then `P-FREEOB-REFUSED` shutdown (fail-closed regardless of `mxfs_p87_refuse_unlock`).
- Recovery: 8 P55C denials → `m_mxfs_freeob_work` (`mxfs_freeob_recover_fn`) takes the AG EX afresh, reads the home dinode, re-scopes/discharges/neutralizes (`P-FREEOB-RESCOPED/FOREIGN`).
- Pitfall that caused D-0351: `P128-INACT-DEFER` clears `MXFS_IF_DLM_RELFLUSH` while keeping the grant cached; the eager per-ifree durability chain is OFF (`mxfs_ifree_eager_durable=0`) and the AG-release inode-buffer drain only writes what `xfs_iflush` already copied in.

## sess429 (0.38.4 / 0.39.0) — home-free FREE obligation settles the publication ledger
- `mxfs_pubob_settle_home_free(mp, ip, site)` (xfs/xfs_mxfs_dlm.c, next to `mxfs_pubob_discharge`): when a FREE obligation is found already satisfied at home (home dinode mode 0, any gen), settle the freed incarnation's `i_mxfs_pub_pending/durable/flush_seq` by equivalence BEFORE the discharge. Predicates: in-core mode 0 + nlink 0, `i_mxfs_freeob==2` + `MXFS_IF_PUBOB`, `i_pincount==0` (ifree log-complete). Fails closed (`P55C-FREE-HOME-UNSETTLED`, ledger left open → P237 still fires). Call sites: P55C `FREE-HOME` branch in `xfs_inode.c` iflush; the FREE-obligation recovery worker (settle-only).
- Why: without it the unlinked inode's evict hit `P237-EVICT-OBLIGATION` (pend≠dur) and shut the node down (s432 test1, fio_perf). The only consumer of `i_mxfs_pub_fenced` is the deferred-RELEASE worker — unlinked inodes get no BAST.
- P237's evict-side last-chance publish is gated on `!XFS_ISTALE_CAW` (never re-publish a stale shell).
- Docs: `docs/free-publish.md` "0.38.3 → 0.38.4".

## Candidate validation at inode allocation (0.75.117-0.75.119, D-0946/D-0947/D-0948)
- `mxfs_dialloc_validate_candidate()` (`libxfs/xfs_ialloc.c`) is phase 2 of the two-phase allocator: called from `mxfs_dialloc_two_phase` with NO btree cursor and NO AGI buffer held, a CLEAN transaction, and the AG EX held. That combination is what makes it the last point where a candidate can be refused without dirtying anything, and the only point where driving a publication write is safe (the AG EX sanctions the write; holding the AGI would deadlock the publisher).
- Return contract, four ways: `0` allocate; `-EBUSY` transient refusal (cooldown + re-pick, nothing dirtied); `-EUCLEAN` platter image LIVE, mount-lifetime quarantine; `-EIO` the home could not be READ.
- **An open publication obligation of ours is a refusal, not a permission (D-0946).** The pubob arm used to ALLOW without reading the platter, reasoning that a live image at the home had to be this node's own committed-but-unpublished free. Nothing downstream shares that reasoning: the recycle gate in `xfs_icache.c` reads the platter, calls the live image cross-node incoherence and returns `-EFSCORRUPTED` on an already-dirty transaction, which shuts the filesystem down. Now refuses on a **positive whitelist** — `MXFS_PUBOB_FREE`/`FREE_PENDING`/`CHAIN_LIVE`, never `okind != UNLINK` — and prints `P946-VALIDATE-PUBPEND`. The obligation kinds moved from `xfs_mxfs_dlm.c` to `xfs_mxfs_dlm.h` for this.
- The refusal is **transient by construction**: the ordinary reservation cooldown (`mxfs_resv_cool_add`, 500-1000 ms), never `pag_disklive_q`. An inode whose only problem is an owed write of ours is not corrupt; quarantining it leaks inode space and manufactures false ENOSPC.
- Progress rule, or the refusal starves: `mxfs_pubob_drive_publication(mp, ino, ms)` after `MXFS_PUBPEND_DRIVE_AT` refusals in one allocation. A storm reports `P946-DIALLOC-PUBPEND-STORM` and returns `-EAGAIN` into the existing sweep back-off — never `-EUCLEAN`, never ENOSPC. `rs->pubpend` also feeds the sweep-retry's "transient contention" test.
- A/B knob `mxfs.dialloc_pubpend_refuse` (default 1); 0 restores the pre-fix allow as a control arm. **One rate-limit counter per arm** — a shared counter lets the louder arm silence the other and the A/B reads backwards.

### Reading the candidate's home
- `mxfs_dbg_disk_di_read_coherent(mp, ino, &mode, &gen, &magic)` (`xfs_mxfs_dlm.c`) — plain bio read of the platter, three-way result: `rc<0` read failed; `*magic == false` read fine, no inode magic; else a decoded dinode. `mxfs_dbg_disk_di_mode_coherent()` remains as the two-in-one `0xFFFF` form for diagnostic callers that only print the value.
- **The two must never be conflated (D-0947).** Mapping both to `-EIO` failed 600 of 600 creates on a filesystem 7% full, because a home with no magic is the ordinary state of every inode in a chunk this mount allocated and has not destaged.
- **But "no inode magic" does not mean "nothing was ever written there" (D-0948).** A home with no magic held `XDD3`, a dir3 data block. So no-magic is never allocated on: `mxfs_pubob_flush_owed(mp)` KICKS the owed writes (`xfs_log_force(mp, 0)` async + `xfs_ail_push_all`) and the candidate is refused transiently (`P947-VALIDATE-NOMAGIC`). The next visit, after the cooldown, reads a home that has had time to land — ours has its magic and takes the ordinary allocate path, and one that was never ours still does not.
- **A refusal must not vote that the AG is exhausted (0.75.121).** `pag_resv_cool[]` entries carry `pubpend`. The ring is the allocator's PEER-CONTENTION signal and a sweep that finds every candidate parked in it declares the AG spent and grows a fresh inode chunk; tallying our own publication-pending refusals there produced `P-DIALLOC-RESV-SWEPT ... contended=0 cool=56` → `P-DIALLOC-RESV-GROW` on a healthy AG. A pubpend skip now increments `rs->pubpend`, not `rs->cool_skips`, and cools 40-80 ms rather than 500-1000 (the owed write is local and was kicked at refusal; a measured one landed in 8 ms). Unnecessary carves are not free — each is an opportunity for D-0948.
- **Nothing under the AG EX may wait (0.75.120).** The D-0946 ruling names a synchronous flush held across the cluster AG grant as cluster-wide head-of-line blocking, worst case exactly this rig's unlink/create churn. Both `mxfs_pubob_flush_owed()` and `mxfs_pubob_drive_publication()` start the writes and return; the reservation cooldown is the retry delay. An earlier build did force the log synchronously and poll up to 200 ms there — do not reintroduce it.
- `xfs_ialloc_inode_init()`'s SYNCINIT FUA write is followed by a read-back (`P948-SYNCINIT-READBACK` / `-OK`) because a write returning success is not evidence the bytes are on the platter.
- Pitfall when scoring any of this: `P133-ICLUSTER-SYNCINIT` prints only its first 20, and a rolled-over ring buffer truncates the rest — its count divided by a carve count is meaningless in both directions.

## sess430 (0.39.1) — same-node free→recycle→free CHAINS (CHAIN_LIVE)
- `struct mxfs_pubob` gains `chain` and kind `MXFS_PUBOB_CHAIN_LIVE`. `mxfs_pubob_recycle(mp, ip)` (xfs/xfs_mxfs_dlm.c, called from `xfs_iget_recycle` on `create || deadshell_create`, after the DEADSTAMP-CLEAR): an open FREE/FREE_PENDING entry whose `epoch` equals the current `pag_mxfs_grant_epoch` becomes CHAIN_LIVE, `chain+1` (`P-FREEOB-CHAIN-LIVE`); other epoch → dropped loud (`P-FREEOB-CHAIN-BROKEN`); other kind → `P-FREEOB-RECYCLE-ANOMALY`. Also resets `i_mxfs_freeob`/`_strikes` (not iflags — `XFS_IRECLAIM_RESET_FLAGS` only clears `MXFS_IF_PUBOB`).
- `mxfs_pubob_arm` on a CHAIN_LIVE entry → kind UNLINK (chain kept). `mxfs_pubob_lookup` now returns `chain` too.
- Classifier change: a chained FREE (`chain > 0`) with a LIVE home image at ANY gen is one of this node's own lives (tenure never left this node; the audit publishes or fails closed before an unlock) → P55C writes it under the same sanction as `di_gen == gen-1` (`P55C-FREE-CHAIN`; no sanction → DENIED, never FOREIGN); the audit skips CHAIN_LIVE entries and publishes chained FREEs when `ob.epoch == pag_mxfs_rel_epoch` (`P-FREEOB-CHAIN`). The recovery worker (fresh EX) keeps FOREIGN.
- Neither FOREIGN branch stamps `i_mxfs_dead_incarn_gen` on a shell whose in-core mode ≠ 0 (a live recycled inode must never be write-poisoned; s433 saw one `P32D-DEADINCARN-SKIP`).
- Reproducer `tests/free_foreign_realloc_repro.sh`; chain `tests/sess430_chain.sh`; classifier `tests/classify_free_foreign.py`.
- 0.39.3 audit fix: `mxfs_p86_agi_unlinked_publish_audit` no longer returns early past its obligation section when the AGI buffer is not incore / `XBF_TRYLOCK` fails / knob off / bad magic — those now `goto obligations` with `P86-HEADWALK-SKIPPED`. Pitfall: the head walk is optional, the obligation enforcement (unlink + FREE-PUBLISH) is not; s436 measured 8 FREE obligations crossing inline releases through that early return. A/B knob `mxfs.dialloc_validate` (default 1) gates the two-phase allocator (test aid only).
- 0.39.9 (sess431, `docs/free-publish.md` "0.39.7 → 0.39.9"): P55C classifies the FREE obligation's home from a raw platter read ALWAYS (`mxfs_dbg_disk_di_mode_coherent`), never from `dip`; `xfs_buf_inode_iodone` clears `MXFS_IF_PUB_SKIPPED` on the `!ili_last_fields` early exit; fault knob `mxfs.freepub_drop_once` (pal/linux/xfs_buf.c, next to `cluster_passenger_skip`) drops the next N claimed free sectors (`P-FREEPUB-INJECT-DROP`) for `tests/freepub_platter_home_inject.sh`. Pitfall: `flush_seq != durable_seq` does NOT mean "the buffer slot is our unlanded image" — drop paths roll it back; never use it as a buffer-vs-platter detector.
- 0.39.7 (sess431, `docs/free-publish.md` "0.39.6 → 0.39.7"): `mxfs_pubob_discharge` keeps CHAIN provenance — an UNLINK-kind store entry with `chain > 0` reverts to `CHAIN_LIVE` (`P-FREEOB-CHAIN-KEPT why=removed|flushed`) instead of being dropped. Invariant: chain provenance ("every live image at home is one of this node's own lives") must outlive the UNLINK obligation of a chained life; dropping the entry at `xfs_iunlink_remove` (tmpfile linkat) or at the unlink-conversion completion minted a fresh `chain=0` entry at the ifree and P55C called the node's own older life FOREIGN (s439: 41/41 FOREIGN, 72 DISKLIVE). Store-entry kinds: UNLINK(0) → FREE_PENDING(1) → FREE(2); CHAIN_LIVE(3) = recycled-under-same-tenure OR unlink-discharged chained life; only FREE-kind discharges (home-free/foreign/superseded) drop.
- 0.39.6 (sess431, `docs/free-publish.md` "0.39.5 → 0.39.6"): (a) `xfs_iflush` copy-in success clears `MXFS_IF_PUB_SKIPPED` (with `CLMERGE_HIT`) — skip verdicts are per staged image; a P235 skip on a re-logged landed slot leaked the flag past that round's iodone (`xfs_buf_inode_iodone` `continue`s at `!ili_last_fields` BEFORE the PUB_SKIPPED handling) into the next copy-in's completion (P187 re-arm, durable not advanced). (b) P55C classifies the home on a coherent platter read (`mxfs_dbg_disk_di_mode_coherent`) whenever `flush_seq != durable_seq` — the buffer slot then holds THIS node's own staged image, not the platter (`P55C-HOME-PLATTER`, `P55C-HOME-READ-FAIL` → strike + `-EAGAIN`). Pitfall: `dip` in `xfs_iflush` is the buffer image; after a copy-in it is never evidence of what is on the platter.
- 0.39.5 (sess431, `docs/free-publish.md` "0.39.4 → 0.39.5"): the FREE-publication CLAIM. `struct xfs_inode i_mxfs_freepub_{bp,epoch,seq,gen}` minted in `xfs_iflush` when P55C sanctioned the copy-in; `mxfs_freepub_claim_valid(ip, bp, pag, img, &why)` / `mxfs_freepub_claim_clear(ip, why)` in `xfs_mxfs_dlm.c` (after `mxfs_ag_pubwrite_end`). Invariant: `mxfs_iflush_cluster_merge_dirs`' protection mask (RELFLUSH | EX+same-tenure | PR-dir-in-AIL) does NOT cover a P55C free slot (inode-NL, AG-tenure sanction) — without the claim the sess62 restore arm overlays the platter's live predecessor over the staged free image and the free never lands (s437: 56/123 P-DIALLOC-DISKLIVE). The merge keeps a valid claim (`P-FREEPUB-KEEP`), the partial-write mask in `pal/linux/xfs_buf.c` publishes it at NL as its own authority class (`P-FREEPUB-WRITE`), a stale claim fails closed via `mxfs_clmerge_ledger_rollback` `cls=freepub-stale` (drops `PUBOB_FLUSHED`). Cleared at iodone durable / PUB_SKIPPED / abort / discharge / recycle. Pitfall: any new "slot authority" predicate in the merge or the mask must consult the claim, never `is_free`/mode.
- 0.39.3 (D-0351 containment, `docs/free-publish.md` "Containment"): `xfs/libxfs/xfs_ialloc.c` dialloc is TWO-PHASE in the cluster — `xfs_dialloc_ag(..., pick_only)` returns a reserved candidate with the trees untouched; `mxfs_dialloc_two_phase()` drops the AGI, `mxfs_dialloc_validate_candidate()` (pubob store first, then `mxfs_dbg_disk_di_mode_coherent` plain LUN read), re-reads the AGI and re-enters with `rs->validated` (cursor at the candidate's chunk; `pick_in_rec` takes exactly it). LIVE image → `P-DIALLOC-DISKLIVE`, `pag->pag_disklive_q` (xarray agino→gen, no expiry, `xa_init` in `xfs_perag_alloc`, `xa_destroy` in `xfs_perag_uninit`), re-pick; all-quarantined → `-EUCLEAN` (`P-DIALLOC-ALL-QUARANTINED`), never ENOSPC/dirty cancel. `struct mxfs_dialloc_resv` gains `validated/quarantined/disklive/restarts`. Injector: `tests/dinode_inject.py` + `tests/dialloc_disklive_inject.sh`.
- 0.39.2: the publication gate (P86 audit + bounded deferral + P-FREEOB-REFUSED fail-closed) is `mxfs_ag_release_publish_gate(pag, path)`, called from BOTH `mxfs_dlm_ag_bast_work_fn` (inline unlock) and `mxfs_dlm_ag_release_work_fn` (deferred unlock — previously un-gated: FREE obligations crossed it, `P-FREEOB-CHAIN-BROKEN`, FOREIGN clusters). `mxfs_pubob_unlock_census(pag, path)` prints `P-FREEOB-XRELEASE` at every `mxfs_v5_dlm_ag_unlock` site when a FREE/FREE_PENDING entry is still open. `mxfs_pubob_recycle(mp, ip, deadshell)`: CHAIN_LIVE + deadshell create = `P-FREEOB-CHAIN-SUPERSEDED` (peer freed our chained life). Pitfall: the deferred release path is taken whenever AG-metadata writeback is still pending at the release COMMIT — anything that must run before EVERY unlock has to be in the gate helper, not in the bast worker.

## sess432 (0.39.10-0.39.12, D-0353) — single-node false-fresh discard, fail-closed invalidation
- `xfs/libxfs/xfs_ialloc.c` dialloc verify (`ino == parent || !xfs_verify_dir_ino`): now prints
  `P-DIALLOC-VERIFY` with every input of the verdict (agino range, sb inums, quota inos, both
  sub-verdicts).  It named the D-0353 rejection as `ino == parent` = double allocation.
- `xfs/libxfs/xfs_ag.h`: `pag_mxfs_grant_single` (bool) — the current AG grant came from the
  CAW single-node fast path (`MXFS_GAUTH_SINGLE_NODE`, no epoch).  Set at the publish site in
  `__mxfs_ag_dlm_lock`, cleared at every `pag_mxfs_grant_epoch` clear (handoff commit, unmount
  release, join-barrier lineage reset).
- `xfs/xfs_mxfs_dlm.c`:
  - P243 epochless-hint guard (fast + slow path): keeps a SINGLE_NODE-provenance hint while
    `mxfs_v5_dlm_is_single_node()`; otherwise drops it (`src=single-era-ended-*`).
    Knob `single_era_hint_keep` (diag, default 1) re-creates the old drop.
  - `mxfs_agmeta_buf_unlanded(bp)`: pinned | bli DIRTY | bli IN_AIL | `_XBF_DELWRI_Q`.
  - `mxfs_dlm_agmeta_preflight(pag, &daddr, &ops)`: dry walk, no staling.
  - `mxfs_dlm_invalidate_ag_meta(pag, ag_preserved)`: `ag_preserved == NULL` = fresh-acquire
    caller → preflight; any un-landed AG-meta → `P131-INVAL-REFUSED` + `xfs_force_shutdown`,
    NOTHING staled.  Non-NULL = census caller (join barrier / recovery barrier) → the locked
    branch RETAINS un-landed buffers (`ag_pres++`) instead of staling them (was: unconditional
    stale = the silent lost update).  Knob `agmeta_inval_enforce` (default 1).
  - P130-FALSE-FRESH (fresh CAW grant over an open lineage) is enforced:
    `P130-FALSE-FRESH-REFUSED` + shutdown.  Knob `false_fresh_enforce` (default 1).
- INVARIANT: local committed AG metadata is landed before the CAW authority is yielded; a
  fresh acquire that finds un-landed local AG metadata stops loudly.  Never add a
  log-force/AIL-push to the fresh-acquire path (a genuine fresh grant may follow a peer's
  writes — landing ours would clobber theirs; RULE-5 ruling sess432).
- Pitfall: `mxfs_dlm_invalidate_cached_views` (join flush) relies on the RETAIN behaviour to
  loop its destage rounds; making the census path shut down would break the single→multi join.
- Tests: `tests/lone_mount_create.sh <label> [node] [nodes] [fixed|p130|p131]`.
  Docs: `docs/ag-metadata-coherency.md` (sess432 section).  Ledger: D-0353, D-0354, D-0355.

### sess435 (0.41.2 / 0.41.3)
- `xfs/xfs_log.c mxfs_log_head_past_boundary()` (0.41.2): after the P308 boundary unmount record, advances `ail_head_lsn` to `xlog_assign_lsn(l_curr_cycle, l_curr_block)` in checkpoint order (head → `xfs_ail_update_finish(NULLCOMMITLSN)` → `xlog_grant_return_space`). Reason: `ail_head_lsn` is written only by `xlog_cil_ail_insert`/recovery seeding; a record written through `xlog_write` never moved it, so the P308 cut was not in force (measured 'did NOT advance', 0.41.1). Verified: adopted-dirty lone crash arm, B's foreign window starts at the boundary.
- `xfs/xfs_trans_buf.c xfs_trans_read_buf_map` (0.41.3): `P378-TRANS-READ-FAIL daddr/bb/nmaps/ops/err/dirty/flags/caller` before the META_IO_ERROR shutdown (D-378 item 1).

### sess441-442 (0.47.0 / 0.48.0) — bootstrap-adopted own log
- `xfs/xfs_log.c xfs_log_mount`: `mp->m_mxfs_bootstrap_adopted` (set in
  `xfs_super.c` from `mxfs_v5_dlm_bootstrap_adopted`) ⇒
  `XLOG_MXFS_BOOTSTRAP_ADOPTED` (never `ADOPTED_SLICE`): FULL own-log replay
  of a certified victim's slice, authority-evaluated per transaction from the
  ESCROWED descriptor; intents ARE applied (`xfs_log_recover.c` skips the
  untrusted-replay intent census for this mode).  After `xlog_recover`: any
  untagged/malformed skip, rman invalid/mutated, census lost or shadow
  mutation ⇒ `P-BOOT-ADOPTED-REFUSED` + `mxfs_v5_dlm_bootstrap_k_refused`
  (typed, terminal for the term); a torn K (`-EFSCORRUPTED/-EUCLEAN` from
  `xlog_recover`) is typed too; any other error leaves the term resumable.
  `norecovery` on an adopted slice is refused (`P-BOOT-ADOPTED-NORECOVERY`).
- `xfs/xfs_mxfs_dlm.c` mount-recovery barrier: a terminal foreign slice under
  a bootstrap term calls `mxfs_v5_dlm_bootstrap_terminal` and ABORTS the
  barrier immediately (sess442); at the end `mxfs_v5_dlm_bootstrap_finish`
  (K_REPLAY_OK → completeness → READ KEYS reconcile incl. own key present →
  RECOVERY_COMPLETE).
- `xfs/xfs_log_priv.h`: `XLOG_MXFS_BOOTSTRAP_ADOPTED` (bit 7),
  `xlog_is_mxfs_bootstrap_adopted`, folded into `xlog_is_mxfs_untrusted_replay`.

## sess444 (0.51.0) — ICREATE under the authority gate: SYNCINIT invariant
(docs/whole-cluster-restart.md §6.9; ledger
D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510.)  ICREATE replay re-inits
WHOLE clusters, which can clobber an inode a peer modified since under inode
authority (no cross-slice LSN order exists); the old strict allowlist made it
taint every create txn instead (the chain-29 terminal-slice root).
- `xfs/libxfs/xfs_log_format.h`: `struct mxfs_icreate_trailer {magic MXIC,
  flags}` + `MXFS_ICL_F_SYNCINIT` — the WRITER-TIME proof, formatted
  contiguously after `xfs_icreate_log` (upstream replay ignores it).
- `xfs/xfs_icreate_item.{h,c}`: item carries `ic_mxfs`; `xfs_icreate_log`
  now RETURNS the item; `xfs_icreate_mark_syncinit`; `mxfs_icreate_record_flags`
  (iov_len ≥ struct+trailer && magic).  Pass 2: SYNCINIT record → FUA-read each
  cluster (`mxfs_pal_scsi_read_fua_bdev`) and verify every dinode
  (magic/v3/di_ino/meta-uuid/CRC): all verify → `P-ICREATE-VERIFIED`, SKIP
  (never written); any fails → `P-ICREATE-VERIFY-FAIL` + `P-ICREATE-REFUSE`
  -EFSCORRUPTED (never re-init without per-cluster authority — ruling); no
  trailer on an MXFS mount / untrusted log → refuse; only a non-MXFS trusted
  log keeps upstream's blind init.
- `xfs/libxfs/xfs_ialloc.c` `xfs_ialloc_inode_init`: P133 sync FUA init now
  runs on EVERY mxfs mount (`syncinit = m_mxfs_dlm && v3inodes`), failure →
  `P133-ICLUSTER-SYNCINIT-FAIL`, `xfs_trans_binval` + error (txn already dirty
  → cancel shuts down: fail closed); success on all clusters → stamp.
- `xfs/xfs_log_recover.c` `mxfs_report_replay_authority`: ICREATE no longer
  taints in the item loop; judged after it from AG-class siblings with
  `res == icl_ag`: SYNCINIT && no refused sibling && (any APPLY → APPLY, all
  REDUNDANT → REDUNDANT) else REFUSE+taint.  `P-ICREATE-AUTH` line; P273
  summary `icreate=apply/redundant/refused`.  Pass-2 REDUNDANT skip
  (`P227-FR-REDUNDANT-SKIP`) now covers ICREATE too (never even the verify
  read — a successor may have reused the extent).
- Stage C of item 5f (composite-K evaluator, `MXFS_SHADOW_LIN_MAX` lineage
  pairs, `P-BOOT-K-COMPOSITE[-EVAL]`) applied this session (drafted sess443).
- **Slice-snapshot prefetch (0.52.0, RULE 0; ruling `docs/rulings/frstab-pipeline-across-slices.md`):**
  `mxfs_xlog_slice_snapshot` split into `mxfs_slice_stabilize(mp, targ,
  logBBstart, bytes, slot, ...)` (the D-527 proof: pass 0 + N sleep-separated
  compares, own 45 s deadline) and a consumer.  `mxfs_xlog_snap_prefetch(mp,
  slot)` runs the proof for the NEXT victim on `system_unbound_wq` (one
  in flight per module, `mxfs_snap_pf` + mutex); the barrier
  (`xfs_mxfs_dlm.c`, before `mxfs_xlog_recover_foreign_slice`) calls it for
  the next `todo` slot; the consumer adopts the buffer only after the
  worker COMPLETED and only for an exact {mp, slot, logBBstart, bytes, targ}
  match, else proves inline (`P-FRSTAB-PREFETCH-FAILED`).  Cancelled in
  `xfs_log_unmount`.  Knob `mxfs.fr_stab_prefetch` (default 1).  Crediting
  certificate age or dropping a pass was STOP-SHIPped.

### 0.53.0 — BLFT re-type no longer voids the authority token (sess445, D-0512)
`xfs_dir2_sf_to_block` (data_init logs as DIR_DATA, block_init re-types
DIR_BLOCK) used to emit a class=NONE/INCOMPLETE image → the slice holding
the conversion was refused on foreign replay (chain 35 point 13: bootstrap
REFUSED).  `xfs_trans_buf_set_type` now calls `mxfs_bli_auth_note_retype`;
the proof is re-established at the next dirty (see pal.md / docs/dlm-protocol.md).
Sibling same-txn re-types: `xfs_dir2_leaf_to_block` (block_init on a DATA
buffer), `xfs_dir2_block_to_leaf` (xfs_dir2_leaf.c:609), `xfs_dir2_node.c:909/924`.

### 0.53.0 — slice-snapshot prefetch is a depth-N ring (sess445, D-0511)
`xfs_log_recover.c`: `mxfs_snap_pf[MXFS_SNAP_PF_MAX=8]`, knob
`fr_stab_prefetch` = depth (default 3); `mxfs_dlm_mount_recovery_barrier`
arms the next `depth` todo victims before each replay.  The 0.52.0 single
entry was dropped by the next arm (30/31 inline).  See
docs/foreign-replay-slice-snapshot.md "Prefetch ring".

## sess446-447: quarantine namespace gate (0.53.1) and D-0514 replay-worker instrumentation (0.53.2)

- **D-0515 fix (0.53.1)** — `mxfs_quar_gate_op(ip, op)` (`xfs/xfs_inode.h`, next
  to `mxfs_inode_incarn_estale`) prints `P240-QUAR-NSOP-REFUSE op= ino= rc=` and
  returns the incarnation/quarantine gate's error (-ESTALE / -EIO).  Called at
  EVERY namespace entry in `pal/linux/xfs_iops.c` (create/mknod/mkdir/tmpfile,
  lookup, ci_lookup, link, unlink/rmdir, symlink, rename ×4 inodes, readlink,
  setattr, update_time) BEFORE any transaction, plus clean-transaction
  backstops: `xfs_trans_alloc_inode/_ichange/_dir` (`xfs/xfs_trans.c`, after the
  ilock, cancel+unlock before ijoin), `xfs_create` (after the first ilock(dp),
  before `xfs_dialloc` dirties; ino=0 + out_trans_cancel) and `xfs_rename`
  (after `xfs_lock_inodes`).  Root: the DLM entry hook's P240-QUAR-REFUSE is a
  void refusal — `xfs_ilock` still takes the local lock and the namespace op
  committed lock-less on two nodes (chain 48 measurement).
- **D-0514 instrumentation (0.53.2)**, `xfs/xfs_mxfs_dlm.c`: the foreign-replay
  work item is ONE `work_struct` (`m_mxfs_foreign_replay_work`); its tail sweeps
  victims' AGI unlinked buckets INLINE (`mxfs_survivor_sweep_slot`), and a sweep
  step that waits on a grant held by a newer, still-undetected victim blocks
  that victim's replay (queued behind the same work_struct).  Provenance lines:
  `P-FREPLAY-NOTIFY slot= qret= busy=RUNNING|+PENDING inv=` (dead-node notify),
  `P-FREPLAY-ENTER/EXIT inv=` (per instance), `P-FREPLAY-PHASE inv= phase=
  INLINE-SWEEP(-DONE)`, `P97-SWEEP-STEP agno= step=read_agi|iget|inodegc_flush
  ms=` (>= 1 s), `P97-SWEEP-START ... inv= dead_slots=`.  TEST knob
  `dbg_sweep_hold_ms` (module param): park the sweep after SWEEP-START until a
  NEW dead slot is notified (budget 4×), then hold N ms (`P-DBG-SWEEP-HOLD`,
  `-END`).  Planned fix (0.53.3): no inline sweep in the replay work fn — the
  reap worker (`mxfs_reap_worker`, separate delayed work) already re-drives the
  replay worker first and sweeps `m_mxfs_sweep_pending_slots` under the
  `bitmap_empty(dead_slots)` guard.

## sess447: token enforcement default-on (0.54.0) + F4 census truth probe

- `xfs/xfs_mxfs_dlm.c`: `int mxfs_foreign_replay_token_enforce = 1;` — the
  shipped default is now ENFORCE.  The setter is unchanged (fails closed on
  F2/release_proof/icluster for runtime re-arming); the mount-time validator
  in `pal/linux/xfs_super.c` (see pal.md) is the decisive admission.  The
  sess197 release gate (`replay_gate_enforce`, F1/F3/F4 READY macros = 0) is
  NOT a prerequisite for this default (RULE-5 ruling sess447): it governs
  tenure release, not the APPLY verdict, which rests on the fence-time
  manifest snapshot + v3 lineage + RELMARK + di_changecount.
- D-0514 fix (0.53.3): `mxfs_dlm_foreign_replay_work_fn` no longer sweeps
  inline (`P-FREPLAY-PHASE phase=SWEEP-DEFERRED`); `mxfs_reap_worker` does
  every bucket sweep.  Closed F&V sess447.
- F4 proviso probe: `mxfs_f4_census_dump` now classifies each open record at
  a walked-clean dir release from the buffer itself (`xfs_buf_incore`
  TRYLOCK; bli DIRTY / IN_AIL / delwri / f4 gens): `P285-F4-REC ...
  truth=REAL-UNSUBMITTED|GEN-OPEN-NOT-DIRTY|STALE-RECORD|NOT-INCORE-OR-BUSY|
  BUFFER-GONE`.  REAL-UNSUBMITTED at a RELMARK-publishing release would be
  the "F4 forges a permissive RELMARK" stop-ship — measured by chain 55's
  `f4truth` histogram.

## sess448 (0.55.0) — ICLUS clean-release certificate (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY path)
- `struct mxfs_iclus` (xfs_mxfs_dlm.c ~54427) gains `auth_lineage` (installed
  in `mxfs_iclus_lock` from `lg.resource_lineage` together with `auth_epoch`,
  cleared in `mxfs_iclus_release_done_locked`) and the irrevocability record
  `relmark_lineage/relmark_epoch` (stamped in `mxfs_iclus_disk_release` before
  the marker publish, never cleared).
- `mxfs_iclus_auth_snapshot_locked` now exports `gres->resource_lineage`
  (routed inodes' tokens become lineage-bearing), returns non-proving on a
  zero lineage, and refuses the marked tuple
  (`P-RELMARK-ICLUS-REINSTALL-REFUSED`) — covers BOTH the fast-path admit and
  the CAS-established path since both go through the snapshot.
- `mxfs_iclus_disk_release`: after the step-6 enforcement gate and before
  `mxfs_v5_dlm_iclus_unlock_gen`, publishes
  `mxfs_relmark_publish(mp, MXFS_AUTH_CLASS_INODE, base, lineage, epoch,
  "iclus_disk_release")`; failure counted (`P-RELMARK-ICLUS-UNMARKED`), replay
  refuses.  New public counters `mxfs_relmark_iclus_counters(marked, failed,
  reinstall_refused)` (xfs_relmark_item.h), shown in the `relmark` debugfs
  block as `iclus_marked/iclus_failed/iclus_reinst_ref`.
- PITFALL: the marker identity MUST equal the token identity (class INODE,
  resource = cluster base) — never emit a different class here without
  changing the capture in `pal/linux/xfs_buf_item.c` (~762) atomically.
- F3 truth-up (sess448): ICLUS defers on every failed-proof exit; the INODE
  class (`mxfs_relbar_close_or_defer` ~15804) CASed unproved on a flush-ticket
  failure — reachable only with `fua_disable=0` (D-0516).  **sess449 / 0.55.1:
  the INODE class now defers too** — `P228-RELBAR-TICKET-DEFER`, DEMOTING,
  `mxfs_relbar_deferred++`, return true; cause `TICKET_STALE` via
  `mxfs_inode_defer_causes`.  Verified only by the forced stage-10 fault
  (`tests/relgate_fault_inject.sh inode`) until fua_disable=0 is admissible.
  `MXFS_RELGATE_F3_COMPLETION_PROOF_READY` stays 0.
- Design: docs/dlm-protocol.md "Cluster (ICLUS) certificate".  Ruling:
  `docs/rulings/iclus-relmark-certificate-and-sequencing.md`.

## sess456 — knobs and facts recorded while working D-0517
- New module param `dino_clobber_check` (`xfs/xfs_mxfs_dlm.c`, next to `dir_perf_probe`) + `atomic_t mxfs_dino_clobber_n`; consumed in `pal/linux/xfs_buf.c` (P-DINO-CLOBBER).
- `mxfs_iclus_make_durable` (~55580) is a PASSIVE settle: log force + AIL push + device flush + polling `xfs_buf_incore`; it never writes the cluster itself (an active variant was reverted for a cross-node ABBA deadlock). `mxfs_iclus_lock` / authority install never invalidates the cached cluster buffer; only `mxfs_dlm_iget_miss_reload` (~1877, iget-miss ladder) clears `XBF_DONE|_XBF_FUA_FRESH`.
- Foreign-replay print caps: `P227-TOKEN` 400 per boot (`mxfs_tokdet_n`, `xfs_log_recover.c` ~3724); `P77-FRINODE` (inode-item changecount verdict) prints only with `mxfs.instr=1`.

## sess459 — buffer-image on-disk-LSN veto is cross-slice (D-0517 root, D-0521 filed)

- `pal/linux/xfs_buf_item_recover.c xlog_recover_buf_commit_pass2` kept upstream's
  `xlog_recover_get_buf_lsn(bp) >= current_lsn => skip` on foreign replay. The stamp
  (bb_lsn/agi_lsn/agf_lsn/dir lsn/sb_lsn) is the LAST WRITER'S slice LSN; per-node
  slices have independent numbering, so the test dropped token-ADMITTED AGI/inobt/
  finobt images whenever the victim died holding an AG whose blocks were last flushed
  by a numerically higher slice (chain 80 lap 2: AG 6 stamped 0x100001183 by slice
  31, slice 6 replaying 0x100000e48/e4c; post-replay stamp unchanged = never written).
  The inode-item path had already replaced the same test with `di_changecount`
  (`xfs/xfs_inode_item_recover.c:397-440`), so a free's core applied while its
  inobt/bucket half was lost => chk `P-ALLOC-FREE-CORE` (a FREE half-lost, not a
  create half-applied). DINO buffers never hit the test (`recover_immediately`).
- Fix 0.61.4 (RULE-5 ruled, `docs/rulings/d0517-buf-lsn-skip-bypass-stop-ship-6-items.md`):
  `xlog_recover_item.ri_mxfs_class` is stashed beside `ri_mxfs_verdict` in
  `mxfs_report_replay_authority`; pass 2 bypasses the veto ONLY when
  `xlog_is_mxfs_untrusted_replay() && verdict == MXFS_RI_VERDICT_APPLY && class in
  {MXFS_AUTH_CLASS_AG, MXFS_AUTH_CLASS_INODE}` (`goto mxfs_apply`); SB class, untagged,
  dquot and every trusted recovery keep upstream. Counters `l_mxfs_buflsn_skips` /
  `l_mxfs_buflsn_overrides` print on `foreign replay of slot N complete (...)`; per
  decision line `P-FR-BUF-LSN ... verdict=SKIP|OVERRIDE-APPLY tokverdict= class=`.
  Invariant relied on: APPLY = held at death per the fence-time manifest + live CAW
  bit with unchanged lineage (P-RMAN live check), dead slot zeroed only after
  P163-RECOVERY-COMPLETE => no successor writer; in-slice replay is in LSN order so
  re-application is idempotent.
- Exposure NOT covered by the fix: a PASS-1 own-stamp reclaim (`xfs/xfs_log.c:642-698`,
  `xfs_mxfs_dlm.c adopted_slice_full_replay` comment) replays a dirty own slice as a
  TRUSTED log (no tokens, upstream LSN test, inode path falls back to di_lsn) —
  ledger D-OWN-SLICE-PASS1-RECLAIM-REPLAY-CROSS-SLICE-LSN-VETO-0521.
- Token class at log time: `pal/linux/xfs_buf_item.c` ~1000-1045 (SB by b_ops, AG when
  `mxfs_buf_ag_authorized && pag grant epoch`, INODE via `mxfs_ownauth_measure` only
  for MXFS_OWNAUTH_DURABLE).

### Intent/done census — item 5 increment 1 (sess461, 0.62.0)

`xfs/xfs_mxfs_icensus.{c,h}` (D-FOREIGN-SLICE-INTENTS-ABANDONED).  Called from
`xfs_log_recover.c` ~4611 BEFORE the whole-txn verdict switch, now with
`trans->r_mxfs_verdict`.  Per open entry it keeps the EFI's extents (copied out of
the native/32/64 layouts; `xfs_verify_fsbext` on each; total bounded 65536 =>
overflow/fswide), the intent txn verdict and — when a done rides in a NON-admitted
txn — that done's verdict (`ambiguous_done`, entry stays open).  "Admitted" =
`MXFS_TXNV_ADMIT|UNTAINTED|SNLOCAL` (inode items keep their changecount gate; ruling
sess359).  `mxfs_icensus_classify()` (once per log) applies the ruling SS7 matrix +
an overlap sweep across all RECOVER candidates -> `P226-ICENSUS-CLASS` per entry,
`P226-ICENSUS-SPLIT recover= recover_mask= quarantine= q_mask= q_fswide=`.
`xfs_log.c` ~1362 calls it inside the terminal predicate and prints the split on
`P226-FR-INTENTS-UNDISCHARGED`; the disposition is UNCHANGED (any open => terminal).
Only EFI can be RECOVER: mkfs sets FINOBT only, so no other intent class exists on
disk; AGFL frees share the EFI encoding (`xfs_extfree_item.c:807-816`).  Later
increments (descriptor `obl_ag_mask` freeze, generation-bound transfer,
recovery-exclusive grant, direct completion at `OBLIGATIONS_DONE`) are laid out in
`docs/dlm-protocol.md` "Item 5" and the sess461 GPT ruling memory.

## sess462 (2026-09-02, 0.63.0) — item 5 increment 2: obligation evidence + home flush

- `xfs/xfs_log.c mxfs_xlog_recover_foreign_slice`: after a CLEAN shadow replay
  the device is flushed (`blkdev_issue_flush`, `P226-FR-HOMEFLUSH`) BEFORE the
  verdict/ladder — the IMAGES_REPLAYED milestone must attest home-written
  images because a takeover successor never re-replays past it (RULE-5
  ruling STOP-SHIP 1; the ladder's post-purge flush was too late).  A flush
  failure is a retryable error (reason NONE).  The terminal predicate now
  exports the census RECOVER extents into the verdict (`obl_count`,
  `obl_ag_mask`, `obl_list` kvmalloc'd, `q_*` split, `obl_lost`);
  `mxfs_freplay_verdict_free()` releases the list.
- `xfs/xfs_mxfs_icensus.c`: `mxfs_icensus_export_recover()` copies the
  RECOVER entries' extents into `struct mxfs_recov_obl_ext` (dlm/recov_obl.h)
  — bounded at MXFS_RECOV_OBL_MAX_EXTENTS (3072), -EOVERFLOW beyond.
- `xfs/xfs_mxfs_dlm.c mxfs_freplay_publish_refusal` (now takes a non-const
  verdict and consumes its list): `mxfs_freplay_obl_evidence()` writes the
  list as TERMINAL evidence through `mxfs_v5_dlm_recovery_obl_write`
  (`P226-OBL-EVIDENCE`) and publishes the refusal with the record in the same
  CAS (`..._publish_refusal_obl`); a failed/lost list publishes WITHOUT a
  record (`P226-OBL-EVIDENCE-FAIL/-LOST`).  Disposition unchanged: any open
  entry still refuses terminally (ruling: no flip before increments 3-4).
- Verification: `tests/d_intents_undischarged_verify.sh burst` (+ chain 93
  `tests/sess462_chain93_intents_evidence_verify.sh`).

## sess464 (2026-09-02) — symmetric directory sharding, stage 1 code (UNWIRED)

- New `xfs/xfs_mxfs_dirshard.{h,c}` + `include/mxfs/mxfs_dirshard.h`, NOT in
  Kbuild yet (written during the chain-89 source-edit freeze; wiring list =
  `docs/dir-sharding.md` "Stage 1 wiring checklist", 16 steps).  Owner
  defect D-32NODE-SHARED-DIR-CREATE-PACE (board face D-401), on the critical
  path of D-FOREIGN-REPLAY-UNGATED-IMAGES.
- Shape (sess463 ruling + sess464 S3 amendment): visible PARENT directory
  (di_flags2 bit 61) carries a 12-byte inline ROOT xattr `mxfs.dirshard` =
  locator {holder ino, gen}; the HOLDER inode (S_IFREG, di_flags2 bit 60
  CONTAINER, UNLINKABLE, nlink 1) owns ONE fsblock holding the manifest as a
  logged metadata block ('MSHB' header + 'MSHD' manifest, `mgen` +1 per
  write, own `mxfs_dirshard_buf_ops`, BLFT 30); N ∈ {16,32,64} shard
  CONTAINER directories (bit 60, S_IFDIR, `..` = parent, nlink baseline 2)
  referenced only by the manifest.  Routing: SipHash-2-4 of the exact name
  bytes under the manifest key, index = hash & (N-1).
- Lock order: parent ILOCK_SHARED (= DLM PR, the "pin") → holder (block
  access only) → exactly ONE shard (PR lookup/readdir, EX create/unlink) →
  target inodes → AG DLM/AGI/AGF.  Parent ILOCK_EXCL (= DLM EX) is the
  barrier: lifecycle, rmdir, parent-core metadata, fsync, repair.  The
  resolver runs BEFORE transaction setup; ordinary ops then call the
  UNCHANGED `xfs_create`/`xfs_lookup`/`xfs_remove`/`xfs_readdir` with the
  shard as the directory inode (`args.pip = shard`).
- Lifecycle = one commit per step: alloc_parent (TMPFILE dir on the AGI
  unlinked list + dir_init + holder + block init + locator), per-container
  alloc + manifest append (+COMPLETE at N), publish (createname in the
  grandparent, bumplink, parent nlink 0→2, iunlink_remove under the AG DLM
  bracket, PUBLISHED).  Only xfs_dialloc's chunk roll can split a step, and
  it precedes every dirtying of ours; the one torn shape (unlinked PARENT
  without locator) is reaped as a plain directory.
- Deletion/inactivation `mxfs_dirshard_inactive_parent`: containers (bit
  cleared + nlink 0 + iunlink, one txn each; "already gone" on gen mismatch)
  → holder (binval + bunmapi + iunlink) → caller frees the parent.
  Restartable at every commit; holder-gone means all containers went before.
- Cross-slice replay of the manifest block: rides the D-0517 INODE-class
  token verdict (`mxfs_buf_derive_owner` must read `blk->parent_ino` as the
  authority owner — wiring step 9) plus an `mgen` veto (step 8).
- Stage-2 Model A: child directories under a sharded parent, rename, link,
  symlink, tmpfile, dir fsync → `-EOPNOTSUPP`; ioctls
  `MXFS_IOC_DIRSHARD_MKDIR` (creates + publishes) and
  `MXFS_IOC_DIRSHARD_INFO` (state/N/entries/key/name→shard).  readdir uses
  logical cookies {7-bit slot << 32 | 32-bit local dataptr}, slot 0 = ./..,
  slot 65 = EOF.  stat: nlink = 2 + Σ(shard nlink − 2), size/blocks sums,
  max times, synthesized into kstat only.
- dcache: `xfs_mxfs_dentry.c` already re-looks the name up under the parent
  lock; routing that lookup through the resolver (wiring step 11) gives shard
  PR/BAST coherency with no event translation.

## sess465 (2026-09-02, 0.63.1) — FREE obligation store is entry-authoritative (D-0524)

- **Root of chain 88's 8/caw test1 fence** (not a false death): a lost update between
  `mxfs_pubob_free_commit` (ifree commit, FREE_PENDING→FREE) and the cluster-buffer write
  completion's `mxfs_pubob_discharge("flushed")` which re-called `mxfs_pubob_free_pending`
  because it read `i_mxfs_freeob==1` outside the lock. Entry stuck FREE_PENDING → the release
  gate (`mxfs_ag_release_publish_gate`, xfs_mxfs_dlm.c) deferred 20 s → `P-FREEOB-REFUSED`
  → `xfs_force_shutdown` → withdraw → fenced. Ledger D-0524 (critical).
- **New invariants** (`struct mxfs_pubob` gained `inflight`, `pred*`, `pending_epoch`):
  every transition decides on the ENTRY under `m_mxfs_pubob_lock`; `i_mxfs_freeob` is a mirror.
  `mxfs_pubob_free_pending(mp, ip, epoch)` is called at ifree START (xfs_inode.c, before
  `xfs_ifree`); `mxfs_pubob_free_commit` is unconditional after a successful commit;
  `mxfs_pubob_free_abort` restores the recorded predecessor; `mxfs_pubob_stage_flush` (copy-in,
  xfs_iflush_int) publishes the in-flight token {UNLINK,FREE}; `mxfs_pubob_discharge("flushed")`
  consumes it and ignores a mismatch (`P-FREEOB-FLUSH-STALE`); `mxfs_pubob_flush_abort` consumes
  it on `xfs_iflush_abort` / merge-overlay. Gate: FREE_PENDING + `MXFS_IF_FREE_COMMITTED` +
  matching tenure → promote (`P-FREEOB-PENDING-COMMITTED`); orphan/cross-tenure →
  `P-FREEOB-PENDING-FATAL` + immediate refusal (`pag_mxfs_freeob_fatal`, xfs_ag.h).
- **Knob** `mxfs.freeob_commit_delay_ms` (D-0524 fault injection). Sweep
  `tests/d0524_freeob_sweep.sh N`; chain `tests/sess465_chain94_d0524_freeob_race.sh`.
- Design doc: `docs/free-publish.md` "0.63.0 → 0.63.1".

## sess466 — directory sharding stage 1 wired (0.64.0)

- `xfs/xfs_mxfs_dirshard.{c,h}` is now built (Kbuild) and wired per
  `docs/dir-sharding.md` "Stage 1 wiring checklist" + "Stage 1 landed".
  Gates: `XFS_SB_FEAT_INCOMPAT_MXFS_DIRSHARD` (bit 29, xfs_format.h, in
  INCOMPAT_ALL), `XFS_DIFLAG2_DIRSHARD_{CONTAINER,PARENT}` (bits 60/61, in
  DIFLAG2_ANY), `XFS_BLFT_MXFS_DIRSHARD_BUF = 30` (xfs_log_format.h),
  `mp->m_mxfs_dirshard_env` (envelope flag), `MXFS_PROTO_GEN` 18.  Build
  checks in the module pin every value to `include/mxfs/mxfs_dirshard.h`.
- Inode: `ip->i_mxfs_dirshard` (manifest cache; NULL at alloc, kfree at free
  in xfs_icache.c).  Cache validity = (parent i_generation, parent
  `i_dlm_epoch`) — the epoch bumps on every grant loss, so no hook in the
  DLM release path was needed (deviation from checklist step 12).
- `xfs_inactive`: PARENT + nlink 0 → `mxfs_dirshard_inactive_parent()`
  BEFORE truncate/ifree; error leaves it on the unlinked list.
- `xfs_remove`: PARENT target → `mxfs_dirshard_isempty(ip)` under the
  already-held ip ILOCK_EXCL (barrier) before `xfs_dir_remove_child`
  (clean -ENOTEMPTY).  `xfs_dir_isempty` exported from libxfs/xfs_dir2.c
  for it.  Without this rmdir of a full sharded dir orphaned its files.
- `xfs_dinode_verify`: dinode-visible facts only (feature present, CONTAINER
  = DIR|REG, PARENT = DIR, never both; nothing about nlink).
- `xfs_mxfs_dentry.c mxfs_drevalidate`: PARENT → `mxfs_dirshard_lookup_ino`.
- `xfs_itable.c`: bulkstat skips containers.
- New module API: `mxfs_dirshard_isempty`, `mxfs_dirshard_lookup_ino`.
  Markers: P-DIRSHARD-CORRUPT / -STRANGER / -ABANDON / -INACTIVE / -GONE /
  -LOCATOR-DEFERRED; replay: P-DIRSHARD-MGEN-VETO / -MGEN-SHAPE.
- Lock order (module header): parent pin/barrier → holder (bmap only) → ONE
  shard → target inodes → AG DLM/AGI/AGF.  Resolver runs before trans setup.

## sess470 — dir-sharding stage 1: the three 0.64.6 rig roots (0.64.11/0.64.12, D-0526)

- **Every inode this module instantiates gets `xfs_setup_iops` before
  `xfs_finish_inode_setup`** (parent, holder, containers; success and release
  paths).  `xfs_icreate`/`xfs_inode_init` install only `xfs_setup_inode`; the
  vtables are the VFS caller's job (`xfs_generic_create` does it itself).  An
  S_IFDIR inode with `empty_iops` gets a `DCACHE_AUTODIR_TYPE` dentry and every
  walk into it returns -ENOTDIR — on the creator only (peers iget from disk via
  `xfs_setup_existing_inode`).
- **`mxfs_dirshard_iget` is a TRUSTED iget** (`mxfs_dirshard_iget_probe` +
  identity check).  `XFS_IGET_UNTRUSTED` on MXFS answers from an inobt read
  WITHOUT the AG DLM lock (`xfs_imap_lookup`), so peer-allocated members read
  as free (-EINVAL) — filed as its own class, D-0527 (NFS handles, bulkstat,
  P88 reap retry, orphan scan), probes `P-IMAP-UNTRUSTED-FREE/-NOREC` in
  `xfs/libxfs/xfs_ialloc.c`.  Probe answers: -ENOENT (free) / -ESTALE (other
  gen, or our gen with nlink 0) = GONE for the deletion path; our gen + linked
  + wrong flags = -EFSCORRUPTED, never cleared over.  `P-DIRSHARD-IGET-FAIL`,
  `P-DIRSHARD-LOAD-FAIL step=` name every failure.
- **sess473 (0.64.20, D-0533): the probe REVALIDATES a cached shell whose
  generation disagrees with the manifest** (`mxfs_dirshard_probe_revalidate`).
  The lock-less `xfs_iget(…, 0, 0, …)` returns a cache HIT for a number this
  node cached under a previous incarnation (freed and reused while it held no
  grant, so nothing BASTed it); the old gen then read as STRANGER (peer
  readdir EUCLEAN; deletion path "gone" -> bit cleared over a live container).
  Now: FUA-read the platter dinode (`mxfs_inode_disk_di_size`); read failure
  -> -EIO (`P-DIRSHARD-SHELL-READFAIL`); platter FREE -> gone; platter live
  with another gen (after one `mxfs_dlm_force_peer_flush`) ->
  -EFSCORRUPTED (`P-DIRSHARD-STRANGER-LIVE`, never gone); platter carries the
  manifest's gen -> in-place reload loop (`i_dlm_stale` src 28,
  `mxfs_dlm_reload_inode(expect_ftype)`), adopted only when !stale && gen &&
  ftype match (`P-DIRSHARD-SHELL-ADOPTED`), else -EBUSY
  (`P-DIRSHARD-SHELL-UNCONVERGED`; `mxfs_dirshard_iget` maps it to -ESTALE for
  readers, the deletion path keeps the set).  Bound 200x10 ms for readers,
  20x10 ms inside a transaction (`current->journal_info`) or on the teardown
  callers (`teardown=true`).  **API change**: `mxfs_dirshard_iget(mp, owner,
  ino, gen, expect_ftype, ipp)` and the probe take `expect_ftype`
  (`XFS_DIR3_FT_DIR` containers / `XFS_DIR3_FT_REG_FILE` holder) so a REG<->DIR
  reuse passes the reload's typeflip guard like a dirent ftype.  Diagnostic
  `P-DIRSHARD-SHELL` on every mismatch.  Review: `docs/history/gpt-review-d0533-probe-revalidate.md`.
- **sess473 (0.64.23, D-0535): every in-place attr-fork drop in the MXFS overlay
  ZAPS (`xfs_ifork_zap_attr`), never `xfs_idestroy_fork(&ip->i_af)`.** Destroy
  frees `if_data` but leaves `if_bytes`/`if_format`; a shell reused for a
  CREATE after a PEER freed the number (`mxfs_dlm_reset_inode_for_create`, the
  P-CR63 path — this node's `xfs_ifree`, upstream's only in-place drop, never
  ran) inherited `if_bytes=32` from its prior incarnation's locator xattr, the
  new incarnation's shortform create grew from it (its `ASSERT(if_bytes==0)`
  is compiled out), and the release drain's `xfs_attr_shortform_verify` shut
  the creator down.  Sites: reset_inode_for_create, the reload's pre-from_disk
  destroy (`xfs_mxfs_dlm.c`), `xfs_iget_recycle`'s adopt and dead-shell reset
  (`xfs_icache.c`).  Probe `P-RESET-STALE-AF` prints the inherited state.
  Rule: any code that re-initialises an in-core inode for a new incarnation
  must reset the attr fork the way `xfs_ifree` does.
- **sess473 (0.64.21/0.64.22, D-0534): the manifest BLOCK is refreshed at every
  read that starts from the holder's bmap** (`mxfs_dirshard_blk_refresh`, called
  by `mxfs_dirshard_manifest_load_slow` and `mxfs_dirshard_inactive_parent`).
  The block is a plain daddr-keyed metadata buffer; a REG holder's data buffer
  belongs to no inode-DLM release drain, so a peer that cached the previous
  set's block at a reused address got a buffer-cache HIT and the verifier
  refused it on the holder gen (`P-DIRSHARD-CORRUPT ... manifest-block
  reason=blk_owner aux=<daddr>`; the `aux` of that line is the daddr).  A clean
  cached copy is staled (`xfs_buf_stale` + clear `XBF_DONE`,
  `P-DIRSHARD-BLK-REFRESH`); one carrying our uncheckpointed modification is
  kept (`P-DIRSHARD-BLK-KEEP`, `mxfs_buf_has_uncheckpointed_mods`).  Rule for
  any future plain-buffer read in this module: it needs the same refresh unless
  it follows a load in the same operation.
- **`mxfs_dirshard_free_holder` removes the parent's locator in the SAME
  transaction as the holder's unlink** (parent joined; `xfs_attr_removename`
  shortform, deferred-intent guard).  Restart after a crash in that window
  takes the no-locator branch (`P-DIRSHARD-INACTIVE ... post-holder-free
  restart`).  `largs` is heap-allocated (frame-size warning otherwise: this
  function inlines into `mxfs_dirshard_inactive_parent` with its 800-byte view).
- **Containers have no IOLOCK holder**: `xfs_readdir` skips its
  `xfs_assert_ilocked(IOLOCK)` for `mxfs_is_dirshard_container(dp)` — the
  parent's i_rwsem (VFS, whole iterate_dir) + the parent pin (DLM PR) / barrier
  (DLM EX) are the container's namespace lock on every node.  588 WARNs on the
  0.64.6 cc laps otherwise.
- **Per-container pre-read settle** `mxfs_dirshard_shard_settle`: the sess97
  `mxfs_dlm_dir_consumer_refresh` + sess11 `i_dlm_stale` reload loop that
  `xfs_file_readdir` runs on the directory it reads — for a sharded parent
  that directory holds no entries, so it must run per shard, lock-free, before
  the per-format lock rule (`P95D-READDIR-WAIT ... shard=1`; symptom was
  `P173-RELOAD-SELFREAD ... rd_last=mxfs_dirshard_readdir ... reload deferred`).
- Docs: `docs/dir-sharding.md` "0.64.11" + "0.64.12".  Verification:
  `tests/sess470_chain109_dirshard_06411.sh` (frozen `sess470_frozen_06412`).
  Tool `tools/handle_probe.c` + `tests/d0527_untrusted_iget_peer.sh` measure
  the D-0527 gap through the NFS-handle path.

## sess467 — classless-image attribution instrumentation (0.64.1/0.64.2)
- `xfs/xfs_log_recover.c` shadow evaluator: P227-TOKEN now prints `blft=`;
  P227-TOKENSUM gains `classless_blft: tN=count` (classless images by BLFT)
  and `dino_none=/dino_agsib=` (classless DINODE_BUF iunlink images and how
  many have an AG-class VALID sibling naming the cluster's AG in the same txn —
  the ruling's shape-B census).
- `xfs/xfs_inode.c` xfs_inactive: the raw per-inode / cluster EX acquire now
  passes a `struct mxfs_grant_result` and logs `P-INACT-EX` (ino rc via_iclus
  resource epoch lineage kind gmode dlm_mode auth_state auth_epoch nlink
  local_unlink; 96 lines) — the tenure half of the shape-A census.  The raw
  lock still installs NO certificate (H1 for the classless bmbt images).

### sess468 — fix shape B (iunlink images AG-class) and the dirshard locator fork guard
- `pal/linux/xfs_buf_item.c`: `mxfs_auth_classify(tp, bip, mp, out)` (now takes the
  transaction).  New `mxfs_buf_iunlink_ag_authorized(tp, bip, mp, agno, blft)`: the
  `xfs_trans_inode_buf` form of an inode-cluster image (XFS_BLI_INODE_BUF, not
  ALLOC/STALE), dinode 0 verified, ino → this AG and this buffer daddr, and the AG's AGI
  joined in `tp` ⇒ class AG with the durable AG epoch.  Markers `P-IUNLINK-AGCLASS`,
  `P228-TOKCLASS iunlink_ag=`.  Ruling: `docs/rulings/intents-classless-images-fix-shapes-a-b-q3.md` (Q2).
- `xfs/xfs_log_recover.c` `mxfs_blf_parse_authority`: class-AG DINODE token without
  `XFS_BLF_INODE_BUF` ⇒ MALFORMED (`P-IUNLINK-AGCLASS-SHAPE`) — the AG class may only ever
  reach `xlog_recover_do_inode_buffer` (di_next_unlinked only), never the reg-buffer apply.
- `xfs/xfs_mxfs_dirshard.c` `mxfs_dirshard_locator_set`: INIT_XATTRS gives an empty
  EXTENTS attr fork; guard is now `xfs_attr_is_shortform()` before / LOCAL + empty dfops
  after (`P-DIRSHARD-LOCATOR-FORK`); `mxfs_dirshard_mkdir` names step-A failures
  (`P-DIRSHARD-STEPA-FAIL`).  See docs/dir-sharding.md "0.64.4 → 0.64.6".
- sess468 fix shape A (0.64.7): `xfs/xfs_mxfs_dlm.c` exports
  `mxfs_dlm_authority_gen_snapshot(ip)`, `mxfs_dlm_inactive_authority_install(ip, gres,
  gen_snap, routed, &why)` and `mxfs_dlm_inactive_authority_revoke(ip, gres)` (exact
  {kind,resource,epoch,lineage} match → revoke_locked).  `xfs/xfs_inode.c` xfs_inactive:
  `mxfs_inact_gres`/`mxfs_inact_cert` are function-scope; snapshot before each raw EX
  acquire (again after the -EDEADLK demote), install right after a successful acquire
  (`P-INACT-CERT ino installed try auth_state auth_epoch gres_epoch kind status routed`),
  revoke before the raw unlock at INACT-EXREL (`P-INACT-CERT-REVOKE-MISS` if the identity
  moved).  DEFER path keeps the certificate.  Doc: docs/authority-certificate.md.
- sess469 fix shape A REWORK (0.64.8-0.64.9, two RULE-5 STOP-SHIP rounds): `xfs/xfs_inode.h`
  adds `seqcount_spinlock_t i_mxfs_auth_seq` (every certificate tuple writer in
  xfs_mxfs_dlm.c brackets its stores; the token producer reads under it),
  `i_mxfs_auth_inact` (MXFS_INACT_CERT_NONE/ACTIVE/LOST/DEFERRED),
  `struct mxfs_inact_cert_id` and MXFS_INACT_REVOKED/_GONE/_FOREIGN,
  MXFS_INACT_CERT_REFUSE_MAX=8.  `mxfs_dlm_inactive_authority_install(..., &why, &cid)`
  reads the INSTALLED identity back; `mxfs_dlm_inactive_authority_revoke(ip, &cid,
  &state, &epoch)` returns REVOKED/GONE/FOREIGN — GONE and FOREIGN shut the fs down
  (P-INACT-CERT-GONE / -FOREIGN); `mxfs_inact_cert_note_loss_locked` (in revoke_locked and
  begin_release_locked) prints P-INACT-CERT-LOST while ACTIVE; `mxfs_dlm_inactive_authority_defer`
  marks DEFERRED at P128-INACT-DEFER; `mxfs_inact_cert_evict_check_locked` runs in mxfs_dlm_evict
  before begin_release (P-INACT-CERT-EVICT; malformed/still-ACTIVE → shutdown);
  `mxfs_defer_reap_cert_refused` counts refusals on the reap entry (`cert_refusals`);
  xfs_inactive aborts to `out:` on any refusal but UNPUB (P-INACT-CERT-REFUSED, >8 →
  P-INACT-CERT-REFUSED-ESCALATE + shutdown); `mxfs_inact_cert_report` prints
  P-INACT-CERT-TOTAL beside P228-TOKCLASS.  Knobs: module param `inact_cert_inject` 1-7
  (defined in pal/linux/xfs_super.c).  Harness: tests/inact_cert_arms.sh.
  **sess474 (0.64.24):** with `ifree_eager_durable=0` (default) EVERY free P128-INACT-DEFERs,
  so the sync INACT-EXREL revoke (knobs 2/5) never runs on the rig and the evict check is the
  COMMON retirement.  Knob 6 = evict check flips `i_mxfs_auth_incarn` on a DEFERRED certificate
  (cls=2 -> EVICT-CORRUPT + shutdown); knob 7 = `mxfs_dlm_inactive_authority_defer` returns
  without marking DEFERRED (evict cls=3 -> shutdown).  The foreign/gone arms set
  `ifree_eager_durable=1` for their rm to reach the sync path.
- sess469 D-0525 (0.64.10): `xfs/libxfs/xfs_inode_util.c` xfs_iunlink_pick_bucket uses the
  slot bucket whenever `m_mxfs_dlm` (the single_node term is gone: layout is a filesystem
  property, not live membership).  `xfs/xfs_inode.c` `mxfs_iunlink_find_bucket(pag, tp,
  agino, &bucket)` (raw 64-head walk; REQUIRES the AG DLM EX; P-UNLFIND-NOTENURE) — used by
  `mxfs_ifree_unlinked_preflight` for an unstamped member (P-UNLPRE-FOUND / -NOBUCKET →
  -EAGAIN), and the preflight gate no longer exempts single-node.  `xfs/xfs_mxfs_dlm.c`
  mxfs_orphan_scan: membership prewalk under AG EX BEFORE the iget; a post-iget member is
  stamped+reloaded only if on OUR slot bucket, else `MXFS_IF_FOREIGN_ZOMBIE` (bit 8, in
  XFS_IRECLAIM_RESET_FLAGS) → xfs_inactive `P-INACT-FOREIGN-ZOMBIE-SKIP` (no DLM, no free).
  P98-ORPHAN-SCAN-DONE gained own_reloaded=; P98-ORPHAN-MEMBER-LATE names the race case.

## sess471-472 (2026-09-02, 0.64.14-0.64.16) — four fixes around inactivation, recycle and untrusted iget
- **D-0529 (0.64.14)** `xfs/xfs_mxfs_dlm.c` mxfs_inact_cert_evict_check_locked: a DEFERRED
  inactivation certificate is cls 0 also when `MXFS_IF_FREE_COMMITTED` and
  `i_generation == (u32)(auth_incarn + 1)` — xfs_ifree bumps the generation by one, so the
  install-time incarnation never matched and every deferred-free evict shut the fs down
  (cls 2 → xfs_force_shutdown).  `auth_incarn` itself stays immutable (RULE-5 ruling).
- **D-0530 (0.64.14)** `xfs/xfs_mxfs_dirshard.c` free_container / free_holder: the container /
  holder is joined with XFS_ILOCK_EXCL, so commit/cancel release the ILOCK; the explicit
  second unlock (rwsem underflow, WARN in mxfs_ilk_note_unlock) is gone.
- **D-0531 (0.64.15, instrumented, root open)** free_holder checks
  `xfs_inode_has_attr_fork(parent) && xfs_attr_is_shortform(parent)` BEFORE the first dirty
  (P-DIRSHARD-LOCATOR-NOTSF, clean cancel) — the post-dirty refusal was a guaranteed dirty
  cancel → shutdown → node fenced.  mxfs_dirshard_inactive_parent prints
  P-DIRSHARD-INACTIVE-AF (forkoff / af_format / af_nextents / af_bytes) at entry.
- **D-0527 (0.64.15)** `xfs/xfs_icache.c` xfs_iget_cache_miss brackets the XFS_IGET_UNTRUSTED
  `xfs_imap` with `mxfs_ag_dlm_lock` / `mxfs_ag_dlm_unlock` on multi-node mounts (blocking
  class, nests for holders, cached release, ends before the inode DLM acquire).  Lock failure
  → P-IMAP-UNTRUSTED-AGLOCK-FAIL, returned as-is.  Read-only param `untrusted_imap_aglock_n`.
- **D-0532 (0.64.16)** new public `xfs_iunlock_nodlm(ip, flags)` (`xfs/xfs_inode.c`, wraps the
  static mxfs_iunlock_rwsems_raw) releases rwsems taken by `xfs_ilock_nowait` for ILOCK, which
  enters no DLM begin; xfs_iget_recycle uses it instead of xfs_iunlock (whose unconditional
  mxfs_dlm_ilock_end underflowed on a DEFERRED-freed corpse with a cached grant).
  Invariant to remember: **xfs_ilock_nowait(ILOCK) has no DLM begin; pair it with
  xfs_iunlock_nodlm, never xfs_iunlock**, on any inode that can still carry a cached grant.
- Certificate refusal codes `MXFS_AUTH_TRY_*` are in `xfs/xfs_inode.h:328-339` (7 = UNPUB,
  the ruling's approved classless case: a locally created, never-published inode).
- **D-0531 root (0.64.17/0.64.18)** — not the attr fork: the 0.64.12 guard in
  mxfs_dirshard_free_holder tested `!list_empty(&tp->t_dfops)` AFTER xfs_bunmapi, and
  freeing the holder's real extent always queues a deferred EFI, so it refused on every
  holder free and cancelled a dirty transaction.  Now: `list_count_nodes` around the attr
  remove (flag only what the remove added), alert-and-commit instead of refusing after the
  first dirty; same treatment for mxfs_dirshard_locator_set's post-add checks (inside the
  parent's dirty allocation txn).  `pal/linux/xfs_xattr.c` xfs_attr_change refuses every
  xattr set/remove (ACLs and security.* included) on a sharded parent with -EOPNOTSUPP
  (P-DIRSHARD-XATTR-REFUSED) so the locator fork stays shortform by construction.
  Rule: **a refusal that can cancel a transaction must run before that transaction's first
  dirty**; after it, only commit or shutdown are honest.

- **D-0532 option (a) (0.64.27, sess474)**: every ILOCK-only `xfs_ilock_nowait` site now releases
  raw (`xfs_iunlock_nodlm`): `xfs_reclaim_inode` (3 unlocks; only the shutdown-abort arm re-takes
  with `xfs_ilock` and ends with the DLM unlock, tracked by `dlm_begun`), `xfs_ifree_mark_inode_stale`
  (chunk siblings = DEFERRED-freed corpses with cached EX), the P146V relog and the shortform
  premerge (`xfs_trans_ijoin(tp, ip, 0)` + raw unlock after commit), the dir data-block evict
  (SHARED).  `xfs_lock_inodes`/`xfs_lock_two_inodes` were already paired (explicit begins + raw
  release on pre-held members).  Mechanical check: `tests/audit_ilock_nowait_pairs.sh`.
  P71-UNDERFLOW prints `un=%pS` (0.64.25) from `i_mxfs_ilk_un_ret`.
- **D-0133 counter arm (0.64.26, sess474)**: `xfs_initialize_perag_data` sums the FRESH AGF/AGI
  buffers in cluster mode (the pag summaries are only rebuilt on first read / fresh tenure and go
  stale for AGs this node never acquires) and prints `P-SB-RECOUNT-STALE`; `xfs_log_quiesce`
  prints `P-SB-SYNC-PRE/-WRITE/-POST` (durable counters via `mxfs_sb_read_counters_coherent`).

## sess475 (2026-09-02, 0.64.29/0.64.30) — D-0133 SB summary critical section moved to put_super + SEAL

- The 0.64.28 in-quiesce `mxfs_sb_summary_lock` was inert (rc=-19 96/96): put_super tears the DLM down before `xfs_unmountfs`.  Now `xfs/xfs_log.c` has two static helpers reached from `xfs_log_quiesce`'s clustered lazysbcount branch: `mxfs_sb_summary_cover` (lock unless `mp->m_mxfs_sb_lock_held`; PRE → `mxfs_sb_summary_recount_uncached` → WRITE → `xfs_log_cover` → buftarg wait + flush → POST re-read, `P-SB-SYNC-POST-MISMATCH` if the durable counters differ from what we logged; fails closed on lock/recount failure — no unlocked SB write) and `mxfs_sb_summary_sealed_quiesce` (after `m_mxfs_sb_summary_done`: writes nothing if the log is still covered and the seal counters are 0 → `P-SB-SEAL-OK`; else `P-SB-LATE-DIRTY-COVER` + `xfs_fs_mark_sick(XFS_SICK_FS_COUNTERS)` + `m_mxfs_sb_late_dirty`).
- `mxfs_sb_summary_lock(mp, &epoch)` now returns the CAW `ex_grant_epoch` (the ordering witness printed on every P-SB-* line).  Knobs in `xfs_mxfs_dlm.c`: `dbg_sb_pause_point` (1-4, one-shot) + `dbg_sb_pause_ms`, `dbg_sb_late_dirty` (one-shot); helpers `mxfs_sb_summary_pause(mp, point)`, `mxfs_dbg_sb_late_dirty_take()`.
- Seal probes: `xfs_trans_alloc` (`P-SB-SEAL-TRANS`, `m_mxfs_seal_trans`), `xfs_log_sb` (`P-SB-SEAL-SYNCSB`, `m_mxfs_seal_syncsb`).  Fields in `xfs_mount.h`: `m_mxfs_sb_summary_done/sealed/late_dirty/lock_held`, `m_mxfs_sb_grant_epoch`, `m_mxfs_seal_{trans,syncsb,sbwrite}`, `m_mxfs_sb_write_seq`.
- INVARIANT: after the seal nothing may allocate a transaction or write the SB sector; the runtime covers (`xfs_log_worker` etc.) are still unlocked writers = D-0536.  See docs/superblock-cluster-mode.md.
- **0.75.34 (D-0536)**: `xfs_log_worker`'s clustered branch (`m_mxfs_dlm && m_mxfs_dlm_was_active && lazysbcount`) calls `mxfs_sb_runtime_cover` (static, `xfs/xfs_log.c`, after `mxfs_sb_summary_cover`) instead of `xfs_sync_sb`: `mutex_trylock(m_mxfs_sb_summary_mutex)` (busy → `P-SB-RUNTIME-COVER-BUSY`, skip) → skip after `m_mxfs_sb_summary_done`/sealed → `mxfs_sb_summary_lock` (fail → `P-SB-RUNTIME-COVER-LOCK-FAIL`, skip) → `mxfs_sb_read_counters_coherent` into `m_sb` (fail → `-READ-FAIL`, skip) → `m_mxfs_sb_cover_durable=1` so `xfs_log_sb` does NOT fold the private percpu counters → sync tr_sb commit with `xfs_trans_bhold` → `xfs_bwrite(sb_bp)` (retires the AIL item inside the section) → buftarg wait + flush → `P-SB-RUNTIME-COVER slot= epoch= rc=` → unlock.  The mutex (`xfs_mount.h`, init in `xfs_super.c` next to `m_mxfs_flush_lock`) is also taken by `mxfs_sb_summary_final_sync` (blocking, around its lock..done) and by `mxfs_sb_summary_cover`'s `!caller_held` path (freeze/remount-ro).  The worker's trylock is what keeps `cancel_delayed_work_sync` inside the final sync's `xfs_log_quiesce` from deadlocking on a worker waiting for the mutex.  Harness: `tests/sb_runtime_cover_2node.sh <label>` (X parks at point 2, Y covers at 1 s; `D0536-MEASURE` line; fixed build = Y unlocked SB writes 0, `P-SB-RUNTIME-COVER` ≥ 1).  Remaining unlocked SB writers (rare, not the periodic cover): quota on/off, growfs, runtime feature upgrades (`xfs_add_incompat_log_feature`, attr/bmap/inode_util `xfs_log_sb`), mount-time `xfs_mount_reset_sbqflags` — still fold private counters.

## sess475 (0.64.31) — D-0532 directed concurrency arm knobs

- `xfs_mxfs_dlm.c`: `dbg_bast_pause_ino`/`dbg_bast_pause_ms` (`mxfs_dbg_bast_pause(ip)` called right before the reg-durable `for (rtry…)` loop in `mxfs_dlm_bast_process`), `dbg_relog_force_ino` (`mxfs_dbg_relog_force_take(ip)` sets `v_behind` once at the clean-but-unlanded decision), `dbg_iolock_hold_ino`/`dbg_iolock_hold_ms` (`mxfs_dbg_iolock_hold(ip)` called from `xfs_ilock` after `mxfs_dlm_ilock_begin` for IOLOCK_EXCL).  Probe `P146V-RELOG-HOLDERS ex_before/ex_after pr_before/pr_after` around the P146V re-log's `xfs_iunlock_nodlm`; `P146V-RELOG-NOWAIT-BUSY` when the trylock fails.  All one-shot per inode number (cmpxchg take).  Harness `tests/sess475_chain117_d0532_relog_concurrency.sh`; the 2-node form is `tests/d0532_relog_live_holder.sh` (0.87.10: the regular-file early-out ahead of the loop falls through while `dbg_relog_force_ino` is armed, otherwise the loop and both hooks are never reached; a user holder is admitted only after the release, by the demote-wait — the concurrent case is closed by construction, see CHANGELOG 0.87.10).  Also 0.87.10: `dbg_bast_defer_ino`/`dbg_bast_defer_ms` (`mxfs_dbg_bast_defer`, top of both BAST work functions, parks the work before it touches in-core state; the work's igrab ref pins the inode, so the corpse cannot be freed or recycled during the park — `tests/d0532_pending_bast_recycle.sh` asserts exactly that), and the recycle-time classification of a delivered BAST in `xfs_iget_recycle`: `recycle_bast_stale` (grant NL, cleared), `recycle_bast_kept` (grant live, kept — must read 0; the tripwire), `recycle_bast_dropped` (live but `recycle_bast_keep=0`), probes `P-RECYCLE-BAST-{STALE,KEEP,DROP}`.

## sess476 (0.64.33-0.64.36) — D-0537 SB summary key BAST refusal; CANCEL authority tokens; pass-1 cancel table from admitted txns

- `xfs_mxfs_dlm.c` `__mxfs_dlm_bast_notify`: a BAST for `mxfs_sb_summary_key(mp)` (no in-core inode, so it would take the no-inode ORPHAN release and unlock from under put_super — D-0537, chain 116 v2 holderfail: Y granted epoch+1 in 255 ms under a parked 60 s hold) prints `P-SB-SUMMARY-BAST slot= req= held= epoch= action=` and, while `mp->m_mxfs_sb_lock_held` (knob `sb_summary_bast_refuse`, default 1), returns without queuing the release.  `pal/linux/xfs_super.c` raises the holder mark BEFORE the granting CAS.
- INVARIANT: any raw inode-class key without an in-core inode is released by the no-inode BAST path on the first peer request — a "lock" on such a key is exclusive only if its holder is registered somewhere the BAST path consults.  The samenode selftest key (64) and the SB summary key (65) are the two reserved keys.
- `xfs_trans_buf.c` `xfs_trans_binval` now calls `mxfs_bli_auth_capture` (+ `mxfs_dbg_cancel_token_forge_apply`, negative arms) BEFORE the stale conversion: CANCEL records carry the authority trailer (chain 105 s475b: 208/208 untagged items were CANCELs).  Sizing/format in `pal/linux/xfs_buf_item.c`.
- `xfs_log_recover.c`: `mxfs_report_replay_authority` / `mxfs_classify_untrusted_txn` take `bool publish` (false = pure decision on a scratch evaluator copy; only `rman_abort` is copied back).  `mxfs_cdefer_{stash,resolve,verify,free}`: CANCEL-bearing untrusted txns are parked through pass 1 (`r_mxfs_deferred`, `log->l_mxfs_cdefer`), decided at the end of pass 1 in `xlog_do_log_recovery` (relmarks are inserted DURING pass 1, so an inline pass-1 verdict would miss later markers), refused ones get `xlog_put_buffer_cancelled` per CANCEL (`P-FR-CANCEL-PASS1`), pass 2 verifies the verdict by (tid,lsn) (`P-FR-PASS-VERDICT-MISMATCH` → -EIO).  `xlog_recover_process_ophdr` does not free a parked trans.  Pass-2 REDUNDANT skip excludes CANCEL records (their put must run).
- New `struct xlog` fields (`xfs_log_priv.h`): `l_mxfs_cdefer`, `l_mxfs_cdefer_ht`, `l_mxfs_p1_*`, `l_mxfs_pass_verdict_mismatch`, `l_mxfs_cancel_put_miss`, `l_mxfs_image_cancel_skips`; `struct xlog_recover` (`libxfs/xfs_log_recover.h`): `r_mxfs_defer`, `r_mxfs_deferred`, `r_mxfs_ncancel`.
- `xfs_super.c` late-dirty arm: `mxfs_sb_late_dirty_prearm` at put_super ENTRY (before the teardown bast-arm sweep) takes the knob and pre-warms the root's DLM EX; the post-seal injection then acquires locally.  Pitfall: a DLM acquire after `m_mxfs_arms_off` can wedge forever on a dead demote instance (`P-DEMWAIT-REDRIVE` → `P6S-ARM-REFUSED teardown`).
- Docs: `docs/superblock-cluster-mode.md` (0.64.33 section), `docs/authority-certificate.md` ("CANCEL records carry the proof too").

## sess481 (0.65.0) — `P132-CREATE` reaches file creates; the create cost is decomposed

- **The trap that hid this for 350 sessions:** `xfs_inode.c` `xfs_create()` started its `p132_t0` clock under `if (mp->m_mxfs_dlm && is_dir)`.  Every workload that sets the shared-LUN create ceiling makes FILES, so the one probe that could attribute a create's cost had never once run on the path that matters.  If you go looking for create instrumentation and find "it exists", check the gate before believing it covers your workload.
- New knob `mxfs.create_cost_ms` (`xfs_mxfs_dlm.c`, extern in `xfs_mxfs_dlm.h`, default **0** = unchanged directory-only behaviour).  Set N>0 to start the clock for file creates too and print any create reaching N ms.  A threshold, not a boolean, because the measurement it exists for runs 3200 creates across 32 nodes and printing all of them would load the path being timed.
- `P132-CREATE`'s opaque `pre_ms` is split into three sub-phases, plus `dir=`, `ag=` and `comm=`:
  - `res_ms` — `xfs_trans_alloc_icreate`, i.e. transaction reservation; a full log blocks in `xlog_grant_head_wait` here.
  - `dlk_ms` — the `xfs_ilock(dp, ILOCK_EXCL|ILOCK_PARENT)` that carries the parent directory's **cross-node DLM EX acquire**.  This is the shared-directory queue wait, seen from the filesystem side (`P291-EXWIN` is the DLM side of the same wait).
  - `dia_ms` — `xfs_dialloc`, which carries the **AG grant** (inode allocation picks an AG by affinity, then takes that AG's lock).
  - the unattributed remainder is `pre_ms - res_ms - dlk_ms - dia_ms`; `tools/p132_attribute.py` reports it as `other_ms` rather than folding it away.
- INVARIANT worth preserving: these three are stamped at **call boundaries inside one function**, so they are mutually exclusive by construction.  A cost decomposition assembled from probes at different call depths lets several buckets claim the same wait, which is how a 20 ms stall gets counted three times and attributed to nothing.
- `pre_ms` deliberately keeps its original meaning (t0 → pre-commit), so readings of this line from before 0.65.0 stay valid.
- Also 0.65.0, same file: both directory-inode durability warnings — `P13-SFPARENT-DURABLE-FAIL` and `P68-DIRINODE-DURABLE-FAIL` — now print `state=` and `releasing=`, supplied by one shared predicate `mxfs_dir_durable_is_release()` so they cannot drift apart.  **Why it matters:** `__mxfs_dlm_dir_inode_durable` makes a directory's inode cluster platter-durable *before* its DLM lock is handed to a peer, and on failure it warns and **releases anyway**.  Whether that is harmless is decided entirely by which arm of `mxfs_inode_cluster_durable` gave up — `icd_max_try = icd_releasing ? 1500 : 25` — and the two arms have OPPOSITE consequences: on the release arm (DEMOTING/BAST, ~3 s) giving up "hands the dir EX to the peer with a stale on-disk dinode ... the peer's FUA read durably RESURRECTS our removed dirent", which that function's own comment calls a violation of Architectural Invariant #1; on the op-side arm (CACHED, ~50 ms) a miss is harmless by design because the release-side drain catches it at handoff.  Both printed identical text with no state field, so the 10 occurrences measured on 0.64.37 (7 of 32 nodes, root dir included; `P68` **zero**, so confined to shortform dirs) were unreadable in either direction.  Tracked as `D-DIR-INODE-DURABLE-BARRIER-FAILS-ARM-UNCLASSIFIED`.  Do NOT "fix" it by widening the 25-try op-side budget — that arm is deliberately cheap and best-effort, and widening it would mask the release-side case rather than answer it.
- Buckets still NOT instrumented anywhere in the tree (sess481 survey): superblock/global counter acquisition or refill, `xfs_trans_reserve` internals, log commit/force wait (`P-LGRANT` in `xfs_log.c` prints grant-head *state* on each retry but never calls `ktime_get`, and `xfs_log_cil.c` has zero MXFS additions), and ordinary block-I/O completion latency (`P-IOWAIT-STUCK` in `pal/linux/xfs_buf.c` is a 4 s stuck-detector with no elapsed field).  `res_ms` and `commit_ms` bracket the first three from the outside, which is why they are the next place to look.

## sess482 (0.66.1) — `i_dlm_epoch` is a generation counter, and one grant-loss site let it go backwards

**THE INVARIANT, stated by the field itself** (`xfs/xfs_inode.h:233`): `unsigned long i_dlm_epoch` is *"bumped every time this node LOSES the inode's DLM grant (mode -> NL) or marks it stale"*. `d_revalidate`'s zero-I/O fast path rests entirely on it — a dentry whose `d_time` still equals the parent's epoch is returned VALID with no lookup at all — and **directories have nothing else**, having been deliberately excluded from the affine fast path.

- **Ten sites assign `i_dlm_mode = MXFS_LOCK_NL`. Nine advance the epoch on the very next line** with a byte-identical sequence — `ip->i_dlm_epoch++; ip->i_dlm_epoch_src = __LINE__; mxfs_relbar_epoch_check(ip);` — (four of them under `spin_lock(&ip->i_dlm_lock)`, four not); the setup site initialises to 1 instead. The tenth, the **P106 phantom-grant bail**, did not. Fixed in 0.66.1 with the same instrumented sequence, under the lock. Tracked as `D-PHANTOM-GRANT-BAIL-SKIPS-EPOCH-BUMP-DCACHE-ABA-482` — **landed, NOT verified**: the branch never fired in the 2.9M-line row available, so the fix has not been observed to do anything.
- **The bug shape is ABA on a validity token.** The bail demotes a grant the node turns out never to have held, then re-acquires. Mode goes NL → EX while the epoch stays at E, so a dentry stamped E under the phantom grant is blessed again afterwards — a binding earned under authority the code had just disavowed. Bidirectional: a stale positive dentry keeps resolving a deleted name; a stale negative one keeps hiding a created one.
- **Three near-misses worth not re-deriving.** `mxfs_dir_base_invalidate()` clears only `i_dlm_base_valid`, the directory-**block** baseline, which the dentry fast path never consults. The authority-loss helper touches only the certificate. And nothing anywhere on that branch calls `d_drop`/`d_invalidate`/`d_delete`/`shrink_dcache`, so no dentry is purged. Setting `i_dlm_stale` is **not** a substitute either: it must be cleared after the reload, and every surviving stamp becomes fast-valid again the moment it is. Only advancing the generation ends the episode permanently.
- **Acquires never bump** — bumping is purely a grant-LOSS action (verified across all six acquire sites). So a mode that returns to non-NL does not by itself re-issue anything.
- **Auditing this is cheap and reusable**, and is the durable detector: parse the file for every `i_dlm_mode = MXFS_LOCK_NL` assignment and require an `i_dlm_epoch++` within the next few lines. One known false positive: a multi-line `ip->i_dlm_mode == MXFS_LOCK_NL` **comparison** at ~24018 matches a naive assignment regex and is not a site.
- **Two different counter designs live side by side, and only one can suffer this bug.** Worth knowing before auditing any other epoch here:
  - `i_dlm_epoch` (inode / dcache) is a **locally incremented** counter. Its correctness depends on *every* grant-loss site remembering to advance it, which is exactly the obligation the P106 bail dropped. A local counter is only as good as the completeness of its write sites.
  - `pag_mxfs_grant_epoch` (AG) is a **minted, fleet-wide** value: `0` means "not held", and a nonzero value is `gres.grant_epoch` handed back by the granting CAS, never a local increment. Readers compare monotonically (`gres->grant_epoch > ip->i_mxfs_auth_epoch`). Checked in sess482 and it is **sound** — it is *structurally* immune to the ABA, because a re-acquire cannot mint a value it already used, and its declaration explicitly names `mxfs_dlm_ag_force_release_all` (unmount) among the clear sites, warning that "clearing only at the unlock sites would leave a window in which an item could capture an epoch this node is already surrendering."
  - **The lesson for future audits:** a minted/monotonic epoch needs its *clear* sites audited; a locally incremented one needs its *advance* sites audited, and is the fragile shape. When you meet a new counter here, first ask which kind it is.
- **The class-level lesson.** A sess4 comment in this same file already names the family — *"half a dozen recovery paths that set `i_dlm_mode = NL` without transiting a release call (P72 orphan escape, P106 phantom bail, unmount teardown, single→multi transition wipe)"* — and argues they converge safely. That argument is about the **disk-grant** consumer (the ICLUSTER coverage sweep), which is a *different* consumer of the same NL transition from the dcache generation counter. **When one transition feeds two independent consumers, hardening one does not harden the other** — and the second is easy to forget precisely because the first was done carefully.
- **Coverage of the audit, so it does not need redoing.** There are **18 writes to `i_dlm_mode` in the whole tree**, all of them in `xfs/xfs_mxfs_dlm.c` (every hit in `pal/`, `dlm/` and the headers is a comment). Ten reach NL, three are `= MXFS_LOCK_EX`, three are `= mode`, and two are the guarded restores `= g` / `= g2` (both conditioned on `!= MXFS_LOCK_NL` and `i_dlm_mode < g`, so they only raise toward a still-held mode). `MXFS_LOCK_NL` is `0`, but **no site ever spells it `= 0`** and there are no `WRITE_ONCE` writes — so a by-name search is complete, which is not obvious and is worth knowing before trusting a future grep. Because every route to NL must pass one of those ten assignments, **all four paths named in the sess4 comment now advance the epoch**, not just P106.

## sess482 (0.67.0) — there are TWO AG-release paths, and only one got the drain hardening

**Audit by primitive, not by scenario.** `mxfs_v5_dlm_ag_unlock` (`dlm/v5_mount.c` ~15071) is a **pure** release primitive — a TCP unlock or a CAW slot CAS behind a release gate. It does no draining and no flushing, so *every* caller must prepare the platter itself. There are two:

| | cooperative (`~49457` → unlock `~49710`) | **unmount** (`mxfs_dlm_ag_force_release_all` `~49924` → unlock `~49970`) |
|---|---|---|
| steps before unlock | **nine**: drain_alloc_buflist, drain_inode_buffers, blkdev_flush_epoch, drain_meta_buffers, blkdev_flush_epoch, `xfs_log_force(SYNC)`, drain_meta_buffers *again* (sess43), bounded meta_pending wait, final flush | **one**: drain_alloc_buflist |

Tracked as `D-UNMOUNT-AG-RELEASE-SKIPS-DRAIN-PIPELINE-INVARIANT1-482` (critical). The sess385 ordering fix recorded in the closed `D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN` — *"drain_alloc_buflist + drain_inode_buffers now run BEFORE the first drain_meta_buffers, with a blkdev flush between"* — went into the cooperative path only. **Two callers of one primitive; one was hardened across several sessions and the other was never brought along.**

- **The ordering compounds it.** The unmount release is called from `pal/linux/xfs_super.c:2066`, and `xfs_unmountfs` — where the log quiesce and AIL push happen — is at **line 2175 of the same function**, with nothing pushing the AIL in between. So grants are published before this node's metadata reaches the platter, *and* the later AIL push writes that metadata over whatever a peer did with the AG meanwhile. The same put_super/unmountfs inversion is independently recorded in the open `D-SB-PERNODE-DIVERGENT-WHOLE-LOG-LOST-UPDATE-0133` for a different resource, so it is causing at least two distinct problems and may want a structural fix rather than two local ones.
- **`rel_epoch` asymmetry:** cooperative release records `pag_mxfs_rel_epoch` from `pag_mxfs_grant_epoch` before zeroing (`~39140`); the unmount path zeroes `grant_epoch` (`~49956`) **without** setting `rel_epoch`, so the retiring-token guards that read it (`xfs/xfs_inode.c` ~8531, ~10051, gated on `rel_epoch != 0`) are inert there.
- **This is candidate arm (e) for `D-AGIFC-...-408`** (#1 critical, mechanism UNKNOWN since 08-23), whose symptom — AGI freecount disagreeing with inobt/finobt on the platter *after a clean fleet unmount*, plus an orphan still chained in an AGI unlinked bucket — is item-for-item what the sess43 comment predicts from skipping the meta drain. **Not established**: a source-proven omission plus a symptom match is not a causal chain. If proven, 408 and 482 are one defect and close together.
- **Before trusting any clean sweep of `P-AGIFC-RELEASE-MISMATCH`:** that audit runs at `~49968`, one line above the unmount unlock, default-on, reading the platter — the right oracle at the right instant — and it had **four silent exits** (audit off/no DLM, single-node, `xfs_is_shutdown`, read/magic failure, and multi-level btree: it bails unless `agi_level == 1 && agi_free_level == 1`). 0.67.0 counts each by reason and prints `P482-AGIFC-AUDIT-COVERAGE` + `P482-UMOUNT-AGREL` once per unmount. **`ran` is the denominator; a zero mismatch count against `ran=0` measures nothing.** Also note both the audit and the unlock sit inside `if (release_now)` (`pag_dlm_cached || pag_dlm_latched`), so AGs handed off cooperatively before unmount are neither released nor audited here — that subset was never counted either, which is why `ags_released` is now reported.
- **Deliberately NOT fixed yet.** Copying the nine-step pipeline into the unmount path would add up to three device flushes per AG to every unmount and could convert a correctness gap into a RULE 0 failure on the mass-unmount rows. Measure first.

## xfsaild's grant guard: what "stale and skip" actually did, and the 0.70.0 terminal behaviour (sess488)

`xfs_buf_item_push` (`pal/linux/xfs_buf_item.c`) refuses to write an AG-metadata buffer (`mxfs_buf_xfsaild_skip_agmeta_write`: agf/agfl/agi/bnobt/cntbt/inobt/finobt with `!pag_dlm_cached && pag_dlm_holders == 0`) and a released directory's bmbt leaf (`mxfs_buf_xfsaild_skip_bmbt_write`). Until 0.70.0 the arm did `xfs_buf_stale(bp)` and returned `XFS_ITEM_SUCCESS`, believing (sess23 comment) that staling "removes the BLI from the AIL". **It does not**: `xfs_buf_stale` sets `XBF_STALE` and clears the delwri flags; nothing calls `xfs_trans_ail_delete`. The item stays at its LSN, is re-refused every cycle, the log tail never moves, `xfs_ail_push_all_sync` never returns (lap 3 of the unmount campaign: three items — one AG's agi/inobt/finobt, one LSN — at the AIL head for the whole 240 s budget, `P128-AILSTUCK` naming exactly the `P126` daddrs). Second hazard: a later `xfs_buf_find_lock` reuses the staled buffer with `b_ops = NULL` while the item is still attached, so the guard no longer recognises it and the next push writes whatever the buffer then holds.

- **Authority coherence for the guard.** `pag_mxfs_grant_epoch` is written to nonzero at exactly one site (`xfs_mxfs_dlm.c ~42081`, after the granting CAS, then `holders = 1` in the same `pag_dlm_lock` section) and to zero at every release-commit point *before* the on-disk unlock. A lock-free reader that sees `epoch == 0` unchanged around `pag_dlm_cached`/`pag_dlm_holders` has a coherent "not held" snapshot; `epoch != 0` with `holders == 0` is an acquire in flight. On TCP the epoch is always 0 (no epoch is minted), so the boolean predicate remains the hold witness there. `pag_dlm_lock` is a **mutex** — never take it from the push (ail_lock held).
- **Per-item accounting** (0.69.6): `bli_mxfs_refuse_first` (jiffies|1), `_count`, `_lsn`, `_reported` on `struct xfs_buf_log_item`; `P126-XFSAILD-REFUSE` carries lsn, the captured authority (`bli_mxfs_auth` class/status/epoch/window), current epoch, cached, holders; `P126-XFSAILD-REFUSE-RELOG` when a refused item's LSN moves (a second unauthorized mutation — the clock is NOT restarted); `P126-AIL-PINNED` once per item past `mxfs.ailpin_grace_ms` (10 s) and `P126-AIL-PINNED-MOUNT` from `m_mxfs_ailpin_work`.
- **0.70.0 terminal behaviour**: refuse without staling, `xfs_buf_unlock`, return `XFS_ITEM_LOCKED` (xfsaild counts it stuck and backs off — `xfs_trans_ail.c ~632`); past the grace period the work item runs `xfs_force_shutdown(SHUTDOWN_CORRUPT_INCORE)` (the same policy as the acquire-time `P131-INVAL-REFUSED`). **After shutdown the arm falls through**: the delwri submit hits `xlog_is_shutdown` (`xfs_buf.c ~8852`) → `xfs_buf_ioend_fail` → `xfs_buf_ioend_handle_error` shutdown branch (`~2369`, `out_stale`, returns false) → `xfs_buf_item_done` → `xfs_trans_ail_delete`; that is how the pending `xfs_ail_push_all_sync` returns. The push runs under `ail_lock`, so the shutdown must go through the work item, never inline. `P126-XFSAILD-REFUSE-TRANSIENT` = refused on an incoherent snapshot (no accounting). `P126-EPOCH-MISMATCH` = held AG, image captured under another tenure's epoch and never re-logged — **diagnostic only, still written** (measure before enforcing).
- **The steady-state producer question.** On the 0.64.37 freeze the heavy shared-dir storm (`run_crash_consistency_20260904T022603Z`) produced ~50 refusals per node on 12 nodes for ~25 s, always AG 0's agi/inobt/finobt, immediately after `P12-LATCH ag=0 by=unlock` / `P12-WORK ag=0 enter holders=0 cached=0` while an inactivation with `P-INACT-CERT auth_epoch=0` ran — the live-mount instance of "commit after release" that the sess427 FREE-PUBLISH ruling forbids. 0.69.x board-row kernlogs show zero (the 1-per-run hits are a copied `dmesg_at_fail.txt`), but the board row is a lighter storm. With the fail-stop such a node shuts down after 10 s; count `P126-XFSAILD-SKIP-AGMETA` in the current build's heavy-storm evidence before trusting 0.70.0 on boards. `P60` (bmbt arm) has not fired in two days of evidence.
- **Debug injector** (0.69.6): `/sys/kernel/debug/mxfs/<dev>/inject_unheld_agmeta_dirty` ← `<agno>`: for an AG the node does NOT hold (else `-EBUSY`), `xfs_trans_alloc(tr_sb)` → `xfs_trans_read_buf` of the AGI (`XFS_AG_DADDR(mp, agno, XFS_AGI_DADDR(mp))`, real `xfs_agi_buf_ops`) → `xfs_trans_log_buf` unchanged → commit → `xfs_log_force(SYNC)`; prints `P-INJECT-UNHELD-AGMETA`. It bypasses only `mxfs_ag_dlm_lock` (the AG-lock hooks live in `xfs_ialloc.c`/`xfs_alloc.c`, not in the buffer read path) and poisons the node's log slice by design — scratch filesystems only.
- **Unmount ordering after 0.70.1** (`xfs_super.c` put_super): `xfs_unmountfs_prepare` → explicit `xfs_log_force(SYNC)` + `xfs_ail_push_all_sync` + `xfs_buftarg_wait` → `mxfs_sb_summary_final_sync` (cluster-wide SB summary EX lock, `xfs_log_quiesce` under it, seal) → `mxfs_iclus_purge_all` → `mxfs_dlm_ag_force_release_all`. The push moved before the lock so a pinned node stalls (and, with 0.70.0, shuts down) before it can hold the lock the fleet convoys on. The recount under the lock (`mxfs_sb_summary_cover`) reads uncached AG headers and writes only the SB; the under-lock quiesce is still unbounded (separate change).

## sess491 (0.70.4) — the directory grant has THREE exits, and the reclaim exit drains extent-format directories only (D-0491)

A committed dirent was lost twice on 32/caw shared-directory create runs with `dir_persig_flush=0` (node23_f50, node6_f50 — each the writer's LAST create). The shape: the create logs the dir data block under EX; the node's next release of that directory enters at PR (`P51-REL held_mode=3`), the release drain re-lands the never-written block (`P3R-RELAND lseq=4 wseq=0`), `xfs_buf_submit_ex`'s directory fence refuses the sub-EX write (`P123-DIRFENCE-SKIP gmode=3`), the buffer is freed with its F4 obligation open (`P286-F4-ORPHAN`), and a peer cold-reads the stale block and overwrites it. No EX→PR downgrade exists and every phantom-demotion probe (`P108/P106/P72/P-TCPEX`) was zero fleet-wide, so the EX tenure left through the one exit that prints nothing when clean: **`mxfs_dlm_evict`** (inode reclaim, `xfs_mxfs_dlm.c` ~36546). The test's verify phase does `drop_caches`; `xfs_reclaim_inode` → `mxfs_dlm_evict` → `mxfs_v5_dlm_inode_unlock` releases the on-disk grant.

- **The gap.** The sess83 data-block drain arm in `mxfs_dlm_evict` (~36850) is gated `if_format == XFS_DINODE_FMT_EXTENTS`; the 32-node shared directory grows to **BTREE** format within seconds (`fmt=3 nx=48` on every `PW-RELFENCE` row), so the drain is skipped and EX is released with committed-unwritten blocks cached. `mxfs_dir_flush_data_blocks` (~6669, the in-lock variant the arm calls) already handles BTREE (owner scan + `mxfs_dir_bmbt_scan`, then the extent walk if loaded — sess133/sess6), so the arm's gate is older than the helper's capability. Candidate fix = extend the gate to BTREE; **not landed** until `tests/sess491_evict_undest.sh` proves the path (RULE 4) and the reclaim-context sync-I/O hazard is reviewed.
- **Three grant exits** (all must drain before the on-disk unlock — architectural invariant 1 applied to inode grants): the release pipeline (`bast_process` / release loop, `mxfs_dir_flush_data_blocks_relsafe`, four call sites ~17679/19360/19730/21051), `mxfs_dlm_evict` (reclaim), and unmount purge. The acquire side has a fourth actor that can drop a log item without a write: `P34-NEWTENURE-RETIRE` (~9993, `mxfs_dir_evict_data_blocks` at the first modify of a new tenure) argues the block was drained at the prior release — an argument that is only as good as the exits above.
- **0.70.4 instruments (no behaviour change)**: `struct mxfs_dir_undest_census` + `mxfs_dir_undest_census(ip, &c)` (~6725, static, `XBF_TRYLOCK` incore probe per data-fork block; caller holds `i_lock`; `-1` when the btree extents are not loaded) → **`P491-EVICT-UNDEST`** in `mxfs_dlm_evict` before the drain arm (`fmt/mode/gmode/state/undest/inail/locked/cached/f4_open/first_daddr/lseq/wseq/has_bli/done/drain_arm`, capped 400) and **`P491-REL-UNDEST`** (~19622) in the release pipeline after its drain, before the handoff, with `held_mode`. `P34-NEWTENURE-RETIRE-UNDEST` (always on) names each still-undestaged block the new-tenure retire drops. **`bp->b_mxfs_done_site`** (`xfs/xfs_buf.h`) = `__LINE__` of the overlay caller that retires a log item through `xfs_buf_item_done` without a write (seven sites: ~3546, 6106, 6308, 6359, 6582, 9908, 9993); `xfs_buf_item_relse`'s `P285-F4-BLI-FREED-OPEN` prints it as `site=` and clears it. `mxfs_f4_open_for_dir(mp, ino, &unknown)` (~15980) counts open F4 obligations for a directory.
- Frozen at `tests/evidence/sess491_frozen_0704` (sv 999BFFE23C5DD829522F079). Verification chain `tests/sess491_evict_undest.sh` (3 fresh-tag crash_consistency laps, flush off): `RESULT OBSERVED` iff `evict_undest_ex>0 | newtenure_undest>0 | rel_undest_subex>0`.

### sess492 (0.70.5) — the census proved it, and the reclaim exit now drains btree directories too

The 0.70.4 chain (s491a) returned `RESULT OBSERVED` with the cleanest correlation this campaign has produced: exactly one `P491-EVICT-UNDEST mode=5 gmode=5 fmt=3 drain_arm=0 comm=bash` per lap (test9, test29, test19; undest 3/2/5, all `has_bli=0`), and the lost entries in each lap belong to exactly that node (node9_f48-50, node29_f50, node19_f43-48). Each evict line's `first_daddr` is the block the same node re-lands at a PR release 4-5 s later (`P3R-RELAND wseq=0` → `P287-F4-SUPPRESSED-COMPLETION` → `P286-F4-ORPHAN`); `P287` exists on those three nodes only. The release pipeline's post-drain census (`P491-REL-UNDEST`) was `undest=0` on all 1336 releases.

- **Fix (`mxfs_dlm_evict`, ~36870)**: the drain arm's gate is now `EXTENTS || BTREE`. Sequence: `xfs_log_force(SYNC)` → `mxfs_dir_flush_data_blocks` → **`mxfs_dir_noino_land_scan(mp, ino, true)`** (the map-independent undestaged landing pass the no-inode BAST release already used; needed because a block whose log item was retired without a write is invisible to the owner scan's DIRTY/IN_AIL/pinned/delwri predicate) → `mxfs_blkdev_flush_epoch`. Then the drain is **checked**: `mxfs_dir_undest_census` + `mxfs_dir_noino_land_scan(mp, ino, false)` (new check mode: counts, no holds, no writes) + `mxfs_f4_open_for_dir` → **`P491-EVICT-DRAINED landed= left= undest= inail= f4_open= undrained=`**. If EX is held and anything remains: **`P491-EVICT-UNDRAINED`** and `xfs_force_shutdown(SHUTDOWN_META_IO_ERROR)` under the existing `evict_obligation_shutdown` knob (fail closed, same policy as the P237 inode-cluster tripwire a few lines up). Reclaim holds `i_lock`; nothing in the arm takes it; buffer gets are NOFS by `xfs_buf` allocation policy.
- **Not fixed here, filed as D-0492**: the acquire-side new-tenure retire (`mxfs_dir_evict_data_blocks` ~9993, `P34-NEWTENURE-RETIRE`) retired the in-AIL log item of committed-unwritten blocks 2313 times in the same run (all EX-held, 1293 never written, 1145 mid-tenure). Its guard skips pinned/dirty/delwri but not undestaged blocks — the guard `mxfs_dir_evict_owned_data_blocks` (~3517) already has. That is what left `has_bli=0` on the evicted blocks and is a crash-durability hole in its own right (log tail moves past a commit whose only copy is in core).
- Frozen at `tests/evidence/sess492_frozen_0705` (sv 487030A71845D11B32172ED); verification chain s492a (same script, `KO=` override). **s492a result**: cc_fail 28→0 over 3 laps, `P287` 10→0, `UNDRAINED`=0, the cause exercised twice (test3, test21) and drained both times (test21: undest 3→0, left=0). cc_2/cc_3 were the first fresh-directory crash_consistency rows to pass 32/32 in this campaign.
- **0.70.7**: `P491-EVICT-DRAINED` also prints whenever the pre-census flagged something (s492a's test3 case was silent because every post-drain field was zero). **0.70.8**: `P491-NEWTENURE-RETIRE-UNDEST` carries `disk_match=` (memcmp of the in-core block against a plain LUN read at the retire; one bounded read per printed line, cap 400). s492c: `disk_match=0` on all 2074 with cc_fail=0 — byte equality is the wrong test at a tenure boundary (the peer's newer image). **0.70.9**: the line adds `superset=` / `missing=` / `ops=` from `mxfs_dir3_data_superset(mp, core, snap, blen, &missing)` (static, before `mxfs_dir_evict_data_blocks`): every live dirent of the in-core data/block image present by name on the platter (1), some absent (0, `missing=` counts them), not a data/block image or owner mismatch (-1). `superset=0` is the real dropped-obligation signal for D-0492.

### sess493 (0.70.11) — the retire at the stale-base evict requires a destaged block (D-0492)

The 0.70.9 census (s493a, 3 laps, `dir_persig_flush=0`) settled what the new-tenure retire was matching: 2204 retires of undestaged blocks fleet-wide, every one of the 432 comparable data blocks `superset=0` (at least one live entry absent on the platter, `missing=1` in 369), and **all 432 had `b_epoch == cur_mep`** — logged in the current tenure (`wseq=0` in 431; the same daddr re-retired after each create with `missing` growing 1,2,3,4,5). The arms: `new_tenure` (363) is per-INODE — "master epoch advanced since this inode's LAST evict call" — so the first evict call of a tenure also sees the blocks this tenure has already logged; `b_mxfs_grant_gen != cached_grant_gen` (66) is stamped at cold read only and never refreshed by a modify. The 94 `b_epoch < cur_mep` rows were `xfs_dir3_free`/leafn/node blocks at `lseq=wseq+1` under EX — re-logged this tenure with no epoch re-stamp (the stamp sites are in `xfs_dir2_data.c`, `xfs_dir2_leaf.c`, `xfs_da_btree.c`; none in `xfs_dir2_node.c`), so **epoch is not a safe retire discriminator** (GPT ruling sess493). Consequence of a retired item: the log tail moves past the transaction; the fsync-acked entries live only in that cache until the release drain; a crash loses them from journal and platter.

- **Rule now (`mxfs_dir_evict_data_blocks` ~10058)**: the epoch/new-tenure/grant arms still name a stale-base candidate, but `xfs_buf_item_done` runs only when `!mxfs_dir_buf_is_undestaged(dbp)` (written_seq == logged_seq). An undestaged candidate keeps its log item for the AIL push or the release drain, gets `XBF_DONE` set back (the evict cleared it a few lines up; the in-core image is the only copy of committed content, no cold read may replace it) and prints **`P492-KEEP-UNDEST ... epoch_rel=current|prior`** (cap 400). `epoch_rel=prior` with a real prior-tenure image would be an invariant-1 breach worth its own record; the measured ones are the un-restamped free/leaf blocks. The disk-comparison probe of 0.70.8/0.70.9 is gone with the arm it measured.
- Frozen `tests/evidence/sess493_frozen_07011` (sv 9A6A8238AAA2B5308A541A9). Verification: `tests/sess491_evict_undest.sh` s493b (expects `P491-NEWTENURE-RETIRE-UNDEST`=0, `P492-KEEP-UNDEST`>0, laps clean) and the new crash-durability harness (tests.md, sess493).
- Still open from the same ruling: the completion sites set `b_mxfs_written_seq = b_mxfs_logged_seq` at I/O completion (`pal/linux/xfs_buf.c` ~2682/6512/6536/9155/11615, `xfs_trans_buf.c` ~782) — if a block is re-logged while its write is in flight, completion marks it destaged with content the write did not carry. Not yet measured.

### sess493 (0.70.10) — the closure classifier exempts the SB summary key (D-0487)

`mxfs_freplay_res_out_of_closure` (~53968) maps INODE/ICLUSTER resources to `XFS_INO_TO_AGNO` and freezes anything decoding past `sb_agcount`; the SB summary key (`mxfs_sb_summary_key`, slot agcount+66 by construction) therefore stayed frozen after the dead holder's AG-scoped refusal and every unmounting peer convoyed on the 120 s lock timeout (sess492 leg Z: 7 dirty departures). Now `mxfs_sb_summary_key_is(mp, ino)` (static, next to the key) and an INODE-type exact match in the classifier return "out of closure" and print `P487-SBSUM-OUT-OF-CLOSURE slot= ino= ag_mask=`. Only AG-mask verdicts reach the classifier (publisher gates on `domain == AG_MASK && ag_mask`; `mxfs_dlm_closure_classify_cb` returns 0 without a mask), so FSWIDE keeps it frozen; `mxfs_dlm_quar_covers_cb` already answers false for the key. Verified s493z legs Z (publisher + scrub) and S (`closure_skip_publisher_purge=1`, scrub alone): strip on the key within ~6 s of the verdict, 31/31 peers clean at 17-18 s (grace + fence + verdict), 31 successor seals with epochs above the victim's. The remount after the legs exposed D-0493 (dlm.md).

### sess494 (0.70.13) — P132-CREATE attributes the lookup term (D-32NODE-SHARED-DIR-CREATE-PACE)

- The 0.70.2 A/B (s490g) put the whole shared-directory "icr excess" in the EXISTENCE LOOKUP: `lkp_ms` 4.4 ms (persig on) / 7.9 (off) per create in the 3200-entry shared dir, `icr_ms` 0.0, private 0.3. `xfs_create` (`xfs_inode.c` ~2693) now samples three node-wide counters around `xfs_dir_lookup_locked` and prints **`lkp_fua= lkp_fua_ms= lkp_rd=`** at the end of the P132 line: FUA passthrough reads (count + wall, `mxfs_fua_read_calls`/`mxfs_fua_read_ns` in `pal/linux/kern.c`, wrapper around `mxfs_pal_scsi_read_fua_bdev`) and plain read bios (`mxfs_buf_read_bios`, `xfs_buf_submit_bio` in `pal/linux/xfs_buf.c`). Node-wide, so a concurrent reader inflates them; the cc row has one writer per node. Hypothesis H-L1 (cold FUA block reads after the tenure-start evict) and its harness: `tests/sess494_lkp_attrib.sh` (tests.md). `tools/p132_phase_summary.py` FULL_FIELDS carries the three fields.
- Frozen `tests/evidence/sess494_frozen_07013` (sv 6CF6DDD1255241B3FBA1551).

### sess495 (0.70.14) — the adopt check skips its FUA inode read under a continuously held EX (ruling item 2)

- `mxfs_dir_modify_adopt_disk_format` (`xfs_mxfs_dlm.c` ~12293, called from `xfs_create`/`xfs_remove`/`xfs_rename` behind the call-site gate `i_dlm_dir_gen > 0`) reads the directory's inode cluster with a synchronous FUA passthrough on EVERY modify to catch a peer's conversion/growth/in-block adds. That read is the ~1.0 ms `rfr_ms` term of the shared-directory create (0.2 private). New inode fields `i_dlm_adopt_ok_epoch/_incarn/_dir_gen` (`xfs_inode.h`, zeroed in the inode DLM init at ~39251) record `(i_dlm_epoch, i_generation, i_dlm_dir_gen)` after a clean read taken while `i_dlm_mode == EX && !i_dlm_stale`; the next call skips the read while the tuple matches and the grant is still held and not stale. Invariant relied on: `i_dlm_epoch` bumps on every path that loses the grant or marks the inode stale, and a peer can only write the dir inode while holding EX, so an unchanged epoch under a held EX means the platter cannot be ahead. A late DIR_MODIFY ring bump of `i_dlm_dir_gen` re-arms the read (conservative). Knob `mxfs.dir_adopt_skip_held_ex` (default 1; 0 = read every modify). Census: `mxfs_adopt_skip_held_ex` / `mxfs_adopt_read_held_ex` counters and a capped (20) `P495-ADOPT-SKIP` line. Verification chain: `tests/sess495_chain141_adopt_skip.sh` (A knob=1 / B knob=0 on the same frozen ko; rfr_ms in-tenure + coherency rows). Frozen `tests/evidence/sess495_frozen_07014` (sv A84A673F00C9B914F386CB6).

### sess495 (0.70.15) — H-L1 refuted; the lookup-window read trace

- s494h (0.70.13) measured the shared-dir in-tenure lookup at 4.85 ms with FUA reads only 0.36 ms of it (7%) and ~23 node-wide plain read bios per lookup (0.3 private). H-L1 (cold FUA reads after the tenure-start evict) is dead. `mxfs.lkp_trace=1` (knob in `xfs_mxfs_dlm.c` next to `dir_adopt_skip_held_ex`) makes `xfs_create` open a node-wide window around `xfs_dir_lookup_locked` (`P495-LKP-WIN open/close`, `xfs_inode.c` ~2703); while open, `xfs_buf_submit_bio` (`pal/linux/xfs_buf.c` ~6557) prints every read bio (`P495-LKP-RD kind=bio daddr len ops flags done fresh pid comm`, cap 600) and the FUA wrapper (`pal/linux/kern.c` ~969) every passthrough read (`kind=fua lba len us rc pid comm`, cap 300). Harness: `tests/sess494_lkp_attrib.sh LKP_TRACE=1`. Frozen `tests/evidence/sess495b_frozen_07015` (sv ADD683E5F0A6B67320475B2).

### sess496 — the lookup term is the datascan heal; the durable-barrier warning is an orphan-release artefact (0.70.17)

- **The shared-directory lookup cost is `mxfs_dir2_datascan_lookup`** (`xfs/libxfs/xfs_dir2_leaf.c` ~1842, non-static; called on every `-ENOENT` from `xfs_dir2_node_lookup` (`xfs_dir2_node.c` ~2517) and `xfs_dir2_leaf_lookup` (~2270) in a multi-node dir). It is the sess22 leaf-hash-hole HEAL: a linear read of EVERY data block (`ndb` from the in-core extent map) looking for the name. Gate: `i_mxfs_dscan_clean_key` (`xfs_inode.h` ~262) = `mxfs_dscan_state_key(dp)` = (`i_dlm_dir_gen`, `i_dlm_dir_valid_epoch`, `i_dlm_dir_loaded_gen`), recorded only by a scan that found nothing; knob `mxfs.dscan_gen_gate` (default 1, `xfs_mxfs_dlm.c` ~15076); reset to `~0` at inode DLM init (~39285) and at a real fork adopt (~29472). In the 32-way create storm peers' DIR_MODIFY ring bumps `i_dlm_dir_gen` through our tenure, so the create's existence lookup (ENOENT by definition) re-walks the directory cold on most creates: the s495c trace shows p90 = 20 data-block reads per lookup, and the FULL run log (`run_crash_consistency_20260904T124810Z`) shows `P26-DSCAN` 68-171 (ratelimited) per 100 lookups per node with `ndb` up to 38. Trap: a chain's sweep directory holds FILTERED kernlog extracts (1069 lines vs 98197) — count probes in the `run_*` directory.
- **The heal is load-bearing.** `P22-DATASCAN-HIT` fired 101 times on 2026-09-04 (a 4-name hole persisting across five crash+replay runs; a 5-hit hole in chain-139 rows with no crash), so leaf-hash holes still form. RULE-5 ruling (sess496): a negative scan for name A is not a directory-wide certificate — skipping the scan under a held EX would let `create(B)` add a duplicate dirent when a hole for B pre-exists, and `unlink`/`rename` of a leafless ghost (`mxfs_dir2_leafless_removename`, `xfs_dir2_node.c` ~2592) would ENOENT. Sound shapes: a first-scan directory-wide data-vs-leaf completeness certificate (invalidated on conversion/rebuild/reload/replay/epoch change; create-target, unlink and rename-source never skip), or fixing the hole root and removing the heal. The hole root is being ledgered by sess496.
- **`P13-SFPARENT-DURABLE-FAIL` / `P68-DIRINODE-DURABLE-FAIL` now print `refused= held_mode= in_ail= pin= clean=`** (`__mxfs_dlm_dir_inode_durable`, ~8546). Every 2026-09-04 occurrence (393; tool `tools/p13_release_shape.py <file-list>`) was `P-ICD-TENURE-REFUSE rel=1 try=0` on an ORPHAN release — pipeline entered at in-core NL (`P70-BP ENTRY mode=0 qsrc=14`, the `P72-STALE-REQUEUE` source at ~24596), `P15-ORPH-PROCEED` (~18978) — of a CLEAN dinode (`P146-RELDUR in_ail=0 pin=0 ili_fields=0x0`, 680/680), with the unlock-time ledger never open (`P220-UNLOCK-LEDGER-OPEN` 0, `P228-RELBAR-*DEFER` 0 in 1892 logs). The invariant-1 enforcement is `mxfs_relbar_close_or_defer` (~16662) under `relbar_enforce=1` on both unlock arms of `mxfs_dlm_bast_process` (~21576 noanchor, ~21767 anchored), with `mxfs_dlm_relbar_check` (~16436) as the always-on verdict probe at the unlock; `i_mxfs_pub_pending_seq` is bumped once per logged inode change at `xfs_trans_log_inode` (`xfs/libxfs/xfs_trans_inode.c` ~134) and `pub_durable_seq` advanced only in `xfs_iflush_finish` (`xfs_inode_item.c` ~1145), reload adopt (~29577) and `mxfs_pubob_settle_home_free` (~38824). `mxfs_v5_dlm_inode_held` on CAW reads the platter slot (`mxfs_dlm_caw_held`, `dlm/dlm_caw.c` ~11497): a refusal there is authoritative.

## 0.72.2 — sole survivor: the single-node bypasses honour pending invalidations (D-SURVIVOR-SINGLE-NODE-BYPASS-SERVES-STALE-VIEW-AFTER-PEER-DEATH-0904)

Measured on the 2-node TCP death chain (s502c/s504a): after fence + replay +
recovery publish, the survivor drops to `active_count=1`, and every
staleness consumer returned on its single-node bypass before looking at the
signal, so root inode 128 (demoted + `EVICT-RING-DIRMOD ... reload=1` at the
victim's mkdir) answered ENOENT from its pre-death inline fork for a
fsync'd directory; only a readdir of the root (`xfs_file_readdir`'s ungated
`if (ip->i_dlm_stale)` P95D loop) healed it. Changes, all gated on
`mxfs_v5_dlm_sole_survivor()` so a never-multi mount is byte-identical:
- `mxfs_dlm_ilock_begin` 'Single-node bypass' (~31877): if
  `i_dlm_stale || MXFS_IF_DIR_RELOAD || dir_gen > loaded_gen`, log
  `P-SURVIVOR-RELOAD` (stale src 28) and `mxfs_dlm_reload_inode(..., true)`
  before returning; a bailed dir reload re-arms the flag.
- `mxfs_dlm_dir_consumer_refresh` (~10513): runs for a survivor instead of
  no-op'ing (the flag/gen block does no I/O when nothing is pending).
- `pal/linux/xfs_super.c mxfs_drevalidate`: no early "valid" for a survivor.
Measured, not assumed: a demote to NL DOES set `i_dlm_stale` (bast_process
release, src=5, ~18679), so every inode the dead peer took from the survivor
carries the flag and the bypass arm services it (P-SURVIVOR-RELOAD src=5 for
the pre-cached files in s504b-g). The reload itself stales the cached inode
cluster before `xfs_imap_to_bp` (~27009/28445), so the re-read is fresh
even with `fua_disable=1`. The reader hooks still gated on `is_single_node`
(`xfs_dir2_readdir.c:883`, `xfs_da_btree.c` ~3300/3332/3574/4496/4619,
`xfs_icache.c:2372`, the modify-side prelock/refresh/adopt helpers) were
audited (sess504) and left alone: the demote-time eager dir evict and the
reload's own invalidation covered every vector the oracle could make fail.
Only a never-granted in-core inode at NL with no flag (iget without ilock)
is structurally outside the bypass arm — no measurement has reached it.
Oracle (`tests/tcp_death_replay.sh`): W pre-caches `$PRE` (40 files ->
BLOCK format, readdir'd + stat'd), `shared.txt` (written + read) and a
negative dentry `created_by_victim`; the victim rewrites shared.txt and
pre_0..4 at a different size, syncfs's (checkpoint), then rewrites pre_5
(same cluster) and creates created_by_victim + new_0..4 before its file
loop (`OK PRE:<name> <md5>`); each vector is asserted by name, a
verdict-time miss runs the lookup / readdir-root / lookup probe
(visibility.txt) and re-verifies, a second verify runs behind
`drop_caches=2`, and `dino_clobber_check=1` is armed on W with
`P-DINO-CLOBBER` asserted zero.

## 0.74.0 — fail-fast on a RECOVERY_BLOCKED holder (D-FENCE-PRECOMMAND-RETRY-UNBOUNDED-NO-BLOCKED-STATE-0904)

`mxfs_recovery_blocked_covers_ino(mp, ino)` (xfs_mxfs_dlm.c, declared in
xfs_inode.h): true when the inode's cluster grant is held by a dead node
whose prover on THIS node has declared its recovery blocked. O(1) while
nothing is blocked (an atomic count in v5), then one bucket walk of the
local master table (remote-mastered resources answer false). Three
consumers, all synchronous with the prover's state, no per-inode latch:

1. `mxfs_dlm_ilock_begin` restart loop, right after `P240-QUAR-REFUSE`:
   `P240-RBLK-REFUSE`, return without a grant (the op fails at the gate).
2. The acquire-timeout classifier, BEFORE the quarantine arm: `rc ==
   -EHOSTDOWN` (from `P-RBLK-DENY-LOCAL` / the master's LOCK_DENY) →
   `P240-RBLK-EIO-ABORT`, clear ACQUIRING, no shutdown, no park.
3. `mxfs_inode_incarn_estale` → `-EIO` (unavailable, not refetchable), the
   same standing as the quarantine's EIO.

**0.75.33 (D-0915)** — two gaps in the above. (1) The O(1) pre-check
`mxfs_v5_dlm_any_recovery_blocked` counted only `recovery_blocked_n`; a
terminally REFUSED victim (`recovery_refused_n`, 0.75.25) made the DLM deny
the acquire (`P-RBLK-DENY-LOCAL`, per-node predicate) while the xfs gates
answered "not covered", so the void hook returned and the namespace op
committed lock-less (s518i: `P58-DIRPIN-NONEX ino=128 comm=mkdir`, rc=0 to
userspace).  The pre-check now counts refused victims too.  (2) The
`-EHOSTDOWN` arm sets `MXFS_IF_ACQ_REFUSED` (bit 28, `xfs_inode.h`); every
grant-install site in `xfs_mxfs_dlm.c` (the three `ip->i_dlm_mode = mode`
blocks) clears it just before taking `i_dlm_lock`.  It is read ONLY by
`mxfs_quar_gate_locked(ip, op)` = `mxfs_quar_gate_op` + the latch
(`P240-RBLK-NSOP-REFUSE`), which replaced `mxfs_quar_gate_op` at the six
post-ilock backstops (`xfs_create`, `xfs_rename`, `xfs_trans_alloc_inode/
_ichange/_dir`).  The 15 pre-lock entry gates in `xfs_iops.c` keep
`mxfs_quar_gate_op`: reading the latch before the acquire that clears it
would refuse the directory forever.

Grants held by live nodes, or by dead nodes whose recovery is still in
progress, take the pre-0.74.0 paths (park, `P240-QUAR-PARK`). The debugfs
`recovery_blocked` file carries the `FENCE_BLOCKED` ACTION text. On CAW the
predicate answers false and the acquire fails at its poll budget as before.

## 0.74.1 — untrusted replay never drains its buffer queue mid-pass (sess507)

Invariant: on an untrusted (foreign / adopted) replay the recovered-buffer
queue is submitted ONCE, at the end of the pass. `xfs_log_recover.c`
`xlog_recover_process_ophdr`'s upstream per-commit-LSN
`xfs_buf_delwri_submit` is skipped under `xlog_is_mxfs_untrusted_replay`
and counted in `struct xlog.l_mxfs_drain_deferred`, reported as
`drain_deferred=` on the `foreign replay of slot N complete|failed` line
(`xfs_log.c`). Why: the sess459 D-0517 OVERRIDE-APPLY in
`xfs_buf_item_recover.c` admits a token-APPLY image whose on-disk LSN stamp
is newer than the transaction; that image is PARTIAL (dirty 128-byte
chunks only) and older than the platter, so it is consistent only after
every later image of the slice has overlaid it in core. Draining between
transactions wrote the intermediate — a block-format dir with the tail
transaction's leaf/tail chunk beside the platter's newer data chunks —
and `__xfs_dir3_data_check` (xfs_dir2_data.c:270, data entry with no leaf
entry) refused it at submit. The deferral vetoes nothing upstream would
not: no mid-pass write restamps a buffer, so every LSN comparison is
against the platter's own stamp. Harness assertion:
`tests/tcp_death_replay.sh` requires `drain_deferred >= 1` whenever
`buflsn_overrides > 0`.

## 0.75.28 — the acquire timeout classifier no longer fail-stops behind a live holder

`mxfs_dlm_ilock_begin` classifies an exhausted acquire (TCP: 3 attempts ×
`mxfs_dlm_lock_retries(60)` × 1 s = 180 s; CAW: 120 s base, liveness-extended
to 480 s) in evidence order: `-EHOSTDOWN` (dead holder/master, recovery
blocked or refused) → `P240-RBLK-EIO-ABORT`; quarantined domain →
`P240-QUAR-EIO-ABORT`; (2) a dead slot pending recovery → `P240-QUAR-PARK`;
**(2b, new)** `rc == -ETIMEDOUT` and `mxfs_v5_dlm_inode_wait_is_live(dlm, ino)`
→ `P-LKWAIT-LIVE ino= mode= laps= beyond_budget_s=` + `msleep(min(500·laps,
5000))` + `goto restart` (no lap cap: the wait ends when the holder releases
or dies, both of which the membership path delivers); (3) nothing live →
`DLM inode lock unrecoverable` + `SHUTDOWN_CORRUPT_INCORE`, unchanged.  The
bounded second-inode acquire (`P-ABBA-BOUNDED-TIMEOUT`) and the
recovery-context requeue return before the classifier.  Origin: s517g, a
rejoined reader on 2/tcp waited 184 s behind the survivor's paused release
drain, took arm (3), withdrew and was fenced; the holder released normally
140 s later (D-ACQUIRE-TIMEOUT-BEHIND-LIVE-HOLDER-FAILSTOPS-REQUESTER-0912).
Closure harness `tests/live_holder_wait.sh` (PAUSE_MS > 180000 on TCP).

## 0.75.31-0.75.32: a quarantined AG is removed from the allocation DOMAIN (D-0914, D-0538)

The sess325 gate in `__mxfs_ag_dlm_lock` (`mxfs_quarantine_covers_agno` ->
`P240-QUAR-AG-EIO` -> -EIO) is the last defence for an in-domain object, not
the AG-selection policy. Both allocator walks end on any error other than
-EAGAIN, so meeting the gate mid-walk failed the whole operation with
healthy AGs behind it. Measured on 2/tcp with an AG-mask verdict
(`ag_mask=0x2`, AG 0 spared): (a) D-0914 — the sole survivor's directory
rotor (`xfs_dialloc_pick_ag`: multi-node pins dirs to `node_slot %
maxagi`, but `mxfs_v5_dlm_is_single_node()` after the peer's death selects
the spreading rotor) pointed at AG 1 -> root mkdir EIO in 1 ms once per
rotor lap; (b) D-0538 — a fallocate whose extents wrapped out of AG 0 met
AG 1 -> `P240-QUAR-AG-EIO comm=fallocate`, EIO. Fixes: `xfs_dialloc`
(xfs_ialloc.c) `continue`s past a covered AG (and returns -EIO up front
under `m_mxfs_quar_fswide`); `xfs_alloc_vextent_iterate_ags` (xfs_alloc.c)
`continue`s past a covered AG with `P538-AG-SKIP agno= start= comm=`.
Required-AG paths (exact_bno / this_ag) still meet the gate. Harness:
`tests/tcp_death_replay.sh` `TDR_AGMASK_INJECT=1` (+ `TDR_AGFILL=1` for the
block walk: a file's FIRST extent is placed by the per-mount rotor, so the
arm seeds files 1 MiB at a time until one lands in AG 0, then grows it 2.3
GiB and maps extents to AGs with `filefrag -v`; assert `P538-AG-SKIP
agno=1`). Pitfall: a bare fallocate may start at any AG and never meet the
quarantined one — a lap without the skip line proves nothing.

## sess521 (ccloop 140e6b67) — D-482 phantom-bail verification knobs (0.75.35)
- `xfs/xfs_mxfs_dlm.c`, next to the `dbg_sb_*` knobs: `dbg_p106_inject_ino`
  (ullong, the one directory inode), `dbg_p106_inject_shots` (atomic one-shot
  budget, cmpxchg via `mxfs_dbg_p106_inject_take()`), `dbg_p106_bail_pause_ms`
  (one-shot xchg), `p106_check_n` (0444 denominator: dir-EX serves that reached
  the backing-record check).  At the P106 site the injection forces `held=0`
  (P106-INJECT-CONSUMED prints ino/epoch/mode/state/holders/pin); the
  P106-STALE-EX-BAIL line prints `epoch=`/`epoch_src=`; the pause
  (P106-BAIL-PAUSE / -END) sits before `goto restart` with mode NL and no
  holder counted, so a peer's EX is served inside it.  The gate
  `dir_ex_verify_held` is set on EVERY dir-EX serve on TCP (throttled 100 ms
  on CAW only).  Harness: `tests/d482_phantom_epoch_2node.sh`.

## sess522 (ccloop 140e6b67) — 0.75.36-0.75.39
- **P106 injection is a real wire loss (0.75.36).** A shot calls
  `mxfs_v5_dlm_inode_unlock_gen(dlm, ino, 0)` behind the cache and re-samples
  `mxfs_dlm_verify_rawmode`; `P106-INJECT-CONSUMED` carries
  `unlock_rc= resample_held= sampled=`.  Forging `held=0` while the TCP master
  still records the node as EX holder is the OPPOSITE divergence and wedges
  the node (P-INODE-WEDGE causes=0x1 → shutdown → P277 self-withdraw).
  D-482 closed F&V on this.
- **Dentry revalidate trace (`pal/linux/xfs_super.c`, `dbg_dreval_trace_ino`,
  now non-static):** `P-DREVAL-EPOCH-FAST` (both fast paths),
  `P-DREVAL-AFFINE-FAST dp= name= ino= d_time= epoch= dp_mode= audited=`
  (every arrival at the affine regular-file exit), `P-DREVAL-STALEFLAG ...
  stale_src=` (which setter flagged the child; 5 = `mxfs_dlm_bast_process`,
  the release path every grant give-up runs through — BAST, close_release,
  idle reaper, dir-EX sweep — set BEFORE the wire unlock); `P-VNLOOKUP dp=`
  in `xfs_vn_lookup` under the same knob (name-level re-verification);
  `affine_audit_stats` (0444) = the six audit counters.  Positive regular
  files in the node's own affine AG NEVER enter the epoch fast path (the
  affine exit returns before the d_time stamp) — a harness needing the epoch
  path must use a subdirectory.  D-AFFINE closed DISPROVED on six shapes.
- **File fast path yields to a peer (0.75.39, `file_yield_on_demote`=1,
  `file_yield_n`, `P-FILE-YIELD`):** `mxfs_file_yield_gate()` in
  `mxfs_dlm_ilock_begin`'s cached-mode fast path — user task, pin 0, not the
  demoter, state BAST or DEMOTING with a foreign demoter → fall through to
  the demote-wait.  The sess47 RELFLUSH admission is PF_KTHREAD-only under
  the same knob.  Without it a tight local `echo > f` loop held a peer's
  `rm f` for 2.5-4.5 s (until the loop ended) with P-LKTIMEOUT on the peer;
  with it 92-415 ms.  Harness `tests/hot_inode_peer_unlink_2node.sh`
  (D-0916).  `mxfs_p71_hold` logs only in state DEMOTING and caps at 8000
  lines per boot — a zero from it later in a boot means nothing.
  0.75.40 restricts the gate to zero counted local holders (a nested ILOCK
  under a counted IOLOCK self-parked for 3 s rescue polls; board s522o
  dir_reuse_coherency 116 s).  MEASURED sess523: the part of the 0.75.39 fix
  that did the work is the RELFLUSH narrowing (holds admitted during DEMOTING
  7938 → 0-14); the yield gate fired 0-1 times per lap on both builds.
- **Remove/rename pre-acquire polls a peer-held AG before the inode hand-off
  (0.75.41, `preacq_poll_ms`=100, `preacq_poll_hit_n`/`preacq_poll_miss_n`,
  `P271-PREACQ-POLL`):** `mxfs_preacq_poll()` in
  `mxfs_trans_preacquire_inode_ags` — on a mandatory-AG trylock miss with NO
  other AG grant registered on the trans and the trans clean: one demanding
  nb acquire (`__mxfs_ag_dlm_lock(nonblock, demand)` registers the waiter
  and BASTs the cacher, which the silent trylock never did), then silent nb
  retries every 2-3 ms up to the knob; hit → `mxfs_ag_dlm_unlock_deferred`
  and continue the sweep, expiry → the unchanged `mxfs_trans_agwait_handoff`.
  WHY (D-0917, proven on both nodes' logs): the hand-off's cached pre-grant
  is reclaimed at zero holders by the writer's next round (truncate blocks
  for the AG under the file's ILOCK: `P1-AGWAIT comm=bash`), the round hands
  the file over, the restart trylock misses again; cycles × ~90 ms with the
  count unbounded (1,1,1,1,6,16 over six laps).  INVARIANT kept: never poll
  with another AG grant held (no AG→AG hold-and-wait); the inode-held wait is
  bounded, the pattern `mxfs_ag_dlm_lock_bounded` already uses under dirty
  transactions.

## sess528 (ccloop 140e6b67) — `xfs_inode.c` flush publishes in-core forks (0.75.46, D-0920) + create-race lab knob (0.75.47)

### What changed
- `mxfs_iflush_fork_publish` (was the 0.75.45 audit `mxfs_iflush_fork_audit`;
  the `iflush_fork_heal` module param is GONE): after `xfs_iflush_fork` on a
  multi-node mount it re-encodes each in-core fork the way the logged copy
  would (`xfs_iextents_copy` / `xfs_bmbt_to_bmdr` / local bytes) and, when
  the staged bytes differ on an UNLOGGED fork, writes the in-core encoding
  into the staged dinode.  Ratelimited `P-IFLUSH-FORK-STALE` reports each
  repair with a running `total=`.
- `mxfs_create_race_delay_ms` (`xfs_mxfs_dlm.c`, 0644, default 0): `msleep`
  at the top of `xfs_create` for `!is_dir` on multi-node mounts, after the
  INCARN_STALE check and before dqalloc.  Lab only.

### INVARIANT (new) — the cluster slot is not this inode's last image
- Upstream `xfs_iflush_fork` copies a fork only when `ili_fields` says it
  was logged, on the premise that the inode-cluster buffer already holds
  the fork's last flushed image.  MXFS breaks that premise: a reload whose
  cached cluster buffer is PROTECTED (`P91-RELOAD-PROTECT`, it carries this
  node's uncheckpointed changes to neighbouring inodes) adopts the peer's
  dinode from a PRIVATE platter read (`kept_protected` arm, ~28290) and
  leaves the buffer slot as it was.  A core-only flush of that inode (an
  append inside the peer's block: `ili_fields=CORE|TIMESTAMP`) then staged
  `di_nextents=1` over sixteen zero bytes; the peer's next platter read
  failed `xfs_bmap_validate_extent_raw` and the file read empty (s527f: 89
  of 200 files on test2, 10 detector lines on test1's xfsaild).  Any future
  flush-side copy that is gated on "was it logged" inherits the same hole.

### Cross-subsystem
- Diagnostic siblings: `P96-RELOAD-PEER-SHRINK-ADOPT` prints from the STALE
  buffer dip BEFORE the private read adopts the real image (mem_size=5
  disk_size=0 on a file the peer had just grown is that stale dip, not a
  shrink).  `P170-CLWR` (`pal/linux/xfs_buf.c`) is provenance only — no
  overlay.  The co-resident stale-slot clobber of NEIGHBOUR inodes in the
  same protected buffer is D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY
  (`icluster_dlm` default 0); `mxfs.dino_clobber_check=1` FUA-verifies each
  cluster write and logs `P-DINO-CLOBBER`.
- The create-race loser branch (`xfs_create` ~2778, `P127-EEXIST-LOSER`)
  returns `-EEXIST` unchanged; the fix for a plain O_CREAT open lives in
  `pal/linux/xfs_iops.c:xfs_vn_create` (EEXIST -> ESTALE, 0.75.48).

## 0.75.49 (sess529) — the terminal obligation defer keeps the fast path closed for a live local writer

`mxfs_dlm_bast_process` captures `p_pend_entry = i_mxfs_pub_pending_seq` at
entry.  At the P244 terminal gate (`pend != dur` at the terminal store) a
REGULAR file whose pending sequence advanced DURING this drain is a
`live_commit`: the state is left at `MXFS_DLM_ISTATE_BAST` (not CACHED), so
`mxfs_file_yield_gate` parks new user admissions in the demote-wait, and the
bast dwork is re-armed with delay 0 (streak untouched).  A defer whose
obligation did not move keeps the legacy CACHED + `mxfs_relab_backoff_ms`
re-arm.  `P244-REL-TERMINAL-DEFER` now prints `pend_entry=` and `live=`.

Why (D-0922, measured s527h appender trace, ino 5740): 21 consecutive defers
~4 ms apart per peer truncate, each `pend = dur + 1`; every retry ENTERED with
the appender admitted (`ex=1`), landed all but that holder's commit, deferred
with state CACHED, and the appender's own `ilock_end` re-fired the pipeline
~100 us later with the appender already inside its next write.  The only exit
was a scheduling gap.  In append_contention s528p the same loop drove the
relab streak to the 1 s cap (P279) and, once the holder's writer paused, the
peer sat behind a 1 s dwork and expired its acquire deadline
(P-LKTIMEOUT-REMOTE -> P36-RETRY; the D-0912 fail-stop family).

Pitfall: the P236 PRE-NL obligation gate is effectively disarmed — its
`!i_dlm_stale` exemption is always true at that point because the pipeline's
own next-tenure stale mark (`stale_src=5`) is set earlier in the same drain.
The terminal gate is the only obligation gate that fires (P236=0, P244=43 in
s527h).

## 0.75.50 / 0.75.51 (sess529) — live-commit re-fire: immediate was tried, measured, reverted

- 0.75.50 added a `mod_delayed_work(..., 0)` re-fire so a live defer would not
  coalesce onto a pending arm's timer (`queue_delayed_work` refuses when the
  work is pending; s529a: every live defer re-entered 10-12 ms later).
  MEASURED and REVERTED in 0.75.51 (helper removed): the peer truncate was
  unchanged (240/138/227 vs 220/119 ms) and the two-node alternating
  2000-line append went from 4.1 to 18.4 ms per append — with the writer
  parked and the release re-fired at once, every append became its own
  hand-off; the pending arm's ~10 ms had let each node batch a run of
  appends per tenure.  The live re-fire is `queue_delayed_work(ip, 0)`
  again.  Lesson: a contended-file hand-off has a throughput side (tenure
  batching) as well as a latency side; do not shorten the re-fire without
  measuring the ping-pong workload.
- The live defer resets `i_dlm_relab_streak` (progress, not the stuck
  case the 1 s-cap backoff measures).
- `P244-REL-TERMINAL-DEFER` prints `t_us= a= b= b1= b2= c= c1= c2= d=` and
  `P138-BAST` gained `c1=`: a=log_force+alloc-drain, b=settle(b1)+dir
  flush(b2)+targeted AIL drain+coalesced flush, c1=filemap_write_and_wait,
  c2=invalidate_inode_pages2, d=durable loop.  s530a-c: one ~120 ms stage-c
  defer per truncate lap; s530e: repeated ~63 ms stage-b defers.
- Measured shape of one peer "truncate" of a hot-appended file (s529a, ino
  132): FOUR grants on the truncator — open PR, ftruncate EX, close EX,
  stat PR — each a cross-node hand-off (appender release 5-8 ms, wire
  unlock `su` 3-5 ms, truncator release ~7 ms), so the harness's 100 ms
  bound is ~4 hand-offs, not one.  TCP grants are pushed on unlock
  (`promote_waiters` -> `send_grant`, dlm/dlm.c); the requester blocks on a
  1 s condvar (`MXFS_LOCK_ACQUIRE_WAIT_MS`, compile-time) with 60 retries;
  `P138-WAIT` is CAW-only, so TCP has no requester-side wait probe.

## 0.75.52-0.75.54 (sess532-534) — the release drain's page flush: watchdog, parked retry, stage order

- 0.75.52 `mxfs_drain_wb_watch_ms` (default 50, 0 = off): a timer armed
  around both `filemap_write_and_wait` sites in `mxfs_dlm_bast_process`
  (`mxfs_drain_watch_arm/disarm`); if the flush is still running when it
  fires it prints `P-DRAINWB-STALL ino= site= pid= waited_ms= fire=` plus
  the drain task's stack (up to 3 fires per flush).  The harness dmesg
  capture greps `mxfs`, which drops the stack frames — pull raw `dmesg`
  from the node for the stack.
- 0.75.53 `dlm/dlm.c mxfs_dlm_lock_retries`: the `MXFS_DLM_RETRY` branch
  (a request parked because the ledger page is being remastered —
  `P-TAUTH-REMASTER-PARKED/RX`) now sleeps 4 ms doubling to a 100 ms cap
  instead of a flat 100 ms.  Proven by the watchdog: every ~120 ms page
  flush in the peer-truncate lap was the delalloc conversion's
  non-blocking AG probe parked on a remaster and sleeping the flat 100 ms.
  Result: the ~225 ms truncates became ~110-130 ms (s533a-c).
- 0.75.54 stage order in `mxfs_dlm_bast_process`: **a** (log_force +
  alloc-buflist drain) → **c** (`filemap_write_and_wait` +
  `invalidate_inode_pages2`, drain site 1) → **b** (settle to pincount 0,
  log_force, dir data flush, `mxfs_ail_drain_inode_sync`, coalesced device
  flush) → terminal gate → **d**.  Before this the inode was flushed before
  the pages, and the page writeback's ioend then committed the new size
  (`xfs_setfilesize`, `pal/linux/xfs_aops.c`, under ILOCK_EXCL) after the
  inode was already written: every one of the 455 `P244-REL-TERMINAL-DEFER`
  lines across s533a/b/c/f was `live=1`, 32/33 in the truncate laps within
  1 ms of a `P-SFS` on the same inode, and the re-fire (`queue_delayed_work
  (ip, 0)`) coalesced onto the pending 10 ms minimum-hold slice
  (`mxfs_dlm_mht_defer_bast`, qsrc=9), so each hand-off from a node with
  dirty pages was drain (6 ms) + idle (12 ms, `P70-BP lo_ms=11`) + drain
  (5-6 ms).  Data before metadata is XFS's own writeback order, and the
  coalesced flush in b now covers the pages too.  The stage fields on
  `P244`/`P138` are each stage's own duration in the new order
  (`b = p2s_b - p2s_c`, `c = p2s_c - p2s_a`, `d = p2s_d - p2s_b`).
- Tooling: `tools/timeline_2node.py <evidence-dir> test1 test2 --anchor-node
  --anchor <regex> --nth N --before-ms --after-ms [--grep|--exclude]` merges
  both nodes' captures on wall time fitted from the `realns=` lines; the
  fit inherits the nodes' clock skew (test2 read ~6.5 ms behind test1 in
  s533b — check a `P7S-BAST-FIRE` → `P7B-BASTNOTIFY` pair before reading
  cross-node ordering).  `scripts/p244_psfs_histogram.py` pairs every P244
  with the nearest preceding P-SFS.  `P-SFS` is capped at 1500 prints per
  boot, so append laps late in a boot show few.
- Measured shape after 0.75.53 (s533b truncate #1, both nodes): five
  cross-node hand-offs per peer truncate — open PR, the truncator's
  PR→EX self-demote + re-request (`DLM inode lock failed rc=-35` →
  `selfdem=1`) while the appender re-acquires PR then EX (two grants ~6 ms
  apart: open takes PR, the write upgrades), ftruncate EX, the extent free's
  AG hand-off (~32 ms: `P1-AGCONFLICT nq=1` ×2 → blocking request 6 ms later
  → `P12-WORK enter` → `COMMIT` +11 ms → `P85-INODE-DRAIN-CENSUS` +7 ms →
  `P5U-AGUNLOCK` +8 ms), close EX (`xfs_file_release` IOLOCK_EXCL), stat PR.
- AG release fixed sleeps: the prepass push `xfs_ail_push_ag_sync_bounded`
  used to run one push + log_force + `msleep(10)` cycle before it could
  return (v0.3.148 "force at least one cycle"); post-COMMIT `msleep(3)`
  between two log forces (v0.3.104) and `msleep(2)` between the last two
  device flushes (v0.3.102); `mxfs_ag_handoff_grace_ms` is 0.
  `ag_prepass_push_iters` (default 20, 0 = skip the push) is a runtime knob.
- 0.75.55 instrument: `mxfs_ag_bcache_pin_census(pag, &pinned, &inail)`
  (after `mxfs_ag_handoff_closing`) and **`P12-AGREL-STAGES`** printed after
  the unlock in `mxfs_dlm_ag_bast_work_fn`: `pre= commit= f1= pin1= ail1=
  f2= pin2= ail2= dr1= dr2= p3= fl= gate= unlk= total=` (us; each field is
  its own stage — prepass, phase-2 claim→COMMIT, first post-COMMIT force,
  `msleep(3)`+second force, drains+2 flushes, second meta drain, phase-3
  wait, `msleep(2)`+final flushes, publish gate/audit/relmark, wire unlock).
  Measured s535a-d (default): total 22-31 ms = pre 11-13 + f2 ~5 + fl
  3.2-4.0 + gate 1.2-8.6 + unlk 0.5 (local master) / 3-8 (remote); pin/ail
  0 in 32/32 samples at BOTH census points; dr1 ~15 us (occasionally 1-1.4
  ms), dr2 ~0.3 ms, p3 0.  A/B `ag_prepass_push_iters=0` (s535e-h): pre
  4-11 us, total 10-16 ms, truncates 59-89 ms 12/12 under bound (default arm
  3 of 4 laps FAIL, up to 168 ms).
- 0.75.56 `xfs_trans_ail.c xfs_ail_push_ag_sync_bounded`: a HARD-CAPPED
  caller (only the AG worker prepass passes `max_iters`) with an empty first
  sample does `xfs_ail_push_all` + `xfs_log_force(mp, 0)` and returns
  without the forced `msleep(10)`; capped callers that find items and every
  uncapped caller (`xfs_ail_push_ag_sync`, `xfs_super.c` sync path with
  max_iters=0) are unchanged.  Measured: pre 4-16 us, release 10-15 ms.
- 0.75.57: the post-COMMIT `msleep(3)` + second `xfs_log_force` run only
  when the pin census after the first force is nonzero (`P12-AGREL-PINNED`
  names it; never fired in 22 releases).  Release now 5.4-8.9 ms: fl 3.0-5.0
  (`msleep(2)` + two `mxfs_blkdev_flush_epoch` calls that are NO-OPS with
  `mxfs_fua_disable=1`, the default), gate 1.2-1.9 (`mxfs_ag_release_
  publish_gate` = P86 AGI unlinked audit + agifc audit + relmark), unlk 0.5
  local / 2.5-3.5 remote master.  fl is the next removable sleep.
- CREATE ANATOMY on 2/tcp (sess535, tests/ftrace_create_probe.sh): a 4 KiB
  create in a private dir = 8.4 ms small / 13-22 ms past ~400 entries.
  `xfs_create` 5-7.5 ms: `mxfs_dialloc_two_phase` 4.3-5.8 of which
  `mxfs_v5_dlm_inode_reserve_try` (EX NOQUEUE on the new ino) 3-3.7 ms = ONE
  durable authority-ledger commit per create (dlm/tauth_store.c
  `mxfs_tauth_page_write`: 2 reads + CAW ticket + flush + FUA body + CAW
  publish + flush + readback); `mxfs_dlm_dir_modify_refresh` 0.7-1.2 ms in
  big dirs (leaf-range scan, below); `xfs_dir_lookup` 0.6-0.75; `xfs_icreate`
  0.25-0.5.  The reserve commit is the open D-0349 mechanism on 2 nodes.
- 0.75.61 LEAF SCAN ONCE PER TENURE: `mxfs_dir_refresh_stale_data_blocks`'s
  leaf-range branch (dir_coherent_leaf) ran on every modify (its data-branch
  gate uses i_dlm_dir_gen, which never opens on slow-path acquires).  Gate:
  `i_dlm_leaf_scan_epoch/incarn` stamped after a scan taken under a held EX
  (mode==EX, !stale); the next modify skips while epoch, incarnation and EX
  are unchanged (`P6L-SCAN-SKIP`, capped).  Same tuple as the sess495
  `i_dlm_adopt_ok_epoch` adopt-skip.  Knob `mxfs_dir_leaf_scan_once`.
- 0.75.60: fl's `msleep(2)` + second `mxfs_blkdev_flush_epoch` run only
  when `!mxfs_fua_disable` (the helper issues no flush under fua_disable=1,
  so nothing was being settled).  Measured fl=0 on 16/16 releases, release
  1.7-5.6 ms (mean 3.6); what is left is gate 1.3-1.9 ms (P86 AGI audit +
  agifc audit + relmark) and the wire unlock.
- 0.75.58 FILE EX TENURE FLOOR: `mxfs_file_ex_tenure_ms` (default 30, 0 =
  old behavior) and `mxfs_ex_tenure_window_ms(ip)` (dir: shortform window or
  `inode_mht_ms`; REG: the file window; else 0) used by
  `mxfs_dlm_mht_defer_bast`, `mxfs_dlm_dir_tenure_keep_delay` (now accepts
  S_ISREG), the dwork quiet-age gate, the P35-ACQBAST-BATCH arm (dirs or
  REG) and the batch_arm delay.  Why: the MHT defer already applied to
  files, but the keep-delay at `mxfs_dlm_ilock_end` returned 0 for non-dirs,
  so the first op completion after a BAST released the grant, and the P35
  batch arm was dir-only — every truncator syscall (open PR, ftruncate EX,
  close EX, stat PR) became its own hand-off and the alternating append
  handed off every ~1.2 appends.  The file-yield gate (`mxfs_file_yield_gate`,
  parks a user task only at state BAST / foreign DEMOTING) is unchanged and
  composes with the floor: a kept tenure stays CACHED+bast_pending, so local
  ops fast-path until the dwork releases at the first >=grace idle sample or
  the window.
- Truncate anatomy after 0.75.57 (s537d #2, 107 ms): open PR hand-off ~10;
  the truncator's PR->EX upgrade DENIED by the master (`P-CONVBLK-DENY`,
  dlm/dlm.c ~7653, sess12 keeps the GRANTED entry visible and denies) because
  the appender's re-open took PR concurrently -> self-demote + fresh EX
  request (~8-10 ms, one extra BAST round); ftruncate's extent free needs the
  home AG -> `P5D-PREWAIT-DEFERRED-BAST` releases the inode EX before
  blocking (3.4 ms) -> AG hand-off (~8 ms now) -> inode EX re-acquired
  against the appender (~9 ms); close EX ~8; stat PR ~8.  `P-CONVBLK-DENY`
  fires 4-6 times per lap on whichever node masters the inode.  A convert
  queue (keep the converter visible as a holder, BAST the conflicting
  holders, deny only a second converter) is the parked redesign; the
  existing `MXFS_LSTATE_CONVERTING` path (~dlm.c 5930) sets `lk->mode =
  new_mode` and is NOT a holder for `lk_is_holder`, i.e. the invisible-
  holder shape the deny was added to close — do not reuse it as is.
- Clock skew between the two captures varies per lap (test2 read 6.5 ms
  behind in s533b, ~10 ms behind in s534j, ~12 ms behind in s537d): always
  re-derive it from a causal pair before reading cross-node order.
- 0.75.59 WRITE-OPEN EX RIDE: `mxfs_dlm_open_protect(ip, want_ex)` rides
  `XFS_ILOCK_EXCL` (DLM EX) when the open has FMODE_WRITE
  (`pal/linux/xfs_file.c` `xfs_file_open` passes it), SHARED otherwise; the
  fast path admits a write open only on a cached EX.  Knob
  `mxfs_open_write_ex` (default 1; 0 = the old PR ride for every open).
  Why: every open rode PR, so a write open's first write/truncate converted
  PR->EX; with two nodes doing it on one file both held PR, both converted,
  and the master denied the later one (`P-CONVBLK-DENY`) — a full extra
  rotation (drop PR, re-request EX from NL behind the winner's window +
  drain).  Riding EX enters the master's FIFO once as a plain EX request
  that BASTs the holder.  The file window default is 15 ms as of 0.75.59
  (the s538/s539 A/B: append batching identical at 30 and 15, truncates
  70-98 with a 248 tail at 30 vs 39-73 at 15).
- Truncate anatomy at window 15 before the EX ride (s539c #3, 67 ms): ~19
  open-PR wait (appender's grace re-arm + drain), ~31 lost conversion
  (deny, drop PR, appender's 15 ms window + 9.5 ms drain), ~14 the truncate
  (AG0 hand-off 11, close).  No `P5D`/`P152` fires in these truncates: the
  AG wait goes through `P271-AGWAIT-SEAM` (ILOCKs handed off), and after
  close the tenure (held >= window) releases at once.  Outliers: the
  truncator's `P138` stage b (`mxfs_ail_drain_inode_sync` + flush) 38.6 ms
  once in three laps (2-4 ms otherwise); the appender's stage c page
  writeback 21 ms twice (QNAP write-latency variance).

## 0.75.72 (sess559, D-0930) — the untrusted-iget AG bracket never returns EAGAIN

- `xfs_icache.c xfs_iget_cache_miss`, the D-0527 bracket (`XFS_IGET_UNTRUSTED`
  + multi-node): `mxfs_ag_dlm_lock` answers a request that outlived the DLM's
  60-retry budget with `-EAGAIN`, and `xfs_iget`'s `out_error_or_again` arm
  retries ANY `-EAGAIN` forever with `delay(1)` (uninterruptible).  The mount's
  root iget (ino 128, AG 0, `XFS_IGET_UNTRUSTED` in `xfs_mountfs`) therefore
  looped in D state for good whenever AG 0's ledger page had no reachable
  authority (`P-IMAP-UNTRUSTED-AGLOCK-FAIL comm=mount rc=-11` every ~6 s,
  unkillable, D-0930).  The bracket now retries the acquire for
  `mxfs.untrusted_aglock_budgets` DLM budgets (default 5, ~30 s; writable) and
  then fails the lookup with `-EIO` (`P-IMAP-UNTRUSTED-AGLOCK-GIVEUP`), which
  the mount reports as 'Failed to read root inode'; a pending fatal signal
  ends the retry at once.  Invariant: nothing under `xfs_iget` may return
  `-EAGAIN` for a condition that is not a cache race — `xfs_iget` treats it as
  'try again' without bound.

## 0.75.73 (sess560, D-0931) — the mount barrier publishes each foreign slice inside the cut

- `xfs_mxfs_dlm.c mxfs_dlm_mount_recovery_barrier`, replay loop: right after a
  slot enters `replayed` (durable flush + cached views dropped) the barrier
  now runs `mxfs_v5_dlm_mount_cohort_complete` over that ONE slot
  (`P-BARRIER-SLICE-PUBLISHED slot=N`), the way the live reap path
  (`mxfs_dlm_foreign_replay_work_fn`) has always completed each slot behind
  its flush.  The end-of-cut step (d) now completes only `replayed &
  ~published` (a per-slice publication that failed, or every replayed slot
  under a whole-cluster bootstrap term, where the per-slice publish is
  skipped via `mxfs_v5_dlm_bootstrap_adopted` so docs/whole-cluster-restart.md
  6.6's complete-after-all ordering holds) and fails the mount as before.
- Why the old ordering was wrong: deferring every completion to a clean cut
  made two concurrent joiners each owning one slice wait on each other to the
  bound ('slice slot=N is being recovered by another survivor — waiting for
  completion' x66 per node, `P238-RECOV-OWNED why='heartbeating'`, s561).  The
  sess50 cross-slice evidence rule that justified it is obsolete: the replay
  gate (`xfs_log_recover.c` P-RMAN-EVAL, current-safety check ~3236-3320) reads
  only the VICTIM'S OWN sealed fence-time manifest and the victim's own live
  bits, never another victim's grants, so completing slot A cannot change
  slice B's verdicts.  Invariant kept: a slot is published only after ITS
  durable flush and invalidation; nothing is published for a slot that did
  not replay.
- Cross-subsystem: the peer's monitor sees the zeroed sector as
  `P163-RECOVERED` → `mxfs_v5_dlm_mount_resolved_elsewhere` retires the slot
  from the peer's cut ('recovered by a survivor while this mount waited').  The
  matching dlm-side gap — a certified-fenced incarnation is never marked
  REVOKED outside the bootstrap path, so dead provers' FENCING attempts are
  never taken over — is D-0932 (dlm/v5_mount.c).

## sess571 (2026-09-10) — two gates disagree about inode reuse (D-0946)

### The two gates, and why only one of them can see the obligation

**Gate 1 — `mxfs_dialloc_validate_candidate()`, `xfs/libxfs/xfs_ialloc.c:1657.**
Called from *inside* `xfs_dialloc`, after a candidate agino is picked and while
the transaction is still clean. Reads the platter dinode; a live image gives
`-EUCLEAN`, adds the agino to `pag_disklive_q`, and the caller re-picks (its own
probe text: *"no transaction dirtied"*). This IS the containment the sess427
D-0351 ruling asked for — it is not in `xfs_create`, and cannot be, because the
candidate inode number does not exist until dialloc picks it.

It has an early exemption taken **before any platter read**: if
`mxfs_pubob_lookup()` reports this node's own open non-UNLINK publication
obligation for the number, allow — "the live image at home is this node's".

**Gate 2 — the recycle gate, `xfs/xfs_icache.c:1101`.** Reached via
`xfs_icreate` → `xfs_iget` when the create reuses an in-core shell:
`deadshell_create && platter di_mode != 0` → `-EFSCORRUPTED`, on the assumption
that this means *"genuine cross-node incoherence (double-alloc territory)"*.

**`mxfs_pubob_lookup` has exactly two callers in the tree —
`xfs_ialloc.c:1657` and `xfs_inode.c:9075. It is never called from
`xfs_icache.c`.** So gate 2 cannot see the obligation gate 1 relied on, and its
comment's premise is false precisely when gate 1 used its exemption.

### The measured chain (one lap, 5 ms, single node, healthy fs)

    P-FREEOB-CHAIN-LIVE ino=131 epoch=7   free still unpublished, SAME AG EX tenure
    P946-VALIDATE-ALLOW via=pubob ino=132 ogen=2017740547 oepoch=7     gate 1 allows
    P-RECYCLE-GATE ino=132 disk_gen=2017740546 incore_gen=2017740547   platter = ogen-1
    P-CR63-DEFER-DISKLIVE ino=132 — failing recycle                    gate 2 refuses
    P-CR3-CANCEL error=-117 trans_dirty=1 → "Corruption of in-memory data" → SHUTDOWN

`ogen` == in-core generation and the platter carries exactly `ogen - 1`: the
signature of this node's own committed-but-unpublished free. **The inobt is not
stale and the platter is not corrupt.** Both are what the design says at that
instant, so the `verdict=DISK-LIVE=>double-alloc(inobt-stale)` string is a
false-positive label (it is chosen purely on `di_mode != 0`; nothing there reads
the inobt). This is an availability/stability defect, not data loss.

### PITFALL — the errno is not what shuts the filesystem down

Changing `-EFSCORRUPTED` to `-EIO`/`-EEXIST` fixes nothing. The shutdown comes
from cancelling a **dirty** transaction: once `xfs_dialloc` has logged the
AGI/inobt/finobt and counters there is no general rollback, so the shutdown is
the conservative and correct response. **The only clean fix is to make the
decisive refusal happen before the transaction is dirtied**, or to reserve the
candidate before dirtying. (`-EEXIST` would also be a lie — it asserts a
namespace fact that is not true.)

### Do NOT "fix" this by teaching gate 2 the exemption

A second `mxfs_pubob_lookup` plus `di_gen == ogen-1` is a fresh inference from
mutable state, and a false ACCEPT silently overwrites a live inode — strictly
worse than the shutdown. The worst named hazard: an **old free-publication
action surviving reuse** and later writing the freed image over the new
incarnation. Full RULE-5 ruling, including the safe (token-based) form and the
progress rule any allocator-side fix needs: `docs/rulings/d0946-two-gates-reuse-authorization.md`.

### Related knob worth knowing

`mxfs_ifree_eager_durable` (`xfs_mxfs_dlm.c:14801`, 0644, default **0**) makes
each ifree synchronously force the log, drain and flush (`xfs_inode.c:5061`),
i.e. no pending obligation ever exists. Off for pace; with it on, this
condition cannot arise — which makes it the cheapest mechanism confirmation
available, and a containment of last resort.

## 0.84.2 — the explicit fallible acquire (`mxfs_ilock_fallible`) and the inode-scoped registry

`mxfs_ilock_fallible(ip, flags)` (xfs_mxfs_dlm.c ~16054): 0 with every
component of `flags` held and the cluster grant established, or -EIO
(-EINTR for a killed task) with exactly those components released again.  It
registers `{task, ino}` in `mxfs_acqfall_hash` for the duration of
`xfs_ilock`; the classifier arm (2b) in `mxfs_dlm_ilock_begin` consults
`mxfs_acqfall_armed_for(ino)` — the NAMED inode only, because an audited call
takes other inodes' locks inside it (parent, routed conversion) that were never
audited — and writes the verdict with `mxfs_acqfall_give_up`; the caller reads
it with `mxfs_acqfall_taken` (read-and-clear).  Arm (2a) handles the engine's
-EINTR for a killed registered task (`P958-ACQ-KILLED`).  Both arms call
`mxfs_v5_dlm_inode_acq_abandon` (LOCK_CANCEL) before returning.

Audited sites (each: nothing dirty, no transaction open): open
(`mxfs_dlm_open_protect`, its own ride), getattr (`mxfs_getattr_dlm_lock`
returns 1 held / 0 nothing to take / <0 refused, `P958-GETATTR-REFUSED`; caller
in pal/linux/xfs_iops.c fails the stat), the read path (the sticky-PR
`mxfs_read_coherency_envelope` at the top of read_iter, `P958-READ-REFUSED`,
and `xfs_ilock_iocb_read` for the IOLOCK ride of buffered/direct/DAX reads),
splice read.  Writes keep `xfs_ilock_iocb`.  Every other caller — write,
namespace ops, writeback, inactivation, deferred work — still restarts the wait
for ever and is only reported DEGRADED (D-0958 stays open for that class; the
design ruling forbids a timer there).  Verified 2/tcp s586c/d/e/f/h.

A stat through a held fd is the getattr site (s581c/s586d blocked in
vfs_fstat); md5sum fstats THEN reads, so a held-fd md5sum is two serial
fallible waits (two 180 s budgets), not one — a harness window sized for one
wait reads the second as a hang (s586d vs s586h).

## 0.84.5 — the mount's root acquire is a fallible site, and a stalled authority transition is never a shutdown (D-0960)

- `xfs_mountfs` gets the root inode through `mxfs_iget_root_fallible(mp, ino,
  &rip)`: the task registers the root inode as a fallible boundary, the
  untrusted iget's AG 0 acquire (`xfs_icache.c` untrusted-imap loop, now
  `mxfs_ag_dlm_lock_fallible_for(mp, pag, ino)`) registers the AG for the
  same task, and `mxfs_ilock_fallible(rip, XFS_ILOCK_EXCL)` follows.  A
  refusal warns "Failed to read root inode ... a cluster acquire was refused;
  the mount is refused, not shut down" and unwinds through
  `out_free_metadir`.  AG 0's lock is the FIRST cluster acquire a joiner
  makes (measured s590g), the inode's the second; before this the inode one
  shut the joiner down at mount when its page was under a dead authority the
  bootstrap was still taking over.
- The acquire hook has a new arm ahead of the quarantine / pending-recovery
  arms: `rc == -EREMCHG` (the engine's "authority transition stalled 30 s")
  → fallible caller gives up with -EAGAIN (`P960-AUTH-TRANSITION-FAIL`,
  `mounting=` says whether `s_root` was still NULL), non-fallible caller
  parks with backoff and restarts (`P960-AUTH-TRANSITION-PARK`).  Arm (3)
  (force shutdown) is never taken for it.  The 3-attempt loop in
  `mxfs_dlm_ilock_begin` breaks on -EREMCHG like -EINTR.
- `struct mxfs_acqfallible` carries `rc`: `mxfs_acqfall_give_up_rc(ino, rc)`
  names the errno the arm chose (-EIO for an abandoned wait, -EAGAIN for a
  stalled transition), `mxfs_acqfall_taken(e, &rc)` returns it, and
  `mxfs_ilock_fallible` / the read and open rides return that errno instead
  of a fixed -EIO.  Engine side: `.claude/awareness/subsystems/dlm.md` 0.84.5.
- `mp->m_mxfs_mount_complete` (set at the end of `xfs_mountfs`, just before
  `return 0`) is the mount lifecycle mark a refused mount never reaches.
  `xfs_log_quiesce` writes NO SB summary for a mount without it
  (`P960-REFUSED-MOUNT-NOCOVER`, before the `m_mxfs_sb_summary_done` /
  `mxfs_sb_summary_cover` dispatch): the summary lock is a plain cluster
  inode acquire (`mxfs_sb_summary_key`, ino 754974721 on the 24-AG rig LUN),
  and measured s590j a refused mount's unwind (`xfs_log_mount_cancel` →
  `xfs_log_unmount` → `xfs_log_clean` → quiesce) parked on it — the same
  page in transition the mount had just been refused for — until the
  takeover moved again (70 s).  Such a mount committed nothing this
  incarnation, its AIL was pushed above, the counters are derived state the
  last node out recounts under the lock and the next clustered mount
  recounts anyway; and the plain `xfs_log_cover` is NOT taken either (it
  syncs the lazy counters unlocked — the sess30 run14d clobber).  put_super's
  `mxfs_sb_summary_final_sync` is unaffected: it runs only for a mount with
  `s_root`, which only a completed `xfs_mountfs` gets.

## 0.84.4 — readdir is a fallible site (D-0958, the ruling's next audited site)

A listing acquires the directory's cluster lock at up to FOUR places, and each
is now an explicit error-returning acquire that names its stage in
`P958-READDIR-REFUSED ino= stage= rc=` (`mxfs_readdir_refused`):
- `refresh` — `mxfs_dlm_dir_consumer_refresh_fallible` (xfs_file_readdir's
  first call; the lookup path keeps the void `mxfs_dlm_dir_consumer_refresh`,
  both are `mxfs_dlm_dir_consumer_refresh_impl(dp, fallible)`).  A refusal
  skips the eviction and leaves the refresh pending: the reload above it
  re-arms its own flag on a bail, and the eviction gate is `dir_gen` against
  `evicted_gen`, which only a completed eviction advances.
- `sf` — the shortform outer `ILOCK_SHARED` in `xfs_file_readdir`.
- `map` — `xfs_readdir`'s dispatcher, through
  `xfs_ilock_data_map_shared_fallible(ip, &lock_mode)` (xfs_inode.c), which
  checks the verdict after EACH xfs_ilock: the mode computation is shared with
  `xfs_ilock_data_map_shared` (`xfs_ilock_data_map_mode`), and the map
  recheck's unlock+relock to EXCL is a second acquisition asked separately, so
  a refused first lock never becomes a second 180 s wait.  Only with
  `tp == NULL` (the readdir syscall path); a transactional caller keeps the
  plain acquire.
- `leaf` — `xfs_dir2_leaf_getdents`' per-data-block re-acquire.  Entries from
  earlier blocks were already emitted; `ctx->pos` is set from `curoff`, which
  still names the unread block, so getdents64 returns the bytes copied (the
  kernel drops the error when entries were copied) and the NEXT call resumes
  there and gets the error.
- `shard-pin` / `shard-sf` — the dirshard parent pin and a LOCAL-format
  container's outer lock; the container's own settle uses the fallible
  refresh.  On any inner error `mxfs_dirshard_readdir` re-encodes
  `ctx->pos = cookie(slot, r.sub.pos)`: the actor had left the outer position
  at the LAST EMITTED entry's cookie, and the inner position is the next
  unconsumed one.

Test-only knob `mxfs.readdir_leaf_pause_ms` (with `mxfs.watch_ino` naming the
directory) sleeps between the data blocks of a leaf listing with no ILOCK held,
so a peer's create in the gap revokes the cached grant and the next block's
acquire is a real request a fault can meet — how the `leaf` stage is reached
at all under `tests/tcp_lockreq_blackhole.sh WORKLOAD=leaf_midlist`.
`WORKLOAD=held_dir_readdir` drives getdents64 directly on a held directory fd
(`tests/getdents64.py`) because opendir is an open() and fdopendir fstat()s
first — both already-audited sites that would take the refusal before readdir
was reached.

## 0.89.0 — cross-node open-unlink on TCP and the exposed-shell contract (D-0977)

Design: `docs/tcp-authority-ledger.md` "Open-holder marks".  XFS-side surfaces:

- **B6 guard** (`xfs_inactive`, xfs_inode.c ~6440): `-EOPNOTSUPP` from the open-holders
  query is no longer a proceed verdict — every non-zero rc defers (`P87-OPEN-DEFER-ERR`).
  A guard deferral sets `mxfs_b6_deferred`, which excludes the inactivation from the
  keep-grant-cached exit (`P128-INACT-DEFER`) so the EX is RELEASED and the reaper's
  retry takes a fresh grant with a fresh mark snapshot.  The inactivation-exit clear
  rides the plain release (`mxfs_v5_dlm_inode_unlock_open(..., -1)`); the standalone
  CAW clear stays for the ICLUSTER arm only.
- **P90 site** (`xfs_mxfs_dlm.c` ~23957): every release publishes the node's ABSOLUTE
  protected state (`p_open_op` = +1 open/mapped, else -1), never "0 = unchanged".
- **Last close** (`mxfs_dlm_open_last_close`): on TCP the clear is driven by a release —
  `mxfs_dlm_open_clear_ride(ip)` (worker on `m_mxfs_inode_bast_wq`, igrab-held): takes PR
  through `mxfs_dlm_ilock_begin/end` and queues `mxfs_dlm_queue_pr_demote` /
  `_ex_demote` (src 17); the demote's release runs the P90 decision.  Probe
  `P977-OPEN-CLEAR-RIDE`.  `i_mxfs_open_pub` stays set until that release.
- **Evict** (`mxfs_dlm_evict` ~41274): the clear rides the evict release; the retain-PR
  arm is skipped on TCP for a shell with a published mark (a retained grant's later
  noino unlock carries no shell, hence no clear).  `P977-EVICT-MARK-LEFT` names an
  evict that left a mark with no release to carry it.
- **Exposed-shell containment**: (a) `mxfs_dlm_evict_inode_cb` INODE_FREE arm sets
  `MXFS_IF_INCARN_STALE` directly (spinlock context, flag only) when the shell has open
  descriptors or mappings (`EVICT-RING-FLAG ... poisoned=1`); (b)
  `mxfs_dlm_reload_inode_under`, right after the dinode read: a platter generation that
  differs from the in-core one under open descriptors/mappings, on a clean, unpinned,
  published shell, poisons (`mxfs_incarn_poison`, `P977-RELOAD-EXPOSED-MISMATCH`) and
  returns before any adopt arm; (c) `pal/linux/xfs_file.c` re-checks
  `mxfs_inode_incarn_estale` AFTER the I/O lock ride in `xfs_file_buffered_read`,
  `xfs_file_dio_read`, `xfs_file_splice_read`, `xfs_file_write_checks` and after the PR
  hold in `xfs_filemap_fault` — the entry gates ran before the acquire that discovers
  the mismatch.
- Harness: `tests/d0977_open_unlink_tcp.sh` (arm A lifetime + multi-opener + reuse after
  the last close; arm C containment with `open_tracking=0`), on the capture gate
  manifest with a 200 s bound.
