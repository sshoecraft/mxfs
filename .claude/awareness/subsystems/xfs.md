# xfs (XFS-6.19 fork + MXFS overlay)

**Owner files**: `xfs/` (331 files), `mxfs_clayer/` (4 files), top-level `mxfs.c`
**Last updated**: 2026-07-30 (ccloop c7ee71c6 sess28, 0.11.239-245 — **THE DIR EPOCH IS A PROPERTY OF THE INODE NUMBER, NOT OF AN INCARNATION**: `caw_tombstone_slot`/`caw_claim_inherit_epoch` deliberately carry a slot's `dir_epoch` across an idle gap and `grant_meta` outlives the inode, so every `master_epoch > i_dlm_dir_valid_epoch` compare was cross-incarnation — permanently true for a dir created on a recycled inode number, and `P32E-DIREPOCH-FENCE` (ships 1) then skipped every flush of it. NEW FIELD `i_dlm_dir_valid_incarn` (stamped at all 11 baseline assignment sites) + NEW PREDICATE `mxfs_dir_epoch_superseded()` used by BOTH consumers. NEW MODULE PARAMS: `mxfs.dir_epoch_incarn_gate` (default 1, the fix), `mxfs.creator_baseline_stamp` (default 0, MEASURED NO-OP — the epoch is 0 at every publish site). REMOVED: `mxfs.create_baseline_trackers` (dead code + latent sleep-in-atomic). NEW PROBES: P210-CREATOR-BASELINE (unconditional exposure counter), P211-EPOCH-{REBASE,NOGRANT,FOREIGN}; `base_state=` added to P195. NOTE THE SHIPPED ASYMMETRY: the fence consumer ships enabled while its maintainer `mxfs.dir_epoch_adopt` ships disabled (sess49 AG double-free) — a fence with no maintainer eventually refuses everything. See the dated section at the end.)

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
2. **bast_work_fn for an AG runs at most one at a time.** Routed through `m_mxfs_ag_bast_wq` ordered queue. Multiple parallel invocations starve xfsaild and saturate event-pool. v0.3.147.
3. **`pag_dlm_acquire_lock` MUST NOT be held across `mxfs_v5_dlm_ag_lock` CAW poll.** The CAW poll sleeps up to 120s; `mxfs_dlm_ag_meta_iodone` needs `pag_dlm_lock` to fire deferred releases the CAW grant may be waiting on. Holding deadlocks.
4. **AG-DLM grant validity = on-disk slot state.** `pag_dlm_cached=true` is a hint for fast-path acquire; the authoritative grant is the disk slot, not the in-memory flag.
5. **The AG-meta track hold is a ONE-SHOT token — released by writeback OR abort, never leaked (2026-07-21 fix).** Every logged AG-meta buffer gets an extra `xfs_buf_hold` + `pag_dlm_meta_pending++` from `mxfs_ag_meta_track` (idempotent per dirty epoch via `XFS_BLI_MXFS_AGMETA_TRACKED`). That hold's ONLY writeback releaser is `mxfs_dlm_ag_meta_iodone` (installed as `b_iodone`, which fires only in `__xfs_buf_ioend`). On a forced shutdown the dirty AG-meta buffers are aborted WITHOUT writeback (`xfs_buf_item_release` abort branch → `xfs_buf_item_done`, no ioend), so iodone never fires — the OLD code leaked the hold and wedged `xfs_buftarg_drain` at umount (agi/inobt/finobt stuck `b_hold=2`, PROVEN via the new P-HOLDRING dump). FIX: a one-shot `atomic_t bp->b_mxfs_agmeta_hold` armed by track, consumed (`cmpxchg 1→0`) by EXACTLY ONE of iodone (writeback) or the new **`mxfs_ag_meta_reclaim_abort(bp)`** — called from `pal/linux/xfs_buf_item.c`'s abort branch to drop the hold + dec pending (logs P-AGMETA-RECLAIM). NEVER re-key AG-meta cleanup on `b_iodone` alone — abort paths don't run ioend. See ccmemory `pve-agi-wedge-ROOT-agmeta-track-hold-leak-FIX-and-pve1-hung`.

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

## Historical Bugs

- **sess26(ccloop) dir_reuse_coherency 8/tcp whole-block clobber — ROOT FOUND (capped gen-bump), lever `dir_gen_per_handoff` (DEFAULT 0), build `965BDBD3`**: PROVEN (RULE 4, dataclobber=1 detect run on a real loss: `bufgen==dirgen==379` on the clobbering writes) — the fast-path EX-grant epoch-handoff gen-bump (`mxfs_dir_epoch_adopt`, `xfs/xfs_mxfs_dlm.c` ~12119/12156) is CAPPED by `if (i_dlm_dir_gen <= i_dlm_dir_loaded_gen) i_dlm_dir_gen++`, so it bumps only ONCE per reload cycle. The 2nd..Nth intra-round fast-path handoff fails the cap → NO re-invalidate → a cached dir DATA block stays `bgen==dir_gen` and aliases a peer-superseded image as fresh → the read-path pre-read invalidation (`xfs_da_btree.c:3363`, `bgen != dir_gen`) never fires → holder RMWs/destages a stale base → **whole dir DATA block of a peer's dirents durably reverts** (round1 lost node2_f13-32.md5 contiguous). FIX (gated lever): `if (mxfs_dir_gen_per_handoff || dir_gen<=loaded_gen) dir_gen++` at both fast-path sites → i_dlm_dir_gen advances on EVERY cross-node handoff. SAFE: the master dir epoch advances only on a real cross-node handoff (a peer held EX), never while we hold EX continuously, so no spurious mid-tenure re-read. RESULT: loss reduced **whole-block (~20 entries) → SINGLE-entry (readdir=799)**. RESIDUAL (next session): the per-handoff re-read also re-reads LEAF blocks, bringing in a leaf NEWER than this node's in-core data-fork EXTENT MAP (peer grew the dir) → `!(flags & XFS_DABUF_MAP_HOLE_OK)` internal error (`xfs/libxfs/xfs_da_btree.c:2876`, 511×, trips `dmesg_clean`). OPPOSITE of sess20's stale-leaf hole (postread_leaf_only won't fix it); needs a COORDINATED extent-map refresh on the per-handoff invalidation (NOT leaf exclusion, which re-exposes sess20). sess68 (P68-MAPDIVERGE=0) proved maps agree at modify-PRELOCK — the hole is the per-handoff re-read window only. Keep `dir_gen_per_handoff` default 0 until leaf/map consistency is solved; build is keeper-equivalent at default. Decisive lesson: the clobber is NOT detectable at any async write/read chokepoint (gen doesn't advance on fast handoff = read-guard blind; write-time disk-compare is racy + can't distinguish a legit remove); the reliable fix is making the per-handoff coherency signal (i_dlm_dir_gen) actually fire every handoff. See ccmemory `sess26-PROGRESS-dir-gen-per-handoff-wholeblock-to-single-but-dabuf-hole`.
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
- REMAINING (stack-proven, run36): dir-grow edge — xfs_dir2_grow_inode→xfs_bmap_btalloc blocks up to 61s on ONE peer-held AG with dirty trans + dir DLM EX held; needs bounded/rotating AG acquire (design in ccmemory sess5-END-abba-grow-stack-proven-design-next).
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
  -EDEADLK → P109 self-demote+fresh-EX dance.
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
(clyde /home/steve/disk.img, xfs_data_offset from tools/chk_mxfs -v) to
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
AAA-ccloop46ef-sess7-ROOT-broot-bytes-oops-and-wedge-chain).

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
it cost dlm_scaling@32 its 50 ops/s floor — see ccmemory
ccloop8ba7-sess7-printk-volume-is-a-perf-criterion).

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
HOST — see ccmemory `sess385-clyde-ext4-jbd2-wedge-shared-lun-on-root-fs`.

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
- RULE-5 ruling (ccmemory `ccloop-c7ee71c6-sess390-GPT-ruling-noino-fence-convoy-intents-lifecycle`):
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
  Both attempts to arm it failed at 25 AGs (ccmemory
  `ccloop-c7ee71c6-sess390-readopt-close-two-failures-latch-design`): blocking
  waiters wedged ILOCK holders; pinned re-adoption livelocked/starved peers.  The
  re-adoption storm is the UNLOCK-side race (P12-ULBP schedules the worker async; a
  re-adopter wins 0→1 first) — the next design latches the handoff at the last-
  holder unlock and brackets `mxfs_ag_dlm_wait_demote` as an AG wait.
  `mxfs_ag_dlm_lock_resfree()` = RESOURCE_FREE class (pregrant, P271 seam: hold
  nothing, may wait for a handoff).  RULE: a nonblock AG acquire never sleeps;
  a blocking acquirer that may hold ILOCKs never waits at an admission gate.
