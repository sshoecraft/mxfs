# xfs (XFS-6.19 fork + MXFS overlay)

**Owner files**: `xfs/` (331 files), `mxfs_clayer/` (4 files), top-level `mxfs.c`
**Last updated**: 2026-07-25 (ccloop c7ee71c6 sess6 — FIX-26 writepages admit + AG orphan-NAK; dated section at end)

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
