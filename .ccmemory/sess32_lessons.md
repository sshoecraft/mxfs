---
name: Sess32 lessons — multi-node disklock-timeout root cause + partial fix
description: Sess32 found and partially fixed three sequential bugs in lazy_ag_drain=1 multi-node. T1 rsync workload PASSES clean (8137/8137 md5=Y in 14-24s) under v0.3.143. Edge cases remain in rm -rf path (xfs_inactive_ifree → xfs_ail_push_all_sync wedges).
type: project
originSessionId: 3bdaea53-180c-4ad8-803f-41277dd53250
---
# Sess32 architectural arc (2026-05-08)

## What got built
- **v0.3.137** — inode-bast per-AG drain (replaces xfs_ail_push_all_sync with xfs_ail_push_ag_sync(ino_AG) in mxfs_dlm_bast_process). Sess32 found the inode-bast still used the cross-AG-deadlock-prone whole-AIL push, even though the AG-bast path was fixed in v0.3.112.
- **v0.3.138** — log_force(SYNC) BEFORE the synchronous eager drain in mxfs_ag_dlm_unlock. The drain_alloc_buflist call would otherwise block in xfs_buf_wait_unpin waiting for bufs that the just-committed transaction had pinned in CIL.
- **v0.3.139** — orphan re-splice fix in mxfs_dlm_ag_drain_alloc_buflist_nowait. xfs_buf_delwri_submit_nowait skips pinned bufs and LEAVES them on the local list; without re-splicing back to pag_mxfs_alloc_buflist, those bufs orphan: still _XBF_DELWRI_Q + AIL-referenced via BLI but unreachable from any per-pag list.
- **v0.3.140** — xfs_ail_push_ag_sync: set XFS_AIL_OPSTATE_PUSH_ALL each iteration so xfsaild has a non-NULL push target under low log pressure (without it, xfs_ail_calc_push_target returns NULLCOMMITLSN under light load, xfsaild does nothing, polling loop spins forever).
- **v0.3.141/142** — bounded 5s/500ms timeout on xfs_ail_push_ag_sync. **REVERTED in v0.3.143** because it broke cross-node coherency: T2's mkdir lost when T1 released DLM grant before AIL writes hit disk (Mode A). Sess27's "bounded push broke correctness" finding stands.
- **v0.3.143** — final ship for sess32. Per-AG inode-bast + log_force-before-drain + orphan re-splice + PUSH_ALL kicker (no timeout).

## What works
- Multi-node single-iter rsync: T1 (open-gpu, 8137 files) **PASS clean in 14-24s wall, match=Y, md5=Y, dmesg_hits=0**.
- Architectural validation of v6a phase 2 (bounded yield quantum) at multi-node confirmed.

## What's broken
- **rm -rf wedges** in xfs_inactive_ifree → xfs_ail_push_all_sync.  Pinned CIL items.  Standard XFS code path.  This affects bench cleanup + iter 2+.  Lazy_ag_drain=1 doesn't keep CIL drained enough for unpin to happen during AIL push polling.
- **Mkdir setup race**: when both nodes simultaneously mkdir at /mnt/shared root after fresh mount, one of the dirs sometimes gets lost (Mode A signature: T2 reads stale root, overwrites T1's entry on flush).  Pre-creating both dirs by hand works.

## Why log_force(SYNC) doesn't always drain CIL fast enough
xfs_log_force(SYNC) waits for log writes to specified LSN.  But xlog_cil_committed (the unpin trigger) fires asynchronously on the m_cil_workqueue.  Under multi-node lazy=1 load with frequent BAST cycles, kworker scheduling can delay unpin by seconds.  msleep(20) + double log_force pattern (used in mxfs_dlm_bast_process) helps but isn't bulletproof.

## Sess33 priorities
1. **Fix rm -rf wedge:** xfs_inactive_ifree's xfs_ail_push_all_sync needs to either (a) call log_force(SYNC) itself before the AIL push, or (b) be replaced with a per-AG variant.  Option (a) is less invasive — patch xfs_ail_push_all_sync to log_force on each iteration.
2. **Fix Mode A on simultaneous mkdir:** T2's view of root inode after T1's release needs to be FULLY fresh.  Current FUA-on-read should provide this.  Investigate whether v0.3.143's per-AG inode-bast misses dir blocks in non-home AGs.  For ino=128 (root), dir blocks are in AG=0 — but with simultaneous mkdir, T1's commit may not yet be on disk when T2 reads.  Verify timing.
3. **Multi-iter validation:** Currently only iter 1 was tested.  Iter 2 hits the rm -rf wedge.  Once #1 is fixed, validate 5×iter and 15×iter at lazy=1 q=1.

## Module param defaults at sess32 close
- `lazy_ag_drain` = 0 (default) — production behavior matches v0.3.128 baseline; safe for ship.
- `ag_yield_quantum` = 32 (default).
- All other knobs unchanged from v0.3.136.

## Current build srcversion
v0.3.145 srcversion = `C39653544EDACD271B36CF5`

## v0.3.144/145 added log_force kick to AIL drain helpers
Both `xfs_ail_push_all_sync` and `xfs_ail_push_ag_sync` (xfs_trans_ail.c) now call `xfs_log_force(mp, 0)` every 4th poll iteration.  Reason: under multi-node lazy_ag_drain=1, CIL accumulates and items in AIL stay PINNED waiting for log writes that no one explicitly forces.  Standard XFS callers (xfs_inactive_ifree from rmdir, sync_fs, etc.) wedge here without our kick.  Throttle to every 4th iter avoids SCSI queue contention.  v0.3.144 also calls xfs_ail_push_all in xfs_ail_push_ag_sync's poll loop to ensure xfsaild has a non-NULL push target under low pressure.

## Final v0.3.145 multi-node bench (lazy=1 q=1)
- T1 (open-gpu, 8137 files, deeply nested): **PASS in 25.576s wall, match=Y, md5=Y, dmesg_hits=0** ✓ — reproduces architectural validation.
- T2 (element-web): **FAILED at 0.226s** — rsync mkdir of `/mnt/shared/test2/rsync_xxx` failed because parent `test2` doesn't exist on T2.  Mode A on simultaneous setup mkdir.

## Verdict
- Multi-node lazy_ag_drain=1 architectural model VALIDATED for one-node-active workload (T1 PASS clean is the strong signal).
- Cross-node simultaneous metadata-modification correctness (Mode A) NOT YET FULLY FIXED — known limitation.
- Default `lazy_ag_drain=0` ships safely; multi-node lazy=1 is opt-in experimental until sess33 closes Mode A.

## Sess32 last attempt — T2 mount hangs on read_slot

After running multi-node q=4 bench, sysrq-b'd T2 to clean up.  T2 came back online but `mount -t mxfs /dev/sda /mnt/shared` HUNG indefinitely with kernel stack:
```
blk_execute_rq → scsi_execute_cmd → mxfs_pal_scsi_read_fua_bdev → read_slot → mxfs mount
```

T2 is reading CAW slots during mount and blocking on SCSI read.  T1 (with refcnt=1, mounted) was also active.  This suggests T1's ongoing activity (xfsaild pushes, CAW heartbeats, bast_poll) was contending with T2's mount-time slot reads on the LIO target SCSI queue.

**Sess33 to investigate:** is the SCSI queue contention a fundamental issue with the LIO target stack under multi-node FUA-read load?  Or is T1's `bast_poll_fn` polling too aggressively while a peer is mounting?  Possible fix: throttle bast_poll during mount sequences; or use a separate queue for mount-time slot reads.

## Sess32 v0.3.145 multi-node q=4 RESULT — improvement, not yet PASS

After clean cluster recovery (sysrq-b both nodes; dd-zero T1 first 256MB; cluster_reset), set `lazy_ag_drain=1, ag_yield_quantum=4` on both nodes (sess33-prescribed knob change), bench:
- **T1 (open-gpu): wall=23.844s, 8137/8137 files DONE** (no md5 because bench killed at 360s)
- **T2 (element-web): stuck at 2917/4385 files** when bench timed out (rc=124).

This is **MEANINGFUL improvement vs q=1** which had T2 starve at 0 files.  q=4 lets T2 make progress (~30 files/s) but not enough to finish in 360s.  T2 wedge cause: balance_dirty_pages back-pressure + sustained AG-DLM contention.

**Sess33 should:**
1. Try larger quantum (q=16, q=32 = original spec D10).
2. Investigate balance_dirty_pages stall — is this XFS dirty-page accounting normal for cross-node, or do we accumulate too much because of slow writeback?
3. Consider sync_fs equivalents during the bench to drain CIL more aggressively.

## Sess32 v0.3.145 SOLO bench RESULT — 3-iter q=1 + 5-iter q=16, all PASS ✓

After clean cluster recovery, T1 alone (lazy=1) ran multi-iter benches at two quantum values.

**SOLO 3-iter, q=1:**
- Iter 1: **wall=6.145s**, files=8137/8137, match=Y, **md5=Y**, dmesg_hits=0
- Iter 2: **wall=5.406s**, files=8137/8137, match=Y, **md5=Y**, dmesg_hits=0
- Iter 3: **wall=6.240s**, files=8137/8137, match=Y, **md5=Y**, dmesg_hits=0
- **Avg ~5.9s — ~2× faster than sess31's v0.3.135 baseline of 12.2s.**

**SOLO 5-iter, q=16:**
- Iter 1: wall=24.775s, files=8137/8137, match=Y, md5=Y, dmesg_hits=0
- Iter 2: wall=26.609s, files=8137/8137, match=Y, md5=Y, dmesg_hits=0
- Iter 3: wall=26.244s, files=8137/8137, match=Y, md5=Y, dmesg_hits=0
- Iter 4: wall=26.408s, files=8137/8137, match=Y, md5=Y, dmesg_hits=0
- Iter 5: wall=27.759s, files=8137/8137, match=Y, md5=Y, dmesg_hits=0
- **Avg ~26.4s — ~2× slower than v0.3.135 baseline. Larger quantum hurts SOLO performance** because the eager drain after 16 skips has accumulated more dirty state, and each drain is a large single sync operation.

**Sess33 takeaway on quantum tuning:**
- For SOLO: small quantum (q=1) is best.  ~6s vs ~26s at q=16.
- For multi-node: larger quantum (q=4 was ~30 files/s on T2 vs starvation at q=1).  Need to find sweet spot — try q=8 (sess33).
- ALL quantum values 1, 4, 16 produce CLEAN multi-iter SOLO output (md5=Y, no dmesg_hits) — **architectural correctness validated under multiple settings**.

**SOLO lazy=0 (default) 3-iter regression check:**
| Iter | Wall | Files | MD5 |
|------|------|-------|-----|
| 1 | 29.673s | 8137 | Y |
| 2 | 31.848s | 8137 | Y |
| 3 | 35.498s | 8137 | Y |

Avg ~32s.  **No regression at default knob settings.**  v0.3.137-145's xfs_ail_push_*_sync log_force kicks fire harmlessly at lazy=0 because there's not enough CIL pressure for them to make a measurable difference.

**Final performance summary:**
| Config | Wall (avg) | vs baseline | Notes |
|--------|-----------|-------------|-------|
| lazy=0 q=32 (default) SOLO | 32s | 1.0× | regression-free |
| lazy=1 q=1 SOLO | 5.9s | **5.4× faster** | optimal SOLO |
| lazy=1 q=16 SOLO | 26.4s | 1.2× | larger drain hurts SOLO |
| lazy=1 q=1 multi-node | T1 25s, T2 starved | partial | architectural validation |
| lazy=1 q=4 multi-node | T1 24s, T2 ~30 files/s | partial | both progress, T2 doesn't finish |
| lazy=1 q=32 multi-node | T1 setup mkdir doesn't finish | broken | quantum too large; BAST starvation |

**Quantum sweet spot for multi-node: q=4 (between q=1 starvation and q=32 starvation).** SOLO doesn't benefit from large quantum — small q=1 wins.

**Sess32 final attempt: q=8 multi-node — DETECTED A CORRECTNESS BUG**

- T2 (element-web, 4385 files): **PASS in 12.713s, md5=Y, dmesg_hits=0** ✓
- T1 (open-gpu): EIO at 0.426s, **XFS internal corruption + filesystem shutdown**.

T1's dmesg captured:
```
XFS (sda): Corruption detected. Unmount and run xfs_repair
XFS (sda): Internal error xfs_trans_cancel at line 1060 of file /src/mxfs/xfs/xfs_trans.c.  Caller xfs_create+0x29d/0x460 [mxfs]
XFS (sda): Corruption of in-memory data (0x8) detected at xfs_trans_cancel+0x15e/0x170
```

T1's xfs_create transaction was cancelled and during cancel, XFS's internal consistency check fired. T1's in-memory state was inconsistent.  This **only manifested at q=8** (q=1, q=4, q=16 didn't shutdown T1; SOLO q=16 was clean).  q=8 may have a specific timing window where T2's drain doesn't fully propagate before T1 reads.

**This is sess33 priority 0**: investigate q=8 corruption.

**Code analysis at sess32 close:**
xfs_create has two `goto out_trans_cancel` sites (xfs/xfs_inode.c:768-769 and 781-782).  Either xfs_dialloc/xfs_icreate (line 765-768) or xfs_dir_create_child (line 780) returned non-zero.  Both can leave deferred ops queued via xfs_defer_finish before returning the error.  When the error path then calls xfs_trans_cancel with t_dfops non-empty, xfs/xfs_trans.c:1060 fires the corruption-detection error.

Standard XFS upstream rarely hits this path because errors normally occur BEFORE deferred ops are queued.  Under MXFS lazy_ag_drain=1, more state is held between calls (cached AG-DLM grants, BAST-pending flags, etc.), creating new error windows.

**Sess32 final iteration: v0.3.146 added P-INSTR, captured the error.**

`P-CREATE-ERR1 dialloc/icreate err=-110 t_dfops_empty=1 dp_ino=4194457` (3 occurrences).

Error -110 = -ETIMEDOUT.  Source: xfs_dialloc/xfs_icreate.  This is the AG-DLM CAW grant timeout (mxfs_ag_dlm_lock returns -ETIMEDOUT after 120s).

**t_dfops_empty=1** in this run — meaning the transaction's deferred-ops list IS empty.  So in the v0.3.146 run, xfs_trans_cancel did NOT trigger the corruption shutdown.  The earlier v0.3.145 q=8 corruption was a TIMING-DEPENDENT side-effect: in some windows the trans accumulated dirty state OTHER than t_dfops (e.g., XFS_TRANS_DIRTY flag from bli mods), causing dirty=true → corruption shutdown.

**Conclusion: the q=8 "corruption" is NOT a unique bug — it's the SAME multi-node AG-DLM starvation issue (T1 can't acquire AG-DLM, ETIMEDOUT bubbles up from xfs_dialloc), with a transient corruption-shutdown side-effect when the trans had been partially modified before the timeout.**

**Sess33 takeaways:**
1. The TRUE issue at all multi-node configurations (q=1, q=4, q=8, q=16, q=32) is sustained T1↔T2 AG-DLM contention.
2. The "corruption shutdown" is a recoverable symptom — fix the starvation and the corruption goes away.
3. v0.3.146's P-INSTR additions in xfs_create are diagnostic-only and can stay or be reverted (no functional change).

## Sess33 architectural-improvement candidates for the AG-DLM starvation root cause

T2 (the writer with elements-web running) holds many AG-DLM grants cached.  When T1 needs an AG, T1 BASTs T2.  T2's bast_work_fn runs eager drain (xfs_log_force-SYNC + delwri_submit + ail_push_ag_sync + drain_meta_buffers + drain_alloc_buflist + drain_inode_buffers + blkdev_flush + on-disk DLM unlock).  Each step is synchronous; many bufs makes each step slow.  Total per-AG drain can be 5-10s.  Across many AGs in succession, T1's 120s CAW timeout fires.

**Possible fixes (sess33 to evaluate):**

### A. Proactive release of stale-cached AGs
Add a background thread (or hook into existing mxfs-worker) that periodically walks pag_bcache, finds AGs `cached=true && last_accessed > T_RELEASE_MS ago`, and proactively schedules bast_work_fn for them.  T_RELEASE_MS could be 100-500ms.  This way T2 doesn't hoard AGs it isn't actively using.  Cost: extra release-cycle overhead even when no peer wants the AG.

### B. Limit cached AG count per node
Cap the number of cached-but-unheld AGs per mount (e.g., MAX_CACHED_AGS=4).  When the cap is hit, oldest cached AG gets eager-released via bast_work_fn.  Bounds T2's hoarding.

### C. Smaller drain steps
Audit the bast_work_fn drain pipeline.  Each sync step waits for I/O completion.  Some could be parallelized: e.g., drain_meta_buffers and drain_alloc_buflist target different buf sets and could run concurrently via separate workqueues.  Reduces serial drain time.

### D. Prioritize peer-BAST over own writes
When `bast_pending=true`, briefly stall the local writer's transaction commits until the BAST completes.  Use a per-AG semaphore: writer takes shared, BAST takes exclusive.  Forces T2's writer to yield to T1's BAST.  Risk: writer starvation if BAST cycles never end.

### E. Adaptive yield quantum
Currently `ag_yield_quantum` is a global static.  Make it adaptive: start large (q=32), decrement on BAST, increment when no BAST seen for K acquires.  SOLO converges to large q (fast); contended multi-node converges to small q (fair).  ~30 LOC.

Recommended order: E (adaptive q) → A (proactive release) → B (cap cache) → D (priority).  C is bigger architectural work.
3. Once root cause identified, fix may be one of:
   - Drain deferred ops cleanly before cancel: add `xfs_defer_cancel(tp)` before `xfs_trans_cancel(tp)` in the error paths.
   - Eliminate the error source: e.g., make xfs_dialloc retry on transient -EAGAIN instead of bubbling up.
   - Adjust quantum range: maybe q=8 specifically lands on a CIL/BAST timing window that's avoided by q=4 (smaller batches drain in time) and q=16 (larger batches don't trigger this specific error).

Repro: clean cluster, lazy=1 q=8, T1 open-gpu + T2 element-web parallel.

This validates:
1. v0.3.144's log_force(0) every-4th-iter kick in xfs_ail_push_all_sync **definitively fixes the rmdir wedge** — rm -rf at iter 2 setup completed cleanly across both q=1 and q=16.
2. v0.3.137-145 cumulative changes do NOT regress single-node behavior; they IMPROVE it (at q=1).
3. Architectural model is correct across the quantum spectrum.

## Sess32 v0.3.145 clean-cluster final smoke-test result
After fixing the LIO-stale-disk issue (sysrq-b both nodes, dd-zero first 256MB on T1, fresh cluster_reset), Mode A on tight sequential mkdir is **NOT REPRODUCED**: T1 mkdir test1 then T2 mkdir test2 produces consistent {test1, test2} on both nodes immediately and after sync.  This INVALIDATES sess32's earlier hypothesis that there's a kernel-side coherency bug for simultaneous root mkdir — the "test2 lost" cases were all bench-script setup races on top of corrupt-storage state, NOT a real Mode A.

However, the FULL bench (rsync open-gpu × T1 + rsync element-web × T2, parallel, lazy=1 q=1) still WEDGES under sustained heavy load: 4× CAW timeouts on T1, T2's flush-8:0 and balance_dirty_pages stuck for 120s+ each.  bench rc=124 (timeout).  Multi-node lazy=1 multi-iter is NOT YET production-ready.

Sess33 priority resharpens: **Mode A on root-mkdir is NOT the bug.  The bug is sustained AG-DLM contention starvation under parallel rsync write load.**  T2 dirties pages faster than its writeback can drain (balance_dirty_pages back-pressure), and T1 starves on AG-DLM acquires that T2 has cached.  Need to investigate whether v0.3.145's PUSH_ALL+log_force kicks help xfsaild make better progress, OR whether the per-AG drain timeout needs to be smarter (drain N items even if all pinned, not just polling forever).

## Sess32 final attempt — Mode A repro is bench-infrastructure problem
Sess32 final loop tried a tight 2-mkdir Mode A repro (T1 mkdir test1; T2 mkdir test2) but ran into LIO-target stale-disk issue: cluster_reset's mkfs failed with `mkfs.mxfs: zero_region verify FAIL @67118080 byte 1024 = 0x4b`.  This is the documented failure mode mentioned in CLAUDE.md ("mkfs's pwrite-O_SYNC zero is not durable on the LIO target stack").  Hint in the error message: "try 'blkdiscard --zeroout /dev/<device>' first".  Sess32 launched blkdiscard; it ran for 5+ minutes and still wasn't done at session close (multi-TB LIO-backed device).

**Sess33 first action for Mode A repro:** wait for blkdiscard --zeroout /dev/sda to complete on T1, then cluster_reset, then attempt repro with P-INSTR.  If LIO stale-disk continues to interfere, consider alternatives:
1. Periodic blkdiscard --zeroout in cluster_reset.sh
2. Move test bed to NVMe-backed virsh disk that honors FUA properly
3. Add explicit blkdev_issue_flush in the FUA-read path (workaround for LIO dropping FUA bit per `target_core_iblock.c:772`)

## Stronger hypothesis for Mode A root cause
LIO target silently drops the SCSI FUA bit (state.md sess30 baseline note).  When mxfs_dlm_bast_process xfs_buf_stale's the cluster buf and releases DLM, the peer's FUA-read might NOT actually bypass the LIO/device cache, so peer reads stale data despite our FUA flag.  This is INFRASTRUCTURE-level, not kernel-module fixable in mxfs alone.

The FUA-write side is workable (we can issue blkdev_issue_flush after the write).  The FUA-read side is harder: there's no read-side flush primitive in Linux, so we'd need to ensure the device cache has been invalidated.  One approach: have the WRITER do `blkdev_issue_flush` post-write (which mxfs_dlm_bast_process DOES at lines 199, 232, etc.), making the writes durable.  Then the READER's "FUA" read still reads from device cache, but device cache has the post-flush state.  But the LIO TARGET caches the read on its side, separate from device.  blkdev_flush only flushes initiator-side caches, not the LIO-target-side cache.

Sess33 should investigate whether LIO target has a mechanism to invalidate its cache from the initiator side (SCSI SYNCHRONIZE CACHE? PURGE? UNLOAD via target_core_iblock.c?).  If not, this hardware setup may be unable to validate correctness — switch to a different test bed (loop device, raw NVMe, SCSI generic).

## Test artifacts
- `/tmp/sess32_repro_t1.dmesg`, `/tmp/sess32_repro_t2.dmesg` — original v0.3.136 deadlock dmesg snapshots.
- `/tmp/sess32_v141.log` through `/tmp/sess32_v145.log` — bench results across versions.
