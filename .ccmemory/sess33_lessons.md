---
name: Sess33 lessons — adaptive yield quantum + ordered bast wq + AIL stall-abort; lock-inversion deadlock identified as structural
description: Sess33 shipped v0.3.147 with 3 architectural changes (adaptive quantum, dedicated ordered bast wq, bounded AIL drain with stall-abort + reschedule). Multi-node parallel rsync still wedges — root cause identified as user-process ILOCK-during-CAW lock-inversion deadlock requiring deeper XFS refactor than any single-session fix.
type: project
originSessionId: sess33-2026-05-08
---
# Sess33 architectural arc (2026-05-08)

## What got built
- **v0.3.147** (srcversion `40FE985FD379F1460B45D73`) — three changes layered:
  1. **Adaptive yield quantum** (prescription E from sess32_lessons.md). New per-pag fields `pag_dlm_yield_quantum_eff` + `pag_dlm_skips_no_bast`. Halve eff on peer BAST (fairness signal), double after `MXFS_AG_YIELD_DOUBLE_THRESH=4` consecutive non-contended eager drains.
     Module param `ag_yield_adaptive` default 1.  KEY DESIGN CHOICE: when adaptive=1, lazy-init starts at **1** (not at cap) and grows via doubling.  Starting at cap=32 wedged immediately because by the time first BAST arrived, 32 unlocks worth of dirty state was already in the AG and the drain pipeline exceeded peer's 120s CAW timeout.
  2. **Dedicated ordered workqueue** for AG BAST work fns (`mp->m_mxfs_ag_bast_wq`, `alloc_ordered_workqueue`).  Previously `schedule_work` used system_wq which spawned 7+ parallel `bast_work_fn` invocations all polling `xfs_ail_push_ag_sync`, saturating event-pool concurrency.  Ordered serializes to ONE concurrent execution.  Verified via `[kworker/u4:1+mxfs-ag-bast/sda]` worker name.
  3. **Bounded AIL drain with stall-abort** (`xfs_ail_push_ag_sync_bounded`).  New module param `ag_bast_stall_iters` default 600 (~6s @ 10ms poll).  When per-AG AIL items count fails to decrease for stall_iters consecutive iters AND iter > min_iters=64, returns -EAGAIN.  bast_work_fn on -EAGAIN ABORTS the release sequence (does NOT drop the AG-DLM grant — sess32 v0.3.141-142 reverted that as Mode A regression), reschedules itself for next attempt.  P67-INSTR diagnostics added.

## SOLO regression-free
- v0.3.147 lazy=0 (default) SOLO 3-iter: **13.65s, 12.59s, 13.45s** avg ~13s.
  - Sess32 baseline at lazy=0 was ~32s.  This is a measurable IMPROVEMENT at default settings (likely because of adaptive code's lazy-init taking the legacy path safely; possibly variance).  No regression.
- v0.3.147 lazy=1 adaptive=1 cap=32 SOLO 3-iter: **17.08s, 16.44s, 15.82s** avg ~16.5s.
  - Sess32 v0.3.145 lazy=1 q=1 SOLO was 5.9s.  Sess33 SOLO regression vs PEAK SOLO of ~3×.  Reason: adaptive starts at eff=1, grows via doubling to cap=32; with no contention, eff settles at cap=32 within seconds, but cap=32 SOLO was already 26s at sess32.
  - To recover sess32's 5.9s SOLO peak, set `ag_yield_adaptive=0 ag_yield_quantum=1` explicitly.  This is a SOLO-specific tuning regression for adaptive=1 default that's an acceptable cost for the convergence-under-contention property.

## Multi-node parallel rsync still wedges — STRUCTURAL deadlock
P67-INSTR captured the EXACT stuck items via `xfs_ail_push_ag_sync_bounded`:
```
P67-INSTR AG-AIL-STALL agno=N iter=ITER buf=2(pinned=0) inode=1 other=0
```
- 2 buf log items + 1 inode log item per AG.
- Items are NOT pinned (`pinned=0`).  CIL is current; log_force(SYNC) drained.
- xfsaild idle in S state.  AIL has items but xfsaild can't push them.
- ROOT CAUSE: **lock-inversion deadlock on ILOCK**.  T2's user-process holds ILOCK on inode-X (e.g., open-gpu file being created).  T2's user-process is blocked in `mxfs_dlm_caw_lock` CAW poll on AG-Y (held by T1).  T2's bast_work_fn for AG-Z (which T1 BAST'd because T1 wants AG-Z) calls `xfs_ail_push_ag_sync`.  AIL items in AG-Z include inode-X's pending iflush.  xfsaild's `iop_push` does ILOCK trylock — fails because T2's own user-process holds it.  The item never drains.
- Mirror cycle on T1 simultaneously.  Neither node can release because its xfsaild can't push the items required to flush its dirty AG metadata.

The stall-abort (sess33 part 3) breaks the SYMPTOM (workqueue saturation, indefinite blocking) but NOT the dependency cycle.  After stall-abort, the next BAST cycle hits the same wedge again (because user-process still holds ILOCK).  Stall-abort cycles every 6s rescheduling; T1's CAW still timeouts at 120s; when it does, T1's ILOCK drops, but T1 immediately re-acquires a different inode's ILOCK and re-enters CAW poll.  Cycle continues indefinitely.

## Sess34 prescription — break the lock-inversion

The fix requires one of:
- **(F) Drop ILOCK during AG-DLM CAW poll.** Refactor `xfs_alloc_vextent_*` → `mxfs_ag_dlm_lock` slow path to release the caller's ILOCK before the CAW poll, re-acquire after.  This is the architecturally correct approach but invasive: needs xfs_alloc_vextent caller to know which inode's ILOCK is held, pass that down, and handle the re-acquire correctly with the buf locks already held.  XFS upstream's lock ordering may require per-callsite refactoring.
- **(G) Detect ILOCK contention in CAW poll and proactively release our own cached AGs that peer is BAST'ing.** In `mxfs_ag_dlm_lock` slow path's CAW poll loop, periodically walk this mount's pags for `pag_dlm_bast_pending && pag_dlm_cached`; for each, attempt an inline drain+release.  The inline drain runs in user-process context with whatever ILOCK is held — it'll succeed for AGs whose AIL items are in DIFFERENT inode/AG from the held ILOCK.  Statistically this should break most cycles since user typically operates on a different AG than peer is BAST'ing.
- **(H) Reduce ILOCK hold scope before AG-DLM acquire.**  Investigate whether xfs_alloc_vextent really needs ILOCK held, vs. just AGI/AGF buffer locks (which AG-DLM is the cluster layer above).  Possibly drop ILOCK at xfs_bmap_btalloc entry, re-take after.

Recommended: (G) first as a less-invasive experiment.  If it breaks deadlock at >50% of cases, ship it as a partial fix.  Then (F) for full correctness.

## Default settings safe to ship
- `lazy_ag_drain` default 0 — pre-sess33 behavior fully preserved.
- `ag_yield_adaptive` default 1 — matters only when lazy=1.
- `ag_yield_quantum` default 32 (cap, unchanged).
- `ag_bast_stall_iters` default 600 — only affects lazy=1 multi-node BAST path.

Multi-node lazy=1 remains EXPERIMENTAL until prescription (F) or (G) lands.

## Key code touchpoints sess33 added
- `xfs/libxfs/xfs_ag.h:152-170` — pag_dlm_yield_quantum_eff + pag_dlm_skips_no_bast
- `xfs/libxfs/xfs_ag.c:244-247` — init both fields to 0 (lazy-init)
- `xfs/xfs_mount.h:357-371` — m_mxfs_ag_bast_wq workqueue field
- `pal/linux/xfs_super.c:632-651` — alloc/destroy m_mxfs_ag_bast_wq
- `xfs/xfs_mxfs_dlm.c:1535-1540` — module params (mxfs_ag_yield_adaptive, MXFS_AG_YIELD_DOUBLE_THRESH)
- `xfs/xfs_mxfs_dlm.c:~1672-1700` — fresh-acquire lazy-init + use eff
- `xfs/xfs_mxfs_dlm.c:~2140-2200` — adaptive halve in bast_notify
- `xfs/xfs_mxfs_dlm.c:~2185-2225` — adaptive double in unlock-exhaust
- `xfs/xfs_mxfs_dlm.c:~2378-2410` — queue_work via m_mxfs_ag_bast_wq
- `xfs/xfs_mxfs_dlm.c:~2670-2715` — bounded ail drain + stall-abort + reschedule
- `xfs/xfs_trans_ail.c:806-905` — xfs_ail_push_ag_sync_bounded with P67 diag
- `xfs/xfs_trans_priv.h:136-146` — declarations

## Test artifacts (in /src/mxfs/tests/sess33_artifacts/)
- `wedge_v0.3.146_q8.txt` — original sess32 leftover wedge stacks
- `wedge_v0.3.147_q32cap.txt` — adaptive cap=32 wedge stacks
- `smoke_v0.3.146_q1.log` — sess32 baseline reproduction (T2 PASS T1 starved)
- `adaptive_v0.3.147_q4cap.log` — q=4 + adaptive wedge with bnobt RIGHT-FAIL (intermittent)
- `static_v0.3.147_q4.log` — static q=4 also wedged
- `adaptive_grow_v0.3.147rev2_cap32.log` — initial=1 adaptive grow (eff=1 visible in P39, still wedged)
- `orderedwq_v0.3.147rev3.log` — single bast_work serialized (1 D-state) but still wedged
- `p67_bench.log` — P67-INSTR captured stuck items
- `stall_abort_v0.3.147.log` — stall-abort cycling AGs every 6s
- `solo_final_v0.3.147.log` — adaptive SOLO 3/3 PASS clean ~16s
- `solo_summary_v0.3.147rev2.txt` — SOLO summary

## Stuck-item count signature (constant across all wedges)
`buf=2 inode=1 other=0` per AG.  The 2 bufs are AGF + AGI (or one of those + a btree block).  The inode is whatever inode is currently being modified by the user-process holding ILOCK.  This signature suggests the ILOCK of the SAME inode that's actively being created/written is the deadlock vertex.
