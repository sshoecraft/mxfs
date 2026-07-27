---
name: ccloop-c7ee71c6-sess6-fix26-wb-deadlock-orphan-nak
description: sess6: 2 roots LIVE-CAPTURED+FIXED — FIX-26 flusher-vs-bast-drain folio/ilock AB-BA (writepages admit) + zombie AG grant from membership-purge (orpha…
metadata:
  type: project
tags: [dir_reuse, deadlock, writeback, dlm, membership, ag-lock, fix26, orphan-nak, 8tcp]
---

# sess6 (ccloop c7ee71c6, 2026-07-25): two live-captured roots, both fixed

## Context
Inherited sess3's open front: "dir_reuse @8/tcp round pace + verify-phase wedge
(NO_TERMINAL_RECORD), dabuf-HOLE suspected." Sessions 4-5 crashed with zero work.
Both the "verify wedge" and the "pace fail" attributions turned out WRONG — the
real causes were two independent deadlocks plus harness reporting gaps.

## ROOT 1 — FIX-26: writeback-submission vs bast-drain AB-BA (v0.11.87)
Live capture on test8 (both stacks D-state, persisted 70+ min, survived across
runs because nothing re-prepped):
- flusher kworker/u12:20+flush-8:0: write_cache_pages folio LOCKED →
  iomap_writepage_map → xfs_map_blocks → xfs_bmapi_convert_delalloc →
  xfs_ilock(EX) → mxfs_dlm_ilock_begin demote-wait (P73 ino=10485894 req=5
  mode=3 state=3=BAST work_busy=3 every 30s).
- mxfs-ino-bast worker: mxfs_dlm_bast_process → filemap_write_and_wait →
  __folio_lock on the flusher's folio. Permanent cycle.
- Collateral: sync hangs forever behind dead flusher → EVERY later run's
  create-wave `sync` wedged at round 1 (state.md sess3 said "verify wedge" —
  actually create/sync; rank8 never reached wave1-done).
FIX: xfs_task_in_writepages() registry (pal/linux/xfs_aops.c, stack-resident
hash nodes bracketing iomap_writepages in xfs_vm_writepages) + widened
mxfs_ilock_admit_ioend (FIX-25) to admit writepages tasks: nested EX under
still-granted EX/PR mirror, counted in ex_holders → release aborts at holder
gate + re-arms. P25 print now src=ioend|writepages.
Precursor (why dirty delalloc under PR): 30s dirty-expiry flusher on pages whose
EX→PR downconvert ... P26PRE probe added (see below); common population is the
DRAIN's own conversion after mode pre-clear (mode=0 relflush=1 dem_cur=1 —
NORMAL). Foreign-task (dem_cur=0) events are the wedge population — must pair
with P25 src=writepages.

## ROOT 2 — zombie AG grant via membership-change table purge (v0.11.92)
mxfs_dlm_update_active_nodes PURGES THE WHOLE LOCAL LOCK TABLE on every
membership change; purge timing differs per node during mount ramp. test6
acquired AG9 (master test2 whose view had settled) → test6's next membership
event purged its own GRANTED record → later release: local -ENOENT
(P5U-AGUNLOCK-ENOENT) → NOTHING SENT → master's zombie entry starved the whole
cluster: test2 re-BASTs 1/s 500+s (P12-AGBAST-RX holders=0 cached=0 schedule=0,
"page_ms" = ms-since-bast-pending, holder field = stale last-holder comm);
test1 rm-rf stuck in mxfs_trans_preacquire_inode_ags HOLDING DIR ILOCK
(P132-ILOCK-STUCK); mkdir stat blocked behind it → SYSCALL_HANG → 3/3 runs DNF.
Leftover rm survived its run's abort and poisoned the next runs (S-state,
mxfs_pal_cond_timedwait pending_wait — NOT killable-tested).
FIX: orphan-grant NAK — mxfs_dlm_release_orphan_if_unheld (dlm.c; guard scans
local table for ANY-state entry incl. pend_waiter in-flight → -EBUSY) wired at
(a) AG unlock-ENOENT (ag_orphan_nak flag, send after rwlock drop), (b) v5
wrapper mxfs_v5_dlm_ag_orphan_nak called from mxfs_dlm_ag_bast_notify when
holders==0 && !cached && !scheduled && pending>3s. P5N-AG-ORPHAN-NAK on fire.
FIX-20b mxfs_dlm_send_unconditional_release was the existing primitive
(gen=0 release, process_remote_release treats as unconditional).
DEFERRED: reverse arm (master purged, holder keeps fs-layer grant → concurrent
EX after 20s settle freeze) — unobserved, must be reasoned/instrumented before
final verdict.

## Harness fixes
- run.sh dir_reuse ct: floor-150 EXCEEDED tt=120 kill box → wedges died
  recordless (the NO_TERMINAL_RECORD mystery). Now hang(N*10,fl20) < ct < tt-15.
  N>=12 infeasible (hang>tt) — owned by pace defect.
- dir_reuse_coherency.sh clean-slate rm now includes drc_dchang_r*,
  drc_hang_rm_r*, drc_hang_mkdir_r* — run 155524Z's artifact had 5 boots of
  stale captures (dchang_r14 etc.) that fabricated a false narrative.

## Instrumentation added (all default-off/capped, in tree)
- fix26_delay_ms module param: xfs_convert_blocks holds (folio locked) until
  bast lands or N ms — deterministic collision driver.
- P26PRE-DELALLOC-SUBEX (cap 200): writeback converting delalloc at mode<EX,
  full dlm state + dem_cur.
- scripts/fix26_wb_bast_exerciser.sh (v4). Lessons: natural window is µs;
  conv=notrunc has NO delalloc (must truncate-realloc); mode==EX collisions are
  served by fast path BY DESIGN (only sub-EX parks); reader loops serialize
  behind writer drains (~2.8s/contended-read of 16MB-dirty file).

## Verification state (v0.11.92/93, srcver 84A5D6346B21D4756912E93)
dir_reuse ×3 green (102/101/102s, 0 fails) + ×3 on .87; cache_coherency
558/558 8s; dlm_scaling 7/7 14s; P73=P132=P146V=WPADM=0 current tenure.
FIX-26 admit + orphan NAK not yet observed firing live (counters armed:
WPADM='src=writepages', P5N). P146V was 2-5/run in sess3, now 0.

## Env facts
- run.sh 8 tcp uses hostnames test1..test8; prep ~35s (208s worst).
- Build ~3-4 min full. dmesg ring rotates <1h at probe volume — grep -c
  counters are recent-window only.
- kernlogs in run dirs: '[Sat Jul 25 HH:MM:SS 2026]' format.
- virsh -c qemu:///system destroy/start testN = the wedged-node reset.
