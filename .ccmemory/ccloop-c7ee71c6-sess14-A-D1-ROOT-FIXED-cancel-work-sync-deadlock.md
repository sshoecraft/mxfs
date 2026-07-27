---
name: ccloop-c7ee71c6-sess14-A-D1-ROOT-FIXED-cancel-work-sync-deadlock
description: sess14: D1 ROOT PROVEN+FIXED v0.11.119 — pre-CAW/yield cancel_work_sync deadlock vs stalled AG drain (stack-captured 2×); P67-NOWAIT-SKIP guard 417 h…
metadata:
  type: project
tags: [d1, root-cause, fixed, cancel-work-sync, deadlock, 32-node, p67, verified-pending]
---

# sess14-A: D1 fence-wedge ROOT CAUSE — PROVEN and FIXED (v0.11.119)

## The capture (2026-07-26 ~14:50, lap 4 of d3_dirring at v0.11.118)
cache_coherency all-32 NO_TERMINAL_RECORD at 60s budget. Straggler = test23: its worker
bash/32841 never completed subtest-1 setup (echo>file truncate+write+sync); 31 peers parked
innocently at the cv_write MQTT barrier. test23 dmesg: P67-INSTR AG-AIL-STALL agno=27
stuck_ino=56623232 ilocked=1 in_ail=1 → sess13's owner probe fired 17×: P67-STALL-OWNER names
owner=bash/32841, nvcsw climbing ~33/s (periodic wakes), grant heads FROZEN, ail_min==tail==
stuck item's own lsn. **P67-STALL-OWNER-STACK captured TWICE (60s apart), identical:**

    write_cache_pages → iomap_do_writepage → iomap_writepage_map → xfs_map_blocks
    → xfs_bmapi_convert_delalloc → xfs_bmapi_convert_one_delalloc   [ILOCK-EXCL held]
    → xfs_bmapi_allocate → xfs_bmap_btalloc → xfs_alloc_vextent_start_ag
    → ...prepare_ag → mxfs_ag_dlm_trylock → __mxfs_ag_dlm_lock+0x1fa
    → cancel_work_sync → __cancel_work_timer → __flush_work → wait_for_completion

## The cycle (AB-BA through the workqueue)
1. bash holds ILOCK-EXCL(ino X) inside delalloc-convert writeback; needs an AG.
2. __mxfs_ag_dlm_lock's PRE-CAW-INLINE-DRAIN scans other AGs with bast_pending&&holders==0
   and calls cancel_work_sync(&pag_dlm_bast_work) before inline-draining.
3. The in-flight bast work for AG-27 is draining, stalled on ino X's AIL item (needs the
   ILOCK bash holds); it stall-aborts (~2s) and RE-ARMS every peer BAST cycle.
4. cancel_work_sync never returns while the work keeps re-running → bash parks silently
   (this capture 60-120s; sess12-E 222s). NO print at the park site (why every sess12/13
   candidate was eliminated "by absent prints"). GPT's grant-head theory REFUTED.
5. Sess12-E now fully explained incl. the ending: peer noino fence → designed shutdown →
   peer BASTs STOP → work goes idle → cancel_work_sync returns → "bash woke at 785 doing a
   fresh xfs_ilock" (P-SHUTDOWN-FENCE + P71-UNDERFLOW pair). The shutdown was the designed
   noino escalation on the peer while bash's AG never drained.

## The fix (v0.11.119, srcver C7689957B8402C7BF7C64A6)
Both scan sites — __mxfs_ag_dlm_lock PRE-CAW drain (~xfs_mxfs_dlm.c:28331) and
mxfs_dlm_yield_basted_cached_ags (~21510): replace cancel_work_sync with non-blocking
`cancel_work()`; if it didn't steal a PENDING work and work_busy() shows RUNNING → SKIP the
AG (ratelimited marker **P67-NOWAIT-SKIP**) — the running worker already owns the drain;
waiting for it is the defect. Steal-success or idle → inline drain as before.
Liveness strictly improves: the ILOCK holder proceeds, finishes its op, releases the ILOCK,
and the deferred drain completes on the next BAST cycle (self-resolving, not deadlocked).

## Verification so far (RULE 4 step 2b — cause proven by stack, fix at proven site)
- 8 laps at .119 (4× storm+cache_coherency recipe, 4× storm+full-chain
  cache_coherency/dlm_scaling/dir_reuse_coherency/fence_during_write): ALL PASS, normal
  wall (cc 23-29s, drc 106-114s), zero NO_TERMINAL_RECORD, zero shutdowns.
- P67-NOWAIT-SKIP fired 417+ times (ratelimited floor) across 27+ nodes = the old parking
  spot is visited constantly under this load; each hit is a would-have-been sync-wait.
- One transient P67-STALL-OWNER (test1, rm holding two ILOCKs) resolved in ONE abort cycle,
  owner proceeded within ms — the intended post-fix shape.
- Historical wedge rate ~1/10 chain sequences → keep counting chain laps before closing;
  the sess12-E shutdown variant needs more laps/sessions of exposure.

## Also this session
- P172-WRTR ring (v0.11.118): NON-PERTURBING per-write provenance ring in xfs_buf_submit_ex
  (pal/linux/xfs_buf.c): 8192×64B, records every dir-metadata + inode-cluster write
  (daddr/owner/cnt/slot-masks/lineage-crc32c/gmode/flags/comm/realns), NO printk. Dump via
  mxfs.dirring_dump=1 poke or auto-throttled at P26-IGET-FAIL. Sanity-verified live (rm
  shows cnt 12→11 + slot-bit clear). Harness tests/d3_dirring.sh (storm→rm→cc, captures on
  failed>0 / NO_TERMINAL_RECORD / unreachable); analyzer tests/d3_ring_analyze.py (merged
  per-daddr timelines, SLOT-REVERT/CRC-REVERT/NONEX-WRITE flaggers).
- D3 has NOT re-hit in 8 laps at .118/.119 (sess13 scored 3/5) — keep grinding storm+chain
  laps; ring stays armed; dirwr stays 0.
- NEW defect observed (D5, OPEN): "DLM reload BAIL ino=… i_lock contended" livelock —
  readdir-context reload of a stale dir self-collides with its own read-held i_lock
  (down_write_trylock can never succeed from the readdir path); caller retries in ~3.5ms
  cycles, EXACTLY 201 prints per victim episode (~0.7s spin), storms of 804-5628/node/day;
  victims incl. ino 128 (root). Print at xfs_mxfs_dlm.c:19047; retry loop caller near
  :22741. Episodes end when the reader gives up/serves stale — but 32-node pileups
  contributed p to the lap-4 minute-scale stalls. Root design flaw: reload-from-readdir
  cannot take the write lock it needs. NOT yet diagnosed/fixed — next session: read the
  :22741 caller loop, decide serve-stale-once vs defer-reload-to-unlock.
