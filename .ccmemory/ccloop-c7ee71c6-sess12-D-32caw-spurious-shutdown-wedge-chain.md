---
name: ccloop-c7ee71c6-sess12-D-32caw-spurious-shutdown-wedge-chain
description: sess12-D REVISED 32/caw diagnosis: fence test is NEGATIVE (nobody should die); test14 spuriously shut down via folio-wedge→AG11-AIL-stall(stuck_ino i…
metadata:
  type: project
tags: [32-node, mpath, fence, spurious-shutdown, ail-stall, noino, rule6, open]
---

# sess12-D: 32/caw failures fully decomposed — the REAL defect is a spurious shutdown

## Correction to sess12-C's framing
fence_during_write is a NEGATIVE test (tests/suite/fence_during_write.sh): all N nodes
storm-write WINDOW seconds; asserts still-writable + own-data-intact + ZERO
fence/shutdown dmesg events + shared-dir drained. Nobody is supposed to die.

## What actually happened at 32/caw (test14 journal, monotonic)
- ~595: writeback kworker/u9:4 wedges in folio_wait_bit_common <- write_cache_pages
  (hung_task at 746: "blocked for more than 151 seconds", flush-252:1 on dm-1/mpatha)
  — a folio stays LOCKED (its locker presumably parked on a DLM acquire).
- 740: P67-INSTR AG-AIL-STALL agno=11 stuck_ino=23068801 iflags=0x20000 ili_fields=0x4001
  in_ail=1 ilocked=1 → stall-abort → P67-AG-BAST-STALL ag=11 release deferred (repeats).
  The stuck inode is ILOCKED while its item sits in the AIL = the CLAUDE.md Design
  Tension "ILOCK held across CAW poll" family at 32-node mpath churn.
- 763: P-NOINO-LISTDRAIN ino=158 ags=0 "fence stalled; drained mxfs alloc buflists
  (xfsaild cannot write _XBF_MXFS_ALLOC_QUEUED bufs)".
- 774: XFS Metadata I/O Error (0x1) at mxfs_dlm_noino_bast_work_fn+0x19b
  (xfs/xfs_mxfs_dlm.c:15884) → Shutting down filesystem → P-WITHDRAW → P163 stamp
  slot=11 node=1100364042. NO scsi/dm/mpath errors anywhere in the window → NOT infra.
- Aftermath: test14 = shutdown-but-mounted ZOMBIE. mountpoint says mounted; every
  acquire prints P-SHUTDOWN-FENCE. run.sh pre-assert (mountpoint-based) does NOT
  detect zombies → next test (cache_coherency rerun) waited on coord barrier for the
  zombie → all-32 NO_TERMINAL_RECORD 60s stall. My "latency probe" 41.7s/never results
  measured the ZOMBIE, not healthy converge (healthy peers converge in 0.6-1.6s).

## Decomposition of the three observed failures
1. fence@32/caw FAIL: test14 spurious shutdown (THE defect); test23/24/27
   still-writable probe failed transiently during test14's withdraw window (survivors
   blocked on locks mastered at the dying node — bounded collateral, verify after fix).
2. cache_coherency rerun stall: zombie-hostage barrier (harness gap: pre-assert should
   detect shutdown zombies — statfs/write probe, not mountpoint).
3. cache_coherency #1 (BEFORE fence, healthy cluster): 650/654 — readers cluster-wide
   missed node17.txt+node25.txt (sees+content) in-window; files fully visible later.
   Separate converge-latency/publish-lag question at 32-way shared-dir churn. May
   share the same AIL/publish backpressure root — re-test after the shutdown fix.

## Next session RULE 4 plan
1. Read xfs_mxfs_dlm.c:15884 error path (what write fails with 0x1 in
   noino_bast_work_fn; is the shutdown escalation even correct there?) + the P67
   stall-abort → deferred-release loop (did AG-11 EVER release? 310719 page_ms!).
2. Identify the folio-locker: who holds the folio lock >150s (likely parked in
   mxfs_dlm_ilock_begin/CAW poll while holding a locked page — echo w > sysrq via
   serial or hung_task stacks further down the journal show more tasks).
3. Repro: rig mpath 32 (UP), re-prep 32/caw, run fence_during_write — first FAIL took
   1 run; capture with watch_ino armed on the hot dir + stuck ino.
4. Recover test14 first: umount -f + rmmod or full re-prep 32/caw (zombie state
   currently persists!). criteria.json holds the honest FAILs.

## Matrix status (context for readiness)
Everything else green at .114: tcp column complete (1/2/4/16 full + 32 spot + wd),
16/cawp full+wd, 32/cawp spots, 1/cawd+1/cawp perf (quiet-host 103%×2), 16/caw
prep+cache_coh, cawd 2/4/8/16+physical at .113 (delta inert). Criteria answer: NO —
this 32/caw spurious-shutdown family is the open front.
