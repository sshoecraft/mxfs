---
name: ccloop-c7ee71c6-sess242-aglock-livelock-ledgered-mechanism-split
description: sess242: livelock LEDGERED; sess241 "tracking loss" REFUTED for test16 (cached=1, demote ran, re-acquired); root suspects = requester sends NO BASTs…
metadata:
  type: project
---

# sess242 — AG-lock livelock: ledgered + mechanism split

## Done
- LEDGERED D-AGLOCK-ORPHAN-EX-TRACKING-LOSS-LIVELOCK-488 (critical; 34 open / 81).
  NOTE: its mechanism text carries the sess241 hypothesis, which this session
  PARTIALLY REFUTED — needs revision once proven.
- Full bit→host map: `dmesg | grep 'DLM initialized' | tail -1` per node gives
  slot + node_id. bit1=test16 bit2=test13 bit12=test30 bit25=test9 bit28=test25.

## Evidence (revises sess241)
- test16/ag=1: in-memory tracking NOT lost. BAST-RX from 5318s: holders=0
  cached=1 sched=1. Demote work ran (P12-READOPT churn vs local rsync, P12-WORK
  COMMIT demoting @5621.827 = last ag=1 event). No stuck kworker. Slot
  lmod=5621878 = 51ms post-COMMIT → unlock likely succeeded, blocked local rsync
  re-acquired EX immediately → current disk bit = legitimate cached hold
  awaiting a BAST that never arrives. grep 'unlock exhausted' = 0 on test16.
- test13/ag=2: BAST-RX @5620-5626 holders=0 cached=0 sched=0 → possible TRUE
  orphan class (different from test16!). Unchecked: 'unlock exhausted' there.
- BAST mis-targeting: test30 receives+NAKs BASTs for ags 0,1,2,4,5 (never held
  them); test16 NAKs ags 0,2-6. All BAST traffic fleet-wide ceased ~5626s when
  other nodes' rsync/mv cleanup exited.
- test30 sweep (P5G, 4.2s/AG, still running @6440s) SUBMITS NO BASTS: P265
  submitted frozen at 12572. Holders with cached=1 would release if BASTed →
  no-BAST-from-bounded-sweep is the prime livelock-root suspect.

## Code facts
- caw_unlock_gen_body (dlm_caw.c:8355): wall-clock unlock retry deadline
  (5000ms) armed ONLY for INODE+ICLUSTER. type=AG keeps tight 100-retry cap;
  -EIO swallowed by void mxfs_v5_dlm_ag_unlock (v5_mount.c:6118). The sess6
  comment documents this exact swallowed-strand mode for ICLUSTER. Candidate
  for test13-class strands. Exhaust print: "dlm_caw: unlock exhausted".
- mxfs_ag_dlm_lock_bounded (xfs_mxfs_dlm.c:36651) is a dumb 40×100ms poll of
  __mxfs_ag_dlm_lock(mp,pag,true); any BAST submit is deeper (35897 → v5
  ag_lock_nb v5_mount.c:5909 → caw). UNREAD — next session step 1.
- bast_work_fn demote tail: 41250-41681, COMMIT 41356, unlock 41667.

## Next
1. Read requester acquire path: where BAST submit happens, dedup/rearm gating,
   target resolution; why test30 sends none since ~5626s.
2. Holder census (test13 + others): unlock-exhausted? own-ag cached=1 in-core
   now? → split healthy-cached vs true-orphan across the 25 AGs.
3. Fix per RULE 4 + RULE 5 consult; then recover rig, re-run board on .488.
