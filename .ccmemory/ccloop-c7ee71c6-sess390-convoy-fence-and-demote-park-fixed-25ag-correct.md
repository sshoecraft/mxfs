---
name: ccloop-c7ee71c6-sess390-convoy-fence-and-demote-park-fixed-25ag-correct
description: sess390: 25-AG wedge root = EFI at AIL min behind a local shared-AG wait (convoy) → 0.20.1 convoy-aware noino fence; split-under-protest root = nonbl…
metadata:
  type: project
tags: [sess390, 474, PACE-388, AGI, EFI, convoy, wait_demote, trylock, 0.20.1, 0.20.2, 25AG, board]
---

# sess390 state (ccloop c7ee71c6)

## Builds
- 0.20.1 sv 99EB07EF68CF5DBAB243DAD — convoy-aware noino fence (B): xfs_ag.h pag_mxfs_agwait_inflight/since_ns; xfs_mxfs_dlm.c: bracket around the blocking mxfs_v5_dlm_ag_lock; mxfs_noino_freeze_is_convoy(); P-NOINO-CONVOY; P-AILMIN EFI detail (needs #include "xfs_extfree_item.h"; daddr→agno helper is xfs_daddr_to_agno(), not a macro).
- 0.20.2 sv 1F8CA561D9F5547F362ADD8 — __mxfs_ag_dlm_lock: `if (nonblock && pag->pag_dlm_demoting) return -EAGAIN` before mxfs_ag_dlm_wait_demote (P-AGTRY-DEMOTING, stat trydemote=). RIG NOW: 64 AGs, 32/32 mounted on 1F8C.

## Measured
- sess389 25-AG wedge frozen item = XFS_LI_EFI (0x1236=4662) on both nodes; test7 probe armed, zero P129 → EFI alone; owner = inodegc/inline-inactivation extent free blocked on the shared AG 13 s; fenced inode already freed (40 peer EX waiters). Convoy, not deadlock.
- 0.20.1 @25AG: laps 1-2 all PASS, 0 wedge; convoy 103x/3 nodes (ag matched, agwait_ms ≤14 s, frozen ≤4); lap 3 pace FAIL only; BUT splits under protest 9→24 on 3→6 nodes: P87-TARGET-TIMEOUT stage=ilock ocomm=rsync → stack: rsync iput → xfs_inactive INLINE → truncate → defer_finish → __xfs_free_extent → mxfs_ag_dlm_trylock → __mxfs_ag_dlm_lock → mxfs_ag_dlm_wait_demote (ILOCK held) while the SAME AG's demote publication stage needed the ILOCK (COMMIT demoting 9 ms earlier; peer waited 11.4 s).
- 0.20.2 @25AG laps 1-3: 0 wedge/0 shutdown/0 DRAIN-STUCK/0 split/0 P87 timeout/0 P88/0 BADHEAD/0 dirty-cancel; P-AGTRY-DEMOTING 839x/16 nodes; P-NOINO-CONVOY 505x/9 nodes. rsync_paired lap1 18 s, lap2 58 s (4 nodes fail barrier), lap3 5 nodes >60 s = PACE-388 pace arm only.
- 64-AG board on 0.20.2: chunks A-C all PASS (rsync_paired 18 s; FLAKY label = 25-AG FAILs in its 11-run window); chunk D result in the sess390 transcript.

## Harness lessons
- ONE lap per foreground call (264-332 s). Two laps in one call overran 10 min and lost the sweep.
- run.sh overhead measured ~20 s/row in this session (chunk B: 6 rows 156 s walls overran a 300 s cap; soak aborted) — derive wrapper = walls + 20 s×n + 15 s. Use `grep --line-buffered` on run.sh output or the kill eats the lines.
- Fleet sweeps: dmesg only; `journalctl -k -b` blows a 25 s ssh cap on long-uptime nodes (23/32 timed out).

## Open next (ruling order)
1. Lifecycle routing (GPT item 1): noino path for -EAGAIN INEW/IRECLAIM/INACTIVATING and -ENOENT NEED_INACTIVE — requeue, retain grant; instrument reachability first.
2. (C) close local re-adoption once BAST pending (P12-READOPT 2918 fleet after 3 laps @25AG) — PACE-388.
3. Ledger: #474 and PACE-388 and D-AGI updated with sess390 evidence (tests/logs/ag25_sess390_convoy_demote.txt). 52 open. CRITERIA NOT MET.
