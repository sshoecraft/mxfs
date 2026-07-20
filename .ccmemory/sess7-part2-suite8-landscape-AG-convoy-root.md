---
name: sess7-part2-suite8-landscape-AG-convoy-root
description: sess7 part2: 8/tcp suite 13/17 (build CAE7BFBD); FIX-20b phantom reconcile (build 5C571CCA); dlm_fairness root = cross-AG hold-and-wait convoy (test8…
metadata:
  type: project
---

# sess7 part 2 — suite landscape + the AG convoy root

## Suite landscape (build CAE7BFBD, run94, clean cycle)
8/tcp FULL suite: **13/17 PASS** — cache_coherency, strong_consistency, posix_multi, mmap, zero_silent_loss, dlm_membership, scaling_curve, dlm_scaling, rsync_paired, crash_consistency, fence_during_write, fault_netpartition, precond_readiness all PASS 8/8. FAILs: dlm_fairness (7/8), dir_reuse_coherency (0/8 in-suite = 480s TIMEOUT, reached r24 @1113s — pace, plus one MAP_HOLE transient r22), soak (dmesg hit = fallout), tcp_dlm_scaling (0/8: node rounds 39/150 + drained=13; wedge at t=1297 = the phantom class on ino 16781703 master-held 184s → test1 shutdown).

## FIX-20 evolution (phantom grants)
- Root class: requester's 6s ACQUIRE_WAIT retry races the late grant → grant DISCARDED (Bug-67 guard) → master GRANTED w/ no local mirror → unlock_gen !found returns -ENOENT with NO wire msg → phantom holds forever; BASTs to the "holder" hit bast_notify NONE/NL arm → p135_held reads LOCAL mirror (empty) → swallowed.
- FIX-20 v1 (build 8A85233D, run95): unlock_gen !found+gen0+remote → always send release. **REGRESSED**: the common eviction/ENOENT unlock path (bulk sequential inos at drop_caches) flooded masters with wire releases under table_rwlock-wr → dlm_fairness 7/8→4/8, dlm_scaling 7/8. REVERTED.
- FIX-20b (build 5C571CCA): targeted only — (1) `mxfs_dlm_send_unconditional_release` (dlm.c; gen=0 wildcard at master's process_remote_release removes sender's GRANTED entry + promotes; master-local = no-op), exported via `mxfs_v5_dlm_inode_release_unconditional`; (2) strike detector in bast_notify NONE/NL arm: 2+ no-mirror BASTs within 15s (i_dlm_phantom_bast_j/_n fields) → set i_dlm_reconcile_pending + DEMOTING + queue bast_process; (3) bast_process P6Z-REL-NOTHING arm consumes the one-shot flag: if !stranded (fresh grant_gen==0 re-check) → send the mirror-bypassing release (P-PHANTOM-RECONCILE-SENT).
- P73-WAITSTALL every-30s self-report exists in the ilock_begin demote-wait — THE wedge signature line (state/ex/bast_pend/work_busy).

## dlm_fairness/tcp_dlm_scaling ROOT (run96 evidence, PROVEN chain)
- test4 "Corruption of in-memory data (0x8) at xfs_defer_finish_noroll (xfs_defer.c:721)" shutdown @273 = NOT corruption: "DLM AG lock failed: ag=14 rc=-110" 23µs earlier — defer-finish couldn't get AG-14 for 240s → error-path shutdown → test4 zombie wedges everyone (dlm_membership 0/8, P1-AGCONFLICT storms; **fs-shutdown node does NOT surrender its DLM grants — separate liveness gap**).
- AG-14 was held by test8 EX for **122s** (master test6: 90 P1-AGCONFLICT vs holder=688185811 from 158s; test8's first P5U-AGUNLOCK ag=14 @280.3).
- test8's mv was itself BLOCKED acquiring AG-3 (P1-AGWAIT @155, P36-RETRY ~1/s, retries 59→…, ~60s) — **cross-AG hold-and-wait**: node-level AG-grant CACHING defeats transaction-level AG ordering; nodes form a convoy each caching one AG + waiting on another, broken only by 1s retry staggering; long holds then kill defer-finish victims (rc=-110 → shutdown policy).
- ALSO seen on test8 during the churn: **P-DBLALLOC agno=3 agbno=302** ×2 (allocator handed out a block holding node2's live dir-block, wasfromfl=0, tenure=5/6) + P117-AGMETA-STALE-CLEAN — the bnobt divergence family resurfacing under 8-node fairness churn (watch; may be detector-recovered).
- NEXT (RULE 4): instrument P1-AGWAIT to print the transaction's held-AG set (tp->t_mxfs_ag_unlocks, exists since v0.3.106) — decides fix shape: empty ⇒ only node-cache holds ⇒ honor pending BASTs on other cached AGs when blocking on an AG acquire; non-empty ⇒ true transactional ABBA ⇒ needs ordering/backoff (-EAGAIN trans restart).

## Pace levers landed (in 5C571CCA)
- P44-GRANTDIREPOCH cap 60000→2000 (was ~6MB serial traffic/run at 700/s vs 11.5KB/s console).
- mxfs_leafprobe default 1→0 (P2R/P2W storm ~700/s in rm phases).
- P60-GENMATCH-STALE FUA compare-read gated behind instr/dirwr.
- NOT touched: FIX-15 honor-wait (EX-skip idea UNSAFE: flag means the tenure fence hasn't processed the block yet — skipping reopens the stale-base RMW hole).

## Standing verification state
- Standalone 8/tcp dir_reuse: PASS 8/8 (run93, CAE7BFBD). In-suite: pace-fail.
- The 1/2/4 conditions not yet measured this generation. sess58 (60EFBE5E, 11d ago) had 2/tcp 17/17×8.
- Cycle+run procedure + node-id mapping per boot: see sess7-FIX16-19 memory.
