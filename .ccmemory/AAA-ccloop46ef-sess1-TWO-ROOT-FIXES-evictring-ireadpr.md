---
name: AAA-ccloop46ef-sess1-TWO-ROOT-FIXES-evictring-ireadpr
description: sess1(46efd8b6): 2 ROOT FIXES build 87E860C4: (1) stale-HB evict-ring replay guard (2) iread-PR. cache_coh@32 chain PROVEN. Validation pending.
metadata:
  type: project
---

# ccloop 46efd8b6 sess1 — cache_coherency@32 root chain PROVEN + 2 fixes (build 87E860C40CDC9DDABEB8D35, v0.10.1)

## Scoreboard entering session
1/2/4/8=17/17, 16=16/17 (dir_reuse unrun), 32: cache_coherency FAIL, crash_consistency FAIL, dlm_scaling+dir_reuse unrun.

## RULE-4 chain (all measured, diag_rv_replay 32-node)
1. Sess8's leading hypothesis REFUTED: P34F/P58/P91/P36 = 0 on hot dir during rename+verify. No self-skip keeps stale layouts. INCONSISTENT-AT-RELEASE w/ need_iread=1 = audit artifact (stale cached leaf pending cold re-read). P33 shrink-adopts = legit nx oscillation.
2. **ROOT A — stale-HB evict-ring replay**: disklock.c HB monitor scan uses PLAIN cacheable read (sess69 only FUA-fixed DEAD-detect). Stale read ⇒ peer head_seq observed jumping backward ⇒ old consume condition (h != last_evict_seq) replayed up to 28 already-consumed DIR_MODIFY/INODE_FREE entries + re-consumed overlap on next fresh read. Each DIR_MODIFY dispatch bumps i_dlm_dir_gen AND arms MXFS_IF_DIR_RELOAD (mxfs_dlm_evict_inode_cb) — "idempotent" is FALSE for the counter. Measured: pure-read verify, test20 dir_gen 197→859 (~6/s) with ZERO writers; 689 reloads ALL identical-fields; w5(EX waits)=0 cluster-wide. Per-op cost 0.2-1s = release+reacquire+reload+block-re-read convoy. FIX: monotonic consume `(int32_t)(h - last_evict_seq) > 0`, never move cursor back, P-EVICT-STALEHB log, `nt->evict_seen=false` at fire_dead (reboot re-baseline). Param evict_ring_monotonic=1 (v5_mount.c; disklock.c builds user-mode).
3. After ring fix: dirmod=0 during verify (was 6/s) BUT verify still ~400-450s: **ROOT B — iread-EX starvation→shutdown**: real adopt at verify start unloads dir fork → first lookup xfs_ilock_data_map_shared escalates ILOCK_EXCL (xfs_need_iread_extents) → xfs_ilock maps any ILOCK_EXCL to cluster EX → 12+ nodes requested dir EX vs 20 PR-cyclers → "disk lock acquisition timed out after 120000 ms"×3 → rc=-110 → "DLM inode lock unrecoverable: shutting down filesystem" on 12/32 nodes (their neg=364s constant = the starved EX; their fast stat/read = post-shutdown error-fails). FIX: XFS_ILOCK_MXFS_PRIREAD bit (xfs_inode.h 1u<<6, outside XFS_LOCK_MASK): data_map_shared/attr_map_shared tag the iread escalation; xfs_ilock/xfs_iunlock map it to MXFS_LOCK_PR (local EXCL kept — iext build; cluster PR suffices: PR excludes writers, Invariant-1 disk consistent; GFS2 model). Param iread_pr=1 (xfs_mxfs_dlm.c ~9820). All 17 data_map_shared callers unlock with returned lock_mode (audited); getdents fully iunlocks (no ILOCK demote); ilock_end underflow-guarded (P71).

## Facts/gotchas discovered
- P59-BMBT-EVICT and P67 skip probes BOTH gated dirwr/instr — zero fires ≠ evict didn't run.
- idle neg-lookup=0.2ms incl first-time (negative dentries cached after; datascan P26 didn't even fire idle). "Datascan-on-every-miss" NOT currently the blocker.
- P138-WAIT logs REQUESTED mode at WAITER (3=PR 5=EX); fires only if waited. P70-BP qsrc: 1=ilock_end_refire 3=notify_idle 7=acq_selfbast 9=mht_arm.
- CAW slot dump live during storm: gm=3, hpr bitmap 14 concurrent PR holders, waiters=0 — PR sharing works; no stranded EX.
- run.sh prep can need 2 power-cycles after storm runs (use timeout 945).
- Group split (12 shutdown vs 20 survived) explains bimodal per-node profiles; test32-style "fast tail" = post-peers-finished uncontended (3ms/op).
- rv_replay verify wall on OLD build ~470s; budget 300s. Healthy target: neg/stat/read all ~ms ⇒ wall <30s.

## Validation plan (next: after prep on 87E860C4)
1. replay create/rename/verify hot3: expect verify walls << 300s, dirmod≈0, NO mode=5 rc=-110, NO shutdowns, P-EVICT-STALEHB >0 proves guard firing.
2. Then real `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" ./run.sh 32 caw cache_coherency` (300s budget).
3. Then crash_consistency@32, dlm_scaling@32, dir_reuse@16/32, 16-regression, 1/2/4/8 spot-check.
4. Remaining known bug (parked): EX starvation under PR churn for REAL writers (sess8 stranded-grant GC) — resurface if mixed-write tests fail.

## Tools
scripts/rv_marker_harvest.sh <N> <since-utc> [ino] — per-node marker counts + first INCONS + ino timeline. scripts/diag_rv_replay.sh phases. Kprobe recipe for EX-taker stacks: p:mxexlock mxfs_v5_dlm_inode_lock ino=$arg2:u64 mode=$arg3:u8 + trigger 'stacktrace if mode==5 && ino==INO' (works, use DURING storm).
