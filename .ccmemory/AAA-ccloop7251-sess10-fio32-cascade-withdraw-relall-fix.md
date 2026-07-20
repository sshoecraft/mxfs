---
name: AAA-ccloop7251-sess10-fio32-cascade-withdraw-relall-fix
description: 32/tcp fio cascade root-chain: AG-17 EX starved 60s → test29 dirty-cancel shutdown → dead node's grants unreleasable → 5 rc=-110 dominoes. Fix: withd…
metadata:
  type: project
tags: [ccloop-72513a13, sess10, cascade, withdraw, fio]
---

# 32/tcp fio_perf cascade (chunk-A run, build 0650D30A) — anatomy + fix

## Chain (RULE-4 traced across 4 nodes' logs)
1. fio_perf@32 ground 686s (recorded wall 45-81s) — cluster-wide degradation
   during the run, cause not yet isolated (AG-lock convoys suspected).
2. test29 kworker (writeback alloc) starved on AG-17 EX vs master test21
   (P-LKTIMEOUT-REMOTE type=3 ag=17 ~1.024s cadence; the 10..5 countdown
   was the ratelimit TAIL of the 60-retry budget) → terminal -ETIMEDOUT →
   **xfs_trans_cancel of a dirty tx → forced shutdown** (xfs_trans.c:1069).
3. test29's DLM master service kept running (granting ino=128 PRs +634s
   post-shutdown — service is pure protocol, no FS needed) BUT its own held
   grants (PR/EX on files+dirs, e.g. fio dir ino=128) stayed in every
   master's table and its dead FS could never serve BASTs for them.
4. rm (fio cleanup) on 5 nodes needed dir ino=128 EX → BAST to holders incl.
   dead test29 → never released → each rm hit terminal rc=-110 → each node's
   ilock_begin unrecoverable arm FORCE-SHUT-DOWN that node too (dominoes:
   test2,4,6,8,20 all "DLM inode lock unrecoverable ino=128 rc=-110 comm=rm").

## Fix (0.11.39 = 420FBA28)
`mxfs_dlm_withdraw_release_all(ctx)` (dlm.c, exported in dlm.h): on withdraw,
snapshot every ctx->buckets entry with owner==local (granted mirrors, own
local-master grants, abandoned WAITING) and run standard mxfs_dlm_unlock per
resource (local: remove+promote_waiters; remote: LOCK_RELEASE). Called from
mxfs_v5_dlm_shutdown_withdraw BEFORE heartbeat stop; TCP-focused (CAW slot
purge already handles its side via disklock). unlock_gen's fallback reaps
WAITING/BLOCKED (skips live pend_waiter entries). Print: P-WITHDRAW-RELALL.

## OPEN: the ROOT grind — why fio@32 went 686s and why AG-17 was held >60s.
Re-measure fio alone on 420FBA28; if it grinds, live-probe P36-RETRY type=3
/ LKTIMEOUT during the run to catch the AG holder red-handed. Note the
master-side P-LKTIMEOUT-HOLDER dump exists for INODE type only — AG timeouts
print no holder detail (instrumentation gap if AG forensics needed).

## Also: mxfs_dlm_lock default retry budget is 60×~1s; ilock_begin drives
## smaller sub-budgets in a loop with cooperative AG yields between.
