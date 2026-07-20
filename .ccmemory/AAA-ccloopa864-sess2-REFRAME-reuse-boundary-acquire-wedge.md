---
name: AAA-ccloopa864-sess2-REFRAME-reuse-boundary-acquire-wedge
description: sess2 REFRAME: dir_reuse@32 is NOT fairness — it's a reuse-boundary ACQUIRE WEDGE. Acquire spins 360s on a HOLDERLESS slot (ex=0 pr=0) at r2/r3. B2-B…
metadata:
  type: project
---

# dir_reuse@32 REFRAME — reuse-boundary acquire wedge, not fairness

## Big pivot (sess2)
Spent B2-B5 (4 runs) tuning the CAW yield/streak fairness mechanism. ALL failed ~r2/r3, alternating EX/PR shutdown by race variance. Then merged-log forensics REFRAMED it:

**The failure is a cluster-wide ACQUIRE WEDGE at the dir-reuse boundary, NOT fairness starvation.**

### Evidence (B5, v0.10.42 E02D0E63)
- ALL P44-MODGRANT (dir EX-modify) events stop at kernel **248s** (end r1/start r2). After 248s NOTHING modifies the shared dir ino=131.
- Yet test5's PR acquire (comm=bash) spins from ~250s→610s (360s) then rc=-110 shutdown. During that window test5 loops on `P-DIRBAST ino=131 state=4(ACQUIRING) mode=0 ex=0 pr=0` every ~6s (the MXFS_CAW_BAST_RESEND cycle) — receiving BASTs for a lock it doesn't hold, deferring them (i_dlm_bast_during_acq).
- The slot is HOLDERLESS (ex=0 pr=0) but the acquire can't promote. NOT contention (no one holds it). It's a stuck acquire / distributed state-machine confusion.
- At 250s test5 DID acquire+reload fine (P34-ACQ-SLOW rc=0 dur2266; P65-EPOCH-ADOPT grant_epoch=384 acq_epoch=376; P62-RELOAD-FORK-SHRINK nx 31→33; P34B-IREAD 33 extents). So the epoch-adopt reload at reuse is expensive but completes. The wedge is a LATER acquire that never settles.

### Confirmed by prior memories (this IS the known long-standing holdout)
- `caw-sess6-dir_reuse16-is-CAW-grant-starvation-not-readstorm`: dir_reuse@16/@32 stalls at round-2 (FIRST reuse) — stack `stat→xfs_ilock→caw_wait_for_grant` msleep forever on the shared reused dir inode. Livelock, NO crash/corruption. "the PRE-EXISTING reason dir_reuse never passed." Candidate fixes: FIFO/ticket grant ordering; bound PR re-grants when EX waiter queued (sess50 defer_for_waiter).
- `caw-sess5-STALER-reload-inode`: mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:14417) on reused-inode grant invalidates cluster buf → FUA storm; makes each tenure expensive. Fix direction (Fable, NOT impl): skip reload cluster-stale when prior_ex_owner==self.

### istate enum (xfs_inode.h:26): NONE=0 CACHED=1 BAST=2 DEMOTING=3 ACQUIRING=4
Known lost-BAST wedge (xfs_mxfs_dlm.c:14189): if i_dlm_state==DEMOTING is STALE, incoming BASTs swallowed ("redundant, ignore") → peer convoy starves forever (P72-SWALLOW-DEAD probe exists).

## Current diagnostic build: v0.10.43 srcver B0F87A63 (RUNNING as B6)
Added probe **P-ACQ-STUCK** (dlm_caw.c caw_wait_for_grant loop, unconditional/ratelimited): when an INODE acquire polls >15s, dumps full slot every 8s: magic gen gm hex hpw hpr **w wex yt ysm streak**. This will show WHY the holderless-slot acquire can't promote (stuck yield_to? phantom waiters? epoch?).
Still carries B2-B5 fairness changes (yield_set_ms don't-re-arm; no streak-reset-on-yield; upgrader-defer-to-PR — the last is INERT, UPG-PRYIELD=0 always). Those did NOT prevent the wedge.

## Next
1. Harvest P-ACQ-STUCK from wedged nodes → root-cause the holderless-acquire wedge.
2. Likely a state-machine/epoch bug at reuse, not fairness. Consider: reload_inode prior-owner skip (sess5); FIFO grant; or the BAST-during-ACQUIRING defer never being honored (i_dlm_bast_during_acq path).
3. If root needs design help: RULE-5 Fable consult warranted (complete diagnosis, 4 approaches tried, architectural).
