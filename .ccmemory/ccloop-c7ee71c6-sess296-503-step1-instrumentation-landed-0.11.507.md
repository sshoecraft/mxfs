---
name: ccloop-c7ee71c6-sess296-503-step1-instrumentation-landed-0.11.507
description: sess296: D-503 ruling step-1 instrumentation LANDED+BUILT 0.11.507 sv F1E678C16F762EC785B1389 — P297-TKT nominee wake/miss attribution + tenure fo/lo…
metadata:
  type: project
---

## sess296 — D-503 step-1 instrumentation (per sess295 GPT ruling) landed

Build: **0.11.507 sv F1E678C16F762EC785B1389**, clean `make clean && make modules`.
NOT deployed — fleet still on .506 (sv 289E4A3F4164D39FFC7DF90).

### Key numeric prior
MXFS_CAW_DEFER_POLL_MS = **250ms** (dlm_caw.h:72) — matches the observed
225-330ms nom-adopt latency. The nominee long-dozes 250ms whenever a foreign
EX holder exists (dlm_caw.c wait loop bottom); the releaser's targeted nudge
(caw_send_grant_mcast at unlock CAS, both mint and nom arms) should end that
doze — the 520 nom adopts riding the backstop mean the nudge is swallowed or
lost. The documented race: caw_acquire_poll_sleep's caw_nudge_prepare runs
AFTER the caller's slot read, so a nudge landing during the read (1-50ms
under load) or loop processing is invisible and costs a full interval.

### What was added
dlm/dlm_caw.c:
- `caw_nudge_wait` → returns bool (woken-by-nudge vs backstop).
- `caw_nudge_check(ctx, from_seq, res)` — locked wants-wake query.
- `caw_acquire_poll_sleep` → returns flags MXFS_CAW_WAKE_NUDGE(1)/
  MXFS_CAW_WAKE_MISS(2), new param pre_read_seq. MISS = nudge for us arrived
  in (pre_read_seq, prepare_seq] — will oversleep. Detection only, per the
  ruling (measure before fix).
- caw_wait_for_grant: pre_read_seq snapshot BEFORE every read_slot; both
  sleep sites record last_wake (1 nudge/2 poll/3 oversleep) + last_sleep_ms;
  **P297-TKT** logged once per wait at first sighting of yield_to naming us:
  `ino mode el_ms wake slept_ms read_ms miss reads gen yt realms` (cap 20000,
  INODE only). Pair realms with releaser exwin "nom" (unlock CAS) and waiter
  "promote"/P138-WAIT (grant) for the full unlock→adopt decomposition.

xfs/xfs_inode.h + xfs_mxfs_dlm.c:
- `i_dlm_tenure_firstop_ns` stamped at first EX ilock_end of a tenure
  (tenure_ops 0→1), reset at all 5 fresh-EX stamp sites.
- P70-BP ENTRY line extended with `fo_ms=` (grant→first op = adoption/setup
  cost) and `lo_ms=` (last op→release entry idle tail); marginal per-op =
  (held_ms - fo_ms - lo_ms)/(tops-1).

### Decision tree for the measurement (next session)
- P297-TKT wake=3 / miss>0 dominant → swallowed-nudge race proven → fix B:
  nominee-only fast retry ladder 1/2/4/8/16ms + prepare-before-read
  (level-triggered), disk stays authority, keep 250ms backstop.
- wake=2, miss=0 dominant → nudge lost on wire / drowned (recv-thread
  sharing per sess8 note) → different arm.
- wake=1 but el still large → sighting→claim CAS latency is the cost, not
  the sleep → B won't help; look at claim contention.
- P70-BP fo_ms large → adoption-setup dominates tenure (ruling step 4:
  if marginal 50ms is real, 80s service-time lower bound → D mandatory).

### Repro recipe (sess294)
Deploy .507 fleet-wide, run board chunks to accumulate background load,
then crash_consistency (the 32×50 O_SYNC create shared-dir phase collapses
only under accumulated load). Analyze fleet dmesg P297/P70/exwin by realms.

### Board state
Unchanged from sess295: 27/27 applicable PASS on .505/.506 mix except
crash_consistency + dir_reuse_coherency (D-503 family) and open_defects
(policy). Soak still owed on .50x.
