---
name: ccloop-c7ee71c6-sess243-GPT-ruling-aglock-livelock-sticky-revoke
description: sess243 RULE-5 ruling (-488 livelock): mechanism = signal-free NOQUEUE sweep vs lazy-cached holders (NO orphan); fix = sticky anonymous on-disk REVOK…
metadata:
  type: project
---

# sess243: -488 livelock mechanism PROVEN + GPT fix ruling

## Mechanism (supersedes sess241 "orphan/tracking-loss" and sess242 framings)
- NO orphan, NO tracking loss, zero 'unlock exhausted' fleet-checked (test13/16/30/8).
- Root: mxfs_ag_dlm_lock_bounded (xfs_mxfs_dlm.c:36651) = 40×100ms NOQUEUE tries;
  NOQUEUE exits caw_lock at dlm_caw.c:7994 BEFORE waiter registration (8067) and
  BEFORE caw_send_bast_mcast (8107) → no on-disk waiters bit (poll thread skips
  !slot.waiters at 11589), no UDP hint → lazily-CACHED holders (release only on
  BAST, by design) never demote → -EAGAIN forever.
- test30 rig: own affine ag=12 lockable (absent from P5G sweep) but can't satisfy
  the dirty-trans grow; other 24 AGs peer-cached; all peers idle → no signal
  source anywhere; >190 sweep laps. Earlier BASTs (≤5626s) were other nodes'
  blocking acquires. P5N NAKs all disk_held=0 (mcast broadcast → non-holder NAK,
  benign). Holders demote fine when BASTed (test8 COMMIT @5556, test16 @5621).

## GPT ruling (gpt-5.6-sol)
1. Option A (mcast hint on NOQUEUE conflict) = mitigation/latency accelerator ONLY.
   Durable fix = **Option B′ sticky anonymous revoke**: resource-level
   REVOKE_REQUESTED state in the on-disk slot. Contender CASes it set on conflict,
   NEVER clears it. Holder poll thread treats it like a BAST. Consumed ONLY in the
   holder's release CAS (owner clear + revoke clear + gen++ atomically) or by a
   fresh acquisition of an unowned slot (normalizes stale revoke). Holder must
   never clear-and-keep-caching.
2. New flag semantics: NOQUEUE = silent probe (dialloc 1st pass STAYS silent —
   blocking 2nd pass generates demand); NOQUEUE|REQUEST_REVOKE = bounded
   dirty-grow path only.
3. Hint cadence: immediate on first conflict, re-hint ~500ms jittered by WALL
   CLOCK (not iteration count); dedup key (fs, resource, owner, owner-gen);
   receiver dedups: one pending BAST per resource, stale-gen hints ignored.
4. Holder demotes UNCONDITIONALLY on valid revoke/hint — no idle-grace (would
   reintroduce tuning-tail).
5. Generation/ABA binding required: delayed hint for owner-gen G must not demote
   owner at G+1.
6. Thundering herd: mitigate at REQUESTER (rank candidates, limit outstanding
   revoke targets ~1 per dirty trans, randomize order, remember failures).
   Sequential 4s/AG sweep already ≈ one revoke target at a time.
7. Rejected: transient waiter-bit registration (recreates samenode waiter-cancel
   race family #15); idle decay (kills lazy-cache perf, livelock tail for any T);
   post-sweep blocking escalation (unproven ABBA).
8. Why A alone unsound: UDP loss can be SYSTEMATIC (mcast misconfig, rcvbuf
   overload, wedged dispatcher) → livelock architecturally still allowed.
   Rule: a nonblocking caller needing eventual cache displacement must leave
   persistent demand or use a reliable channel.

## Implementation notes (sess243)
- Slot has pad space: uint16 pad (dlm_caw.h:162), pad3[3] (:204) — flag fits
  without 512B layout change. Slot already has generation + dir_epoch/ex-epoch.
- Clear revoke in release CAS when last holder leaves; clear in grant CAS when
  acquiring unowned slot. AG locks are EX-single-holder.
- Cadence lives in caller (bounded loop tracks wall clock, passes demand flag).
- Ledger -488: mechanism text must be rewritten (ID's ORPHAN-TRACKING-LOSS
  framing wrong; keep ID).
