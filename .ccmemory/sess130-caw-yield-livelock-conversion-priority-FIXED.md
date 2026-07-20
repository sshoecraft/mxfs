---
name: sess130-caw-yield-livelock-conversion-priority-FIXED
description: sess130: cache_coherency(4) PASS. CAW EX-starvation root = yield-backoff livelock on PR→EX upgrade; fix = conversion priority (build 5EDDFF58, KEEP).
metadata:
  type: project
---

## sess130 — CAW inode-EX starvation ROOT-CAUSED and FIXED; cache_coherency(4) PASS

### Root cause (PROVEN, not the sess123 CAS-race theory)
The P-CAWEXH counter dump (added sess129) showed `yield_bo=100 ea_compat=0 ea_regwait=0` —
ALL 100 retries were **yield-backoffs**, not CAS losses. The livelock:

1. Node holds PR on the hot shared-dir inode (e.g. ino=135/136 in unlink_visibility),
   requests EX (unlink path = lookup-PR then upgrade-EX). It is the SOLE holder
   (`last_hpr` = own bit), so the compat check passes every retry.
2. But `slot->yield_to` is armed for OTHER nodes — peers that registered as EX
   waiters (blocked on OUR PR). Every peer release with waiters present re-arms
   `yield_set_ms`, so the 5s stale-clear never fires.
3. The upgrader is never IN `yield_to` because compatible-but-yielding nodes never
   register in the waiters bitmap — invisible to releasers.
4. → 100× `MXFS_CAW_YIELD_BACKOFF_MS` backoff → -ETIMEDOUT → mxfs_dlm_ilock_begin
   force-shutdown → downstream EIO/AGI-corruption cascade on surviving nodes.

Circular wait: upgrader defers to waiters; waiters wait on upgrader's held PR.

### Fix (dlm/dlm_caw.c ~1608, build `5EDDFF582EFBA66B71D02C7`, KEEP)
Standard DLM rule: **conversions take priority over new requests**. Only FRESH
acquires (`our_mode == MXFS_LOCK_NL`) honor the yield_to backoff; upgraders fall
through to compat-add. Probe `P130-YIELD-UPG-BYPASS` (pr_warn_ratelimited, always-on)
logs each bypass.

### Verification
- test_unlink_visibility (4 nodes): PASS 30s, max unlink wall 8.8s (was 123s starve → shutdown).
- P130 bypass fired 10× in repro, 19× in criterion run; P-CAWEXH = 0 everywhere.
- `tests/criteria/cache_coherency.sh --nodes 4`: **RESULT: PASS passed=4 failed=0** —
  this was THE ship blocker since ~sess39.

### Notes
- sess124 MHT batching protects the HOLDER; this fix protects the ACQUIRER-upgrader.
  Both stand. Gemini strict-handoff ticket (#1) NOT needed.
- defer_for_waiter (sess50) is type-agnostic but only gates fresh acquires — it was
  not the gap; the yield_to hint was.
- node bit ≠ hostname order: test3 had bit 8 (disklock slot order).

Related: [[sess123-caw-ex-starvation-gemini-fairness-design]] [[sess129-inactive-ifree-whole-ail-deadlock-fixed]] [[sess50_lessons]]
