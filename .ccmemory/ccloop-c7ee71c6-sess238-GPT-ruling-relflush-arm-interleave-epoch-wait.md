---
name: ccloop-c7ee71c6-sess238-GPT-ruling-relflush-arm-interleave-epoch-wait
description: sess238 RULE-5 ruling (#23): .482 stamp = sess47 relflush-admit arm (28957, no mode check) admitting opener in ms-long post-terminal-store tail; sess…
metadata:
  type: project
---

# sess238 RULE-5 ruling (gpt-5.6-sol) — #23 D-OPEN-PROTECT-DEMOTE-RACE

## Interleave (CONFIRMED consistent, needs one-shot proof)
.482 stamp (mode=NL, prh=1, nl_age_us=16) = release worker legally stored
NL with 0 holders (all arms+store in ONE i_dlm_lock section 15756-16414),
then the opener's ilock ride entered the ms-long post-store tail
{mode=NL, state=DEMOTING, RELFLUSH set until 17823} and was admitted by
the sess47 relflush-admit arm (xfs_mxfs_dlm.c:28957, reg files, NO mode
check) → prh=1 at the re-read. Explains sess237 non-repro exactly (hold
sat AFTER the ride). Lock ordering already proves holder registered
post-store; instrumentation only needs to identify WHICH arm.

## Proof instrumentation
Per-invocation cookie (open_protect marks task/inode before ride); every
holder++ branch in ilock_begin records admit-arm enum + cookie. Failing/
restart probe prints the cookie's arm. Stamp ALL arms, not just relflush.
One-shot latch preserves first failing cookie.

## Fix completion (sess236 restart loop is INSUFFICIENT — confirmed)
Restart laps burn in µs (each lap re-admitted instantly by relflush arm;
DEMOTING wait bypassed for reg files; admission gate useless vs pipeline
already past terminal store) → -EIO persists in the .482 interleave.
- (a) EPOCH-AWARE COMPLETION WAIT = the correctness completion: on
  re-read NL+DEMOTING, capture release epoch/seq under i_dlm_lock, drop
  ILOCK+holder, wait on i_dlm_wait for THAT epoch completed/superseded
  (explicit seq beats bare state!=DEMOTING — ABA), then full restart
  (tombstone/publication/route re-checks). Timeout → re-snapshot and
  keep waiting, NEVER contention -EIO. RELFLUSH-clear is too early a
  completion signal (before device flush + wire unlock).
- (b) excluding open_protect rides from relflush arm = optional
  hardening ONLY after lock-dependency audit (arm is a deadlock escape
  hatch); never a substitute for (a).
- (c) 25ms backoff = insufficient, rejected.
- Gate stays: protects vs pipelines NOT yet at terminal store.
- Remove contention-derived -EIO exhaustion path.

## Deterministic exercise (two tests, one cannot cover both phases)
1. POST-NL-TAIL test (the .482 cause): release-side PARK after terminal
   store + spin_unlock, BEFORE RELFLUSH clear (test-only knob, timer/
   controller released, NOT dependent on blocked opener). Opener rides
   during park → assert admitted via RELFLUSH arm, re-read NL same
   epoch, enters completion wait, does not pass before park releases,
   then acquires+succeeds. Pre-ride poll alone = stress amplifier only
   (window can close between poll and ride).
2. PRE-TERMINAL GATE test: park before terminal-store critical section,
   arm admit gate, release worker → assert P95-OPEN-ADMIT-DEFER fires,
   no NL store, grant kept CACHED, re-fire works, eventual demotion
   after disarm.
Pass: zero P95-OPEN-PROTECT-FAIL, zero contention EIO/ESTALE, zero
userspace fails, arm/epoch assertions above.

## No DLM state fabrication
Park only prolongs a naturally existing state; never assign mode/state/
holders directly, never sleep holding i_dlm_lock.
