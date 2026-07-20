---
name: feedback-timing-is-failure
description: Slowness IS a failure. A 300s timeout is itself a failure; 1000s is insane. Tests must be FAST (seconds), not eventually-consistent-after-minutes.
metadata:
  type: feedback
---

User (sess38, emphatic): "anytime you use an excessive timeout like 1000 — hell, a 300-second
timeout is itself a failure. Anything that takes five minutes [is a failure], except FIO (each FIO
test doesn't take 5 min). If native rsync is 3s, then 300s is a failure period. Extending to 1000s
is insane. I don't care how many nodes you got."

**Why:** Timing/coherency latency is a first-class CORRECTNESS criterion (see
[[feedback_timing_is_first_class]]). A clustered op that takes minutes when native is seconds is
unusable. Barrier timeouts (120s) in cache_coherency are FAILURES, not "slow but passing".

**How to apply:**
- NEVER use timeout 300+/1000 as a crutch to let a slow test "pass". If a test needs >~minute, the
  FS is too slow = FAIL. Diagnose the slowness as the bug.
- Coherency must be PROMPT: a peer must see a committed change in ~ms (well under the 120s barrier
  timeout), not "eventually". A 120s barrier timeout that converges late is still a FAIL.
- sess38 mistake: added a per-create sync flush (parent-AG push) that made rename_visibility take
  ~5 min — reverted. A fix that adds minutes of latency is not a fix.
- The FIX for coherency must be both CORRECT and FAST. Prefer lazy/read-time invalidation (cheap)
  over per-op synchronous flushes (expensive).
