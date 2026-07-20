---
name: timing-timeouts-must-match-test
description: Test timeouts MUST be set to the test's expected healthy duration, NOT generous ceilings. A run that only passes under a 700s timeout is a FAIL. Slow…
metadata:
  type: feedback
---

When running ANY criterion/test, set the foreground/wrapper timeout to the test's
EXPECTED HEALTHY duration plus a small margin — NEVER a generous ceiling like 700s.

**Why:** A generous timeout MASKS slowness. Slowness IS a failure in MXFS (coherency
must be prompt/~ms, eventually-consistent is a FAIL). A cache_coherency run that is
healthy completes in ~20-60s; cross_visibility taking 244s = a barrier-latency FAIL,
not a slow pass. If a test only "passes" because the timeout was 700s, that is a FAIL.

**How to apply:**
- Healthy cache_coherency (4 nodes) = ~20-60s. Run it with a ceiling around 120s, not
  700s. If it exceeds that, treat the run as FAILED (barrier/writer-starvation latency).
- Also tighten the test's INTERNAL barrier timeouts (tests/lib barrier_wait) so a stalled
  barrier fails fast instead of burning 120-244s per sub-test.
- Generally: pick a timeout = expected_duration × ~2. If you don't know the expected
  duration, measure a known-good run first, then set the ceiling from that.

This reinforces [[timing-is-first-class]] and [[timing-is-failure]]. User had to repeat
this in sess117 (run 4eef1f39) because a 700s ceiling was used again — do not repeat.
