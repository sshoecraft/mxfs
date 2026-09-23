---
name: trap-a-ratelimited-pr-warn-count-is-not-a-measurement-burst-is-10-per-5s
description: TRAP (sess566): a `pr_warn_ratelimited` probe that reports exactly 10 hits is reporting DEFAULT_RATELIMIT_BURST, not a count. Never derive a ratio fr…
metadata:
  type: feedback
tags: [trap, instrumentation, probes, sess566, rule4]
---

# A ratelimited probe's count is not a measurement

sess566, D-0941. I counted probe hits in one failing lap and got:

    P34H-POISON-UNRETIRED   24 distinct inodes   (plain pr_warn)
    P34H-INCARN-POISON      10 distinct inodes   (pr_warn_ratelimited)

and started building an inference on the 24-vs-10 gap: that 14 inodes must have been
poisoned in an EARLIER lap and carried a persistent unretireable flag forward. That would
have been a significant escalation of the defect's severity.

**It was an artifact.** `pr_warn_ratelimited` uses `DEFAULT_RATELIMIT_BURST` = 10 per
`DEFAULT_RATELIMIT_INTERVAL` = 5 s. Ten hits in a sub-second window is exactly the burst
ceiling. The probe was not reporting how many inodes were poisoned; it was reporting how
many lines the ratelimiter let through.

## The rule

- A ratelimited count that lands **exactly on 10** (or any multiple of the burst across
  intervals) should be assumed truncated until proven otherwise.
- Never compute a **ratio** between a ratelimited probe and an unratelimited one. The
  denominators are measuring different things.
- Counting probes in this tree use `static atomic_t n; if (atomic_inc_return(&n) <= CAP)`
  — that caps the PRINTING while the counter keeps the true total. Use that shape when
  the number matters, and print the total.
- Different `pr_warn_ratelimited` call sites have INDEPENDENT ratelimit state, so one site
  printing 48 lines while another printed 0 does not mean the second was suppressed —
  that comparison is sound. It is the absolute count from a single ratelimited site that
  is not.

## Why this keeps happening here

Third probe-integrity failure in one session, all the same family — a probe that looks
like it is measuring something and is not:

1. `P134-IDENTICAL-BUFSTALE` compared only `di_mode`/`di_gen`, neither of which moves when
   a peer changes dirents, so it was VACUOUS for the defect it sat inside and its silence
   in every prior run proved nothing.
2. `tests/d0941_cc_loop.sh` matched `[PASS]` while `run.sh` prints a bare leading word, so
   a lap that genuinely reproduced the defect was recorded `NO_TERMINAL_RECORD`.
3. This one.

Before trusting any probe count, ask what would make it print a wrong number, not just
whether it printed.
