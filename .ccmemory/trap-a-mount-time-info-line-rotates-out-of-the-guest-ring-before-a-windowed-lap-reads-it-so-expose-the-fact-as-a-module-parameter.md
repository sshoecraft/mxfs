---
name: trap-a-mount-time-info-line-rotates-out-of-the-guest-ring-before-a-windowed-lap-reads-it-so-expose-the-fact-as-a-module-parameter
description: TRAP (s149c): an INFO line logged once at mount was gone from the victim's ring 150 s later (thousands of capped probe lines per mount), so a whole-r…
metadata:
  type: feedback
tags: [harness, dmesg, ring, module-param, evidence]
---

# A mount-time ring line is not there when a lap reads the ring

`tests/parked_log_waiter_across_closure.sh` (s149c, 0.89.68,
tests/evidence/20260922T114951Z_plwait_s149c) counted
`P290-AUTH-WITHDRAW-THREAD` over the victim's WHOLE ring (`dmesg | grep -c`)
and read 0 — while the same lap's window held `P290-AUTH-WITHDRAW
via=withdraw-thread`, which only that thread prints. The line is
`mxfs_pal_log(MXFS_LOG_INFO)` → `pr_info`, unfiltered; the lease's
`transitioned to ACTIVE` lines at the same level print fine. The line was
simply gone: a mount's first minutes log thousands of capped probe lines
(P74-GRANT alone is capped at 8000 per boot) and the guest ring is finite,
so a single INFO line from the mount had rotated out by the time the lap,
150 s later, went looking for it. The verdict was FAIL on that assertion
alone.

Two things could not substitute for the ring:
- the task list: every PAL thread is `kthread_create(..., "mxfs-worker")`,
  so no comm names the thread;
- a capture right after prep: the lap's own prep is what mounts, and the
  line lands within its window, but that makes the reading a race with the
  ring's churn.

What does: a read-only module parameter maintained by the code itself
(`auth_withdraw_threads`, 0.89.69: incremented at
`v5_auth_withdraw_thread_start`, decremented at the join). The lap reads
`/sys/module/mxfs/parameters/auth_withdraw_threads` when the module carries
it and the ring only for a module that does not, and says so in the
assertion text.

Companion to `technique-ask-the-built-module-which-probes-exist-before-trusting-any-harness-that-counts-one`:
that one is about a probe that is not in the module; this one is about a
probe that was printed and is no longer in the ring.
