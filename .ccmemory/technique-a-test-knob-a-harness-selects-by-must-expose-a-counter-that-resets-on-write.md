---
name: technique-a-test-knob-a-harness-selects-by-must-expose-a-counter-that-resets-on-write
description: TECHNIQUE (sess586): third lap lost to counting a budgeted probe's printed lines (n<=8, n%64); fix is a readable counter reset by the knob's set-call…
metadata:
  type: feedback
tags: [technique, harness, knob, counter, dlm, test-only]
---

# A knob a harness selects by must expose a counter, reset when the knob is written

**Third occurrence of the same trap (sess586, tests/tcp_lockreq_blackhole.sh):** the candidate search that finds an inode remotely mastered from W counted `P912-DROP-LOCKREQ` lines in dmesg. The probe prints only its first 8 drops and every 64th after them, PER MODULE LOAD. After lap s585c spent the 8, laps s585c2 and s585e read every candidate as "locally mastered" and aborted; s585d found a target only because a hit landed on n=64. Earlier instances: `trap-the-nth-printed-line-of-a-budgeted-probe-is-not-the-nth-event` (s581) and `trap-a-selection-step-keyed-on-a-cumulative-dmesg-count-picks-the-previous-runs-target`.

**The fix that ends the class (0.84.2, dlm/dlm.c):**
- the drop counters are readable module parameters (`dl_drop_lockreq_n`, `dl_drop_grant_n`, via `module_param_named(..., atomic.counter, int, 0444)`);
- the knobs (`dl_drop_lockreq_ino`, `dl_drop_grant_ino`) are `module_param_cb` with a set-callback that resets the counter AND the print budget on every write, arm or disarm — so the count is per arm and the printed `n=1` is the first drop of THIS arm;
- the reset must be in the WRITE path, never lazily at the next send: a lazily reset counter is inherited by a candidate that triggers no send at all (a locally mastered inode), which is exactly the false positive the search exists to exclude.
- the harness reads the counter (`cat /sys/module/mxfs/parameters/dl_drop_lockreq_n`) and refuses a build without it.

**User-mode build note:** dlm/dlm.c is also compiled for tests/tauth; `dlm/dlm_user_compat.h` now stubs `module_param_named`, `module_param_cb`, `MODULE_PARM_DESC`, `struct kernel_param_ops`, `param_set_ullong`/`param_get_ullong` and `atomic_set` (under `#ifndef __KERNEL__`). Before that the tauth build of dlm.c did not compile at all once the first module_param_named landed in it.
