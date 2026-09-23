---
name: trap-a-shared-debug-injector-cannot-change-meaning-without-re-reading-every-harness-that-arms-it
description: TRAP (s146): dbg_auth_pump_pause_ms skips the gate call AND the pump; one lap needed only the pump held. Changing the knob would have re-shaped 3 oth…
metadata:
  type: feedback
tags: [trap, injector, harness, authority-lease, measurement-integrity]
---

# The trap

`tests/parked_log_waiter_across_closure.sh` went VACUOUS three times (s132c, s133b, s140d, `reason=no-closure`) because the injector it armed, `dbg_auth_pump_pause_ms`, skips BOTH the PR worker's periodic gate call (`mxfs_v5_dlm_write_admitted`) and the withdrawal pump. With every writer parked in the very log wait the lap creates, nothing asked the gate, so the lease never closed and the arm measured an absence that does not exist in production (the periodic tick is the production path for an idle node).

The first fix attempted was to move the hold below the gate call, so the knob held only the pump. That would have been correct for this lap and wrong for three others: `admitted_write_parked_across_fence.sh`, `auth_lease_resurrection.sh` and `fence_late_detection.sh` all arm the same knob precisely so the victim is BLIND — no evaluation, no closure, no withdrawal — while a fence lands underneath it. A closure landing at 30 s would have changed what those laps' windows contain and what their "B noticed nothing" assertions mean.

# The rule

- Before changing what a debug knob does, `grep -ln <knob> tests/*.sh` and read how each lap uses it. A knob's semantics are part of every banked verdict that armed it.
- When one lap needs a different cut of the same mechanism, add a second knob (0.89.66: `dbg_auth_withdraw_pause_ms`, `P-DBG-AUTH-WITHDRAW-PAUSE`) and leave the first exactly as it was.
- Name the knob for what it holds, not for the thread it lives on: "pump pause" said nothing about the gate call it also skipped, and that is how the lap was mis-armed for three runs.
