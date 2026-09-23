---
name: design-the-acquire-path-fail-fast-gate-was-reachable-only-from-the-precommand-fence-leg
description: DESIGN (0.89.11, D-381): recovery_blocked_n / fence_retry[slot].blocked is what makes waiters fail fast with EIO; only v5_fence_retry_arm(nonproving)…
metadata:
  type: project
tags: [fencing, dlm, recovery-blocked, design, v5_mount]
---

# Two different "blocked"s, and only one of them stops a waiter hanging

`dlm/v5_mount.c` has two structures that both sound like "this slice is
blocked", and they do completely different jobs:

- **`ctx->blocked[slot]`** (`v5_blocked_set`) is a REPORT. It feeds
  `/sys/kernel/debug/mxfs/<dev>/recovery_blocked` and nothing else. Setting it
  changes no behaviour.
- **`ctx->fence_retry[slot].blocked` + `ctx->recovery_blocked_n`** is the GATE.
  `mxfs_v5_dlm_node_recovery_blocked()` reads it on the acquire path (via the
  DLM's `recovery_blocked_cb`), and it is what makes an acquisition behind a
  dead node's frozen grants **fail fast with EIO** instead of waiting out the
  acquire budget. It also makes `v5_node_live_cb` answer "not live".

Until 0.89.11 the gate was set in exactly one place: `v5_fence_retry_arm()`
with `nonproving=true`, i.e. only when the **PRECOMMAND** bounded series ran
past `fence_blocked_after_ms`. The `MAY_HAVE_SUBMITTED` (ambiguous) leg calls
`v5_fence_retry_disarm()` and never arms, so the gate was never engaged for it.

**Consequence, measured on 2/tcp:** after a fencing attempt whose command may
have run, the survivor's own root-inode acquire sat behind the fenced victim's
EX for 764 s and climbing (`P-LKTIMEOUT-HOLDER`, `P36-RETRY` counting down),
`umount` and `fuser` hung, the module could not be released, and only a power
cycle cleared the node — with zero BUG, zero Oops, zero shutdown. The debugfs
view meanwhile printed the slice and asserted "This is a REFUSAL, not a hang",
which was true of the refusal and false of the waiters.

## The lifecycle, if you touch this

- The gate is lifted by `v5_fence_retry_disarm()`, which the certify, takeover
  and supersede paths all call — so a slot marked blocked is cleaned up by the
  existing paths; do not add a second lift.
- `disarm` DECREMENTS `recovery_blocked_n`, so any new place that sets blocked
  must guard on `if (already blocked) return;` or the counter drifts.
- `disarm` clears `blocked` — so if you both disarm and block in one leg, the
  **block must come after the disarm**.
- Leave the slot `armed = false`. The retry worker only visits armed slots, and
  `mxfs_disklock_recovery_fence_retryable()` answers 0 for any descriptor
  carrying `MXFS_RECOV_F_FENCE_CMD_MAY_HAVE_RUN` anyway — but an armed slot
  would be visited and then `disarm`ed, silently lifting the gate again.
- `fence_retry[slot].victim` is what the lookup matches on, and `disarm` does
  NOT clear it; set it explicitly when blocking outside `arm`.

## The principle

Refusing to recover a slice without proof of exclusion is the invariant.
Making every waiter hang on that refusal is not part of it: no proof means no
recovered grants, and no progress means failing the local operation explicitly
rather than deadlocking its teardown.
