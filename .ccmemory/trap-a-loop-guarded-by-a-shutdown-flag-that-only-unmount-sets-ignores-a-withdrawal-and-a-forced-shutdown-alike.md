---
name: trap-a-loop-guarded-by-a-shutdown-flag-that-only-unmount-sets-ignores-a-withdrawal-and-a-forced-shutdown-alike
description: TRAP (s88): the DLM acquire loop tests ctx->shutting_down, which ONLY unmount sets; a closed lease plus a forced shutdown left a waiter blocked 72 s…
metadata:
  type: feedback
---

## What bit us

`dlm_lock_impl()` opens with `if (ctx->shutting_down) return -ESHUTDOWN;`,
which reads like a general "is this mount going away" guard. It is not.
`ctx->dlm->shutting_down = true` is assigned in exactly one place —
`mxfs_v5_dlm_shutdown_defer_release()`, which runs at **unmount**.

`mxfs_v5_dlm_shutdown_withdraw()`, the path a fence or a lease closure takes,
does not set it. It poisons the v5 context, stamps the slot WITHDRAWN, stops
discovery — and its own comment says "conflicting acquires ride their 60 s
budgets through the few-second window", which is the behaviour, written down,
by someone who knew.

## The measurement

`tests/evidence/20260920T175325Z_lockreqbh_s88f`, 2 nodes / TCP, a task blocked
in an acquire whose request was dropped so the master would never answer:

```
+82s alive=1 closed=0 shut=0
+85s alive=1 closed=1 shut=1     <- lease CLOSED *and* filesystem shut down
...
+155s alive=1 closed=1 shut=1
+157s alive=0 closed=1 shut=1    <- 72 s later
```

**Both stop signals were already present at +85s and the loop saw neither.**
It ended at its own retry budget. `delta = 72 s` against a 10 s bound.

## What to take from it

- **Grep for the setters of any flag a loop guards on before believing the
  flag's name.** One assignment in one teardown function is not "the system is
  shutting down"; it is "unmount reached line N".
- A subsystem can have several distinct terminal states — going away, withdrawn,
  authority closed — and a loop needs to test the one that matches the event it
  must react to, not whichever one already had a variable.
- Measuring "did it eventually end" proves nothing. It always ends. Measure the
  interval from the signal that *should* have ended it, and assert on that.

## Related

- ruling: `docs/rulings/terminal-authority-cancellation-in-the-acquire-machinery.md`
- `design-the-acquire-path-fail-fast-gate-was-reachable-only-from-the-precommand-fence-leg`
  — the other acquire-path gate, `recovery_blocked_cb`, which answers a
  *peer's* problem and must not be reused for this one.
