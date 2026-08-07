---
name: ccloop-c7ee71c6-sess116-owed-run-passes-NULL-real-corruption
description: sess116: PROVEN by code — lreq_finish's owed run passes e=NULL, so the deferred clear bypasses the tenure guard entirely and can strip the holder bit…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess116, samenode-waiter, corruption, code-facts]
---

# sess116 — the owed deferred clear bypasses the tenure guard (shipped in 0.11.441)

Tree UNCHANGED at time of writing: VERSION **0.11.441**, srcversion
`B385712E9A1F9A025F1D3C1`, still the STOP-SHIP core, fleet on 0.11.440.

## The defect

`lreq_finish` (`dlm/dlm_caw.c:~2721`) runs the deferred ("owed") cleanup when
the last local attempt leaves, and calls:

```c
    caw_drop_own_waiter(ctx, owed_slot, resource, NULL, (uint8_t)m);   /* :2781 */
    caw_drop_own_waiter(ctx, owed_slot, resource, NULL, MXFS_LOCK_NL); /* :2784 */
```

`e = NULL`. And `lreq_plan` (`:1705`) opens with:

```c
    plan->waiters = true;
    plan->waiters_ex = true;
    plan->holder = (giveup_mode != MXFS_LOCK_NL);
    if (!e || !ctx->lreq_lock)
        return;                 /* <-- legacy "clear everything" plan */
```

So the owed pass **never consults the registry at all** — no `tenure[]` guard,
no `others` guard. The block comment above the call claims the opposite:
*"The plan is re-derived inside, and with attempts now at zero it permits what
the deferring attempts could not — except where a committed tenure still owns
the bit, which stays refused and is correct."* That sentence is false as
written; the tenure refusal is unreachable on this path.

## The concrete corruption sequence

1. Thread **B** abandons an EX acquire on resource R. At its `lreq_plan`,
   `tenure[EX] == 0` (nobody committed EX yet) and `others >= 1` (thread **A**
   is still attempting), so it takes the `else if (others)` arm:
   `plan.holder = false; e->owed_holder_mask |= 1u << EX; e->owed_slot = slot`.
   Nothing is cleared — correct so far.
2. Thread **A** is then GRANTED EX. In `lreq_finish` it does
   `e->tenure[EX]++` and `e->attempts--` in one critical section; `attempts`
   reaches **0**.
3. Same call, same thread: `attempts == 0 && owed_holder_mask != 0` →
   `run_owed = true` → `caw_drop_own_waiter(ctx, owed_slot, R, NULL, EX)`.
4. With `e == NULL` the plan is the legacy one: `plan.holder = true`. The CAS
   loop reads the slot, sees our node bit in `holders_ex` (A's fresh grant),
   logs `P6H-ABORT-RECONCILE`, and **clears it**.
5. `caw_drop_own_waiter` returns; `lreq_finish` returns; `mxfs_dlm_caw_lock`
   returns **0** to XFS. A believes it holds EX. The disk says no node holds
   it. A peer takes EX and both write.

This is the exact defect class the registry was built to prevent, reintroduced
by the deferred path.

## The fix

Pass `e` (it is already pinned across the unlocked I/O by `e->pin++`) instead
of `NULL`. `lreq_plan` then computes `others = 0` (attempts is 0) and
`other_writers = 0`, so the waiter clears still proceed, while
`e->tenure[giveup_mode]` correctly refuses the holder clear. No other change is
needed for this specific defect.

Ledger: belongs under **D-SAMENODE-WAITER-CANCEL-COLLISION** (entry 16) as a
second, independently-provable instance — or as its own entry if the board
prefers one defect per mechanism. NOT yet added to
`tests/criteria/OPEN_DEFECTS.json` at the time of writing.
