---
name: ccloop-c7ee71c6-sess119-ambiguous-CAW-landed-plus-3-unwindowed-clears
description: sess119: ruling items 3+8 LANDED (ambiguous CAW = may-have-written) + AUDIT FOUND 3 destructive clears with NO clear window. srcversion A78D555…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess119, samenode-waiter, stop-ship, clear-window]
---

# sess119 — ruling items 3 and 8 landed; the bypass audit found three more sites

Build: VERSION still `0.11.441` (landing incomplete, not revved).
srcversion `AC44AC4FAF6EF5DA0C24299` → `A78D555EAA0734BC6BBFD6E`. Builds clean,
zero warnings. STILL STOP-SHIP — fleet stays on 0.11.440.

## Landed (sess118 ruling checklist items 3 and 8)

**New predicate `caw_may_have_written(rc)`** (right after `caw_slot`): the ONLY
definite no-change outcome of a CAW is `-EAGAIN` (the target compared and
miscompared, so by the definition of COMPARE AND WRITE nothing was written).
`rc == 0` is a definite write; **everything else — I/O error after retries,
transport failure, `-ESHUTDOWN` — is AMBIGUOUS and must be treated as
may-have-written**. Reporting the third class as "no change" is exactly the
destructive change happening invisibly to validation that the ruling names.

Wired at all three clear sites:
- `caw_giveup_cleanup` — `committed = true` on any non-`-EAGAIN` result, not
  just `rc == 0`.
- `mxfs_dlm_caw_unlock_gen` — the `if (rc) goto out;` arm now sets
  `clr_committed` when the result is ambiguous. Local tenure is deliberately
  NOT retired there: `lreq_release_all` stays on CONFIRMED clears only (a
  stale-high tenure only makes later plans refuse — the safe direction),
  whereas `clr_seq` must move on the merely-possible one.
- `mxfs_dlm_caw_force_release_self` — item 8 (multi-step clear). It walks up to
  `CLAIMRACE_SCAN_MAX` slots with an independent CAS in each, so the
  clear-sequence answer is the OR over every sub-operation. Added
  `may_have_cleared` alongside `cleared` (the latter is the return value and
  counts only confirmed clears, so it could not carry this).

**Plus a real bug found in `caw_slot` itself.** With `caw_gen_verify=1`, a
verify-read I/O failure did `rc = vrc; continue;` — retrying the CAS *after the
CAW had already succeeded*. The compare image is then stale, so the retry
miscompares and the function returns `-EAGAIN`: "definitely nothing changed"
reported for a write that definitely DID change the slot. Now returns the read
error (ambiguous), with `P250-CAW-VERIFY-IO`. Off by default (knob), but it is
the exact inversion the ruling is about.

## THE AUDIT (ruling item (i): "no destructive path bypasses begin/end")

Grepped every `&= ~ctx->node_bit` in `dlm_caw.c` and classified all 30+ sites.
**Three strip this node's authority with NO clear window:**

1. **DIVERG exact-mode arm**, `mxfs_dlm_caw_lock` (~5105) — clears our holder
   bit when a peer holds an incompatible mode.
2. **DIVERG higher-mode arm**, same function (~5266) — same clear for the
   "we hold a higher mode that subsumes" case.
3. **convert DOWNGRADE arm**, `mxfs_dlm_caw_convert` (~7484) — strips the old
   (HIGHER) mode bit and sets the new lower one. A local thread holding
   `tenure[old_mode]` loses its on-disk authority.

All three are memory-invisible to a concurrent already-held/adopt publication
exactly like the three already-windowed sites. Each caller has already
`lreq_join`ed, so the entry exists and windowing them costs no allocation once
`lreq_clr_begin` is find-first (below).

Sites checked and CLEARED as not needing a window, with reasons:
- promote waiter→holder (~4033) and "compatible — add ourselves" (~5642):
  these are GRANTS. They write the slot, so a concurrent clear CAS
  miscompares. The upgrade arm clears the old lower mode in the SAME CAS that
  sets the higher one, and `node_held_mode` returns the highest bit set, so
  higher subsumes lower — no de-authorization. A downgrade cannot reach here
  (`our_mode >= mode` returns early via the already-held shortcut).
- convert upgrade (~7525) and post-wait clear-old (~7597): same subsumption
  argument.
- `yield_to` stale clears (~4026, ~5618): a handoff TICKET, not an authority
  bit. Costs a handoff at worst.
- `open_holders` (~6511, ~7135): open/unlink tracking bitmap, not lock
  authority.
- `mxfs_dlm_caw_release_all` (~7727): unmount teardown — the terminal state
  the ruling's item 7 explicitly exempts. Needs an explicit precondition
  comment, not a window.

## Next steps, in order

1. **Blocker 5 (ENOMEM fail-closed) — design settled, not yet written.**
   Restructure `lreq_clr_begin` to **find-first**: take `lreq_lock`, look up,
   and only allocate if the entry is genuinely absent. This is not an
   optimization — it removes the allocator from the path entirely for any
   resource this node holds a grant on, because `lreq_finish` publishes
   `tenure[]` and `lreq_gc` refuses to free an entry with nonzero tenure. So
   unlock and both DIVERG arms never allocate. Then add a small per-ctx
   **reserve free-list** (`lreq_gc` returns entries to it instead of freeing
   when below target) for the genuinely-absent case, and make all three sites
   fail closed when even that is empty. Unlock's fail-closed disposition is
   bounded retry against its EXISTING unlock deadline, then `-EIO` (lock stays
   held, caller re-BASTs) — never "proceed under the legacy mark alone", which
   is what it does today.
2. Window the three sites found by the audit above.
3. **Blocker 2** — replace the 50ms fail-forward wait in `lreq_finish` with
   GPT's preferred restructure (record owed intent under the registry mutex
   BEFORE the long disk-I/O portion) or a guaranteed-progress executor.
4. **Blocker 7** — explicit precondition on `force_release_self`.
5. **Blocker 1** — the residual post-validation demotion window (XFS-layer
   quiescence). The largest, and the one the ruling refuses to let out of
   scope.

Items 4 and 6 landed in sess118. Items 3 and 8 landed here. 1, 2, 5, 7 open.
