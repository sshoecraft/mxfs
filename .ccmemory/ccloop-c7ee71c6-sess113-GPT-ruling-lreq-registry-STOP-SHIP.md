---
name: ccloop-c7ee71c6-sess113-GPT-ruling-lreq-registry-STOP-SHIP
description: sess113 RULE-5 ruling: the sess112 lreq registry is STOP-SHIP. Counter-sampling cannot authorize a clear; needs explicit op ownership. 3 corruption p…
metadata:
  type: reference
tags: [mxfs, dlm-caw, gpt-ruling, lreq-registry, samenode-waiter, stop-ship, sess113]
---

# sess113 — RULE-5 ruling on the sess112 local request registry: STOP-SHIP

Prior: `…sess112-lreq-registry-LANDED-0.11.441` (what landed),
`…sess111-GPT-ruling-blocker6-REJECTS-held-table-guard` (what was required).

Tree at consult time: **0.11.441, srcversion `750BDB5F2A229A3B8438947`, builds
clean, NOT deployed** (fleet still on 0.11.440).

## Verdict

**"No-go for the 32-node rig."** The sess112 substitution — *"any other local
attempt is joined ⇒ refuse to clear"* in place of the ruling's
ADOPTING/CANCELLING ownership state — **is not sound and is not stronger**.
Sampling aggregate counters does not establish exclusive ownership of the
adopt-versus-cancel transition; taking a mutex just before a disk CAW does not
close the race.

## The three corruption paths (1 and 2 found by my own audit, confirmed; 3 is GPT's)

**(A) The deferred owed pass passes `e = NULL`, bypassing the tenure guard.**
`lreq_plan(e=NULL)` early-returns with `plan.holder = true` unconditionally.
Sequence: A joins EX (attempts=1) → demoter B joins EX (attempts=2) → B times
out, refuses and records `owed_holder_mask |= EX` → B finishes (attempts=1) →
**A is GRANTED EX**, `lreq_finish` sets `tenure[EX]=1`, attempts→0, runs the
owed pass with `e=NULL` → clears A's live EX holder bit. A believes it holds
EX; the disk says it does not; a peer takes EX. Unfenced writer.

**(B) The plan is snapshotted once, then used across a loop of up to 1000
iterations × 8 ms + disk I/O.** A plan computed when `others==0 && tenure==0`
authorizes clearing a bit that became load-bearing seconds later. The disk CAW
serializes B against other *disk* writers; it does not serialize B against
publication of A's *local* tenure.

**(C) [MISSED BY ME] Passing `e` to the deferred pass is itself wrong.**
`lreq_plan` computes `others = attempts - 1` on the assumption that the caller
is still counted. The deferred pass runs *after* `lreq_finish` decremented, so
if a new thread C joins between the unlock and the deferred call, the plan
subtracts C and concludes `others == 0` → authorized to clear C's bits. Same
for `writers`/`waiters_ex`.

## Why the substitution fails (GPT's holes)

1. **Check-then-act.** Another attempt can join after the check, before the CAW.
   Affects holder, `waiters` and `waiters_ex` alike.
2. **One attempt can have competing adopt/cancel control paths** — a grant
   callback adopting while the timeout cancels, same logical attempt:
   `attempts==1, others==0, tenure==0` while an adoption is in flight. *(NOTE:
   in MXFS the adopting thread IS the attempting thread — verify before relying
   on this being inapplicable.)*
3. **Unsolicited direct handoff.** Clearing a truly orphan grant is correct;
   the unsafe part is that a new attempt may start or adopt that grant *during*
   the cleanup. Ownership must block that.
4. **`tenure[]` is necessarily zero during the whole adoption window** — the gap
   between the holder bit appearing on disk and `lreq_finish` publishing.
   Counters cannot say whether an attempt is waiting / adopting / cancelling /
   converting / committed-but-unpublished.
5. **No grant-epoch ownership.** The registry has no observed write-grant epoch,
   so it cannot distinguish a delayed grant for an *abandoned* request from a
   grant for the *current* one, nor from a bit left by an earlier tenure.

## Structural defects beyond the race

- **5.2 The exact-mode tenure guard is too weak under CONVERSION.** If a convert
  moves the node's on-disk representation PR→EX and then gives up before
  publishing, `tenure[EX]==0` so cleanup clears EX — and the surviving local PR
  tenure is left with **no on-disk holder bit at all**. Cancellation may need to
  *downgrade to the strongest remaining locally required mode*, not clear.
  REQUIRES an audit of whether convert clears the old bit in the same CAS.
- **5.3 `lreq_release_all` memsets the whole tenure vector** while `tenure[m]>1`
  is representable. Safe ONLY if a higher local layer guarantees the disk unlock
  CAS happens exclusively on the final local reference. That invariant is not
  enforced or asserted anywhere.
- **Item 4 — a single `owed_slot` is structurally wrong.** A later debt
  overwrites an earlier one's location. Losing an old `waiters_ex` clear
  recreates the measured 16-node wedge. Debt must be a *collection of exact
  obligations* (resource incarnation, slot index, stable slot-claim cookie, bit
  classes). Slot `generation` is NOT a stable claim identifier (any write bumps
  it).
- **Item 5 — identity mismatch is NOT discharge.** `if (resource mismatch) { rc
  = 0; break; }` means "the remembered location is stale", not "the obligation
  is complete". Recorded debt must survive, retarget via canonical lookup, or
  escalate. Blind re-scan by resource has its own hazards (ABA on resource
  reuse, new slot incarnation, movement during scan, duplicate claims, 65536-slot
  cost, and a claim-exhaustion probe position that was never registered on
  should not become holder debt at all).
- **Item 6/7 — exhaustion still does not escalate.** A warning + counter + owed
  flag is not escalation: the deferred path ignores return values, `e==NULL`
  loses the re-record, and GC can then delete the only evidence. Needs a
  *guaranteed* mechanism — persistent reconciliation worker with bounded retry,
  block further acquisition of that resource while unresolved, poisoned state,
  and ultimately withdrawal/fencing.
- **5.5 Counter overflow unhandled** — `attempts++/writers++/tenure++/pin++`. An
  `attempts` wrap makes live users look quiescent and authorizes cleanup. Also
  add a compile-time assert `MXFS_LOCK_MODE_COUNT <= 32` before using a u32 mask.
  `if (e->attempts) e->attempts--;` hides accounting bugs — underflow is an
  invariant violation, not something to silently absorb.
- **5.6 GC must also require `pin == 0` and no live op**; `lreq_release_all`
  must respect `pin`.
- **5.7 Registry allocation failure must FAIL THE MOUNT.** Logging and
  continuing produces a mounted FS where every acquisition returns -ENOMEM —
  not a designed degraded mode.
- **`waiters_ex` downgrade** is conceptually right (a stale peer image
  miscompares; a peer recomputing from current bitmaps computes the lower mode)
  but needs: the same ownership fix, the deferred-subtract fix, an explicit
  mode→bitmap invariant (does `mode_can_write()` match exactly the set of
  requests `waiters_ex` represents?), and an audit that
  `recompute_waiter_mode()` is a pure derivation and never uses the previous
  `waiter_mode` as an input hint.

## Required before any rig test (GPT's list, verbatim in substance)

1. Replace sampled `attempts/tenure` authorization with explicit
   ADOPTING/CANCELLING/RELEASING ownership.
2. Block new disk-request issuance and grant adoption while cancellation owns
   the resource.
3. Publish tenure / effective mode / grant epoch before releasing ADOPTING.
4. Model cancellation debt per slot/incarnation, not one `owed_slot`.
5. Never treat slot identity mismatch as successful debt reconciliation.
6. Guaranteed retry/escalation path.
7. Define and enforce the local-reference / last-unlock invariant.
8. Audit conversion as a node-wide effective-mode transition incl. downgrade to
   remaining local demand.
9. Checked counter arithmetic; invariant failures.
10. Fail mount if the registry cannot be created.

"Replanning inside the retry loop and passing `e` fix two immediate
manifestations, but they do not repair the underlying safety model."

## My implementation reading (sess113) — the reduction that makes this tractable

The exclusion actually needed is **CANCELLING vs JOIN**, not a full 6-state
machine, *provided* adoption is always performed by an already-counted attempt
on its own thread (hole 2 inapplicable — VERIFY THIS IN CODE, do not assume):

- `caw_drop_own_waiter` claims CANCELLING **and computes the plan in the same
  critical section**;
- `lreq_join` waits for `op == NONE` before counting/issuing;
- therefore during CANCELLING `others` cannot grow, and the only case where
  anything is cleared is `others == 0` — the canceller is the sole live local
  attempt and no new one can appear.
- `lreq_finish`'s deferred pass claims CANCELLING **in the same critical section
  that takes attempts to 0** (no unlocked window), and passes an explicit
  `self_joined = false` so it does not subtract a thread that is not itself.

No deadlock: the canceller waits only on disk I/O, never on another local
thread, so a demoter blocked behind CANCELLING cannot close a cycle (unlike the
ACQUIRING park, which is why that exemption exists).
