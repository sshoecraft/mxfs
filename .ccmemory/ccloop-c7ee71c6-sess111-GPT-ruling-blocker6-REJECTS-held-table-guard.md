---
name: ccloop-c7ee71c6-sess111-GPT-ruling-blocker6-REJECTS-held-table-guard
description: sess111 RULE-5 ruling: my ctx->held mode-guard for blocker 6 is REJECTED (two more same-node races). Requires an authoritative per-resource local sta…
metadata:
  type: reference
tags: [mxfs, foreign-replay, step5.3, dlm-caw, gpt-ruling, blocker6, linearization, reconcile]
---

# sess111 — blocker 6 audit, measurement, and the RULE-5 ruling that rejected my fix

Prior: `…sess110-blocker5-LANDED-and-P241-VERIFIED-on-rig` (blocker 5 done),
`…sess107-GPT-ruling-direct-handoff-mint-10-blockers` (the 10-blocker list).
Tree unchanged this session — **0.11.440, srcversion `DF0E1ABC1CEA16331E2DF6C`,
no code edits, fleet still deployed at that build.**

## The audit — line-verified code facts

**`caw_drop_own_waiter(ctx, slot_idx, giveup_mode)`** (`dlm/dlm_caw.c:2318`) is
the reconcile. Three call sites, all post-giveup: grant-wait timeout (3346),
claim-exhaustion (4990), convert-exhaustion (6479). It loops ≤1000× with
backoff clearing `waiters`, `waiters_ex` **and our holder bit in
`giveup_mode`**, then returns — success or not.

**The adopt arm** (`dlm_caw.c:2823`) writes NOTHING: pure recognition.
Predicate `gen > reg_gen && !(waiters & node_bit) && (holders[mode] & node_bit)`,
plus for write modes `last_ex_slot == me && ex_grant_epoch != 0 &&
ex_grant_epoch > reg_epoch`.

**THE CORE PROBLEM (mine, confirmed by GPT):** the on-disk image is *identical*
for "handoff landed, nobody adopted" and "handoff landed AND another thread on
this node adopted it and is live". Node identity is ONE BIT and adoption writes
nothing, so the ruling's "compare epoch/generation + holder mode" **cannot be
satisfied from the slot alone**. Any binding must use in-core state.

**Same-node concurrency IS possible by design.** AG acquires are serialized by
`pag->pag_dlm_acquire_lock`. Inode acquires are serialized by the
`MXFS_DLM_ISTATE_ACQUIRING` park in `mxfs_dlm_ilock_begin`
(`xfs/xfs_mxfs_dlm.c:28138`) — **but the demoter is exempt** (`!mxfs_is_demoter(ip)`
on the park at 28141 and on the state-set at 28415), because the drain's trailing
`xfs_irele` must self-reenter. The tree already carries the probe
`P3A-DEMOTER-SLOWACQ` labelled "the prime suspect for the same-node
concurrent-request collision".

## The measurement (32/caw, 0.11.440, sess110 board still in dmesg; 27/32 reported)

`tests/census_p.sh 32 '<snippet>'` is the right tool for this.

    P3A-DEMOTER-SLOWACQ                = 0   on every node
    P6H-ABORT-RECONCILE                = 0   on every node
    "disk lock acquisition timed out"  = 0   on every node
    P-CAWEXH / P91-CLAIMEXH            = 0   on every node
    P6H-ADOPT                          ≈ 970 per node

**The reconcile arm is never entered under a healthy board.** The hazard is real
by construction and unobserved in practice. RULE 6 forbids closing on that.

## MY PROPOSED FIX — REJECTED

I proposed: add `modes[]` parallel to `ctx->held.slots[]`; refuse to clear the
holder bit when a tracked tenure at that slot has `mode == giveup_mode`; still
clear waiter bits; fail-safe on `held_overflow`.

**GPT: "No-go on the proposed fix exactly as written."** The direction (in-core
binding, no durable adopt CAS needed) is right; `ctx->held` + a mode lookup is
not, because of two further same-node races:

1. **Observe-to-track window.** adopter validates → reconciler sees nothing
   tracked and clears → adopter calls `track_held()` and returns success. The
   guard is useless unless adopt and reconcile share one synchronization domain.
2. **Multiple local attempts share ONE on-disk node bit.** One abandoned attempt
   can clear the waiter bit *belonging to another live local attempt*.
   `reg_gen`/`reg_epoch` do not identify WHICH local request a handoff satisfies.
   Not limited to holders.

Also ruled: a semantically-null adoption CAS that only bumps `generation` is
**also insufficient** — generation is bumped by unrelated waiter registration, so
"generation increased" does not prove *this* grant was adopted. A durable marker
would need a per-attempt token (grant cookie / adopted_epoch bound to mode +
incarnation + grant epoch), and even then the one-bit-per-node format still
requires local multiplexing. **Recommendation: strict node-local per-resource
serialization + coalescing; keep pure-recognition adoption; no extra LUN write.**

## What GPT requires to close blocker 6 (verbatim in substance)

1. ONE authoritative local state machine per (node, resource) — states at least
   WAITING / GRANT_OBSERVED / ACTIVE / CANCELLING / RELEASING, plus local mode,
   refcount, conversion state, the single outstanding on-disk attempt identity,
   and the observed write-grant epoch.
2. **At most one on-disk request per node per resource**; other local callers
   join / wait behind / coalesce / recurse. Demoter reentry must join, not issue
   an independent request.
3. Adoption and reconcile mutually serialized *through* final slot validation and
   local-state publication (adoption linearizes at GRANT_OBSERVED→ACTIVE;
   cancellation at its cleanup CAS). Holding a mutex over disk I/O is not
   required — an explicit ADOPTING/CANCELLING ownership state + condvar is fine,
   the exclusion property is what matters.
4. Cleanup never clears a holder an active/committed local tenure depends on.
5. **"recorded mode differs ⇒ still clear" is TOO WEAK** as the general
   predicate — mid-conversion, local state may say PR while another thread has
   already committed the EX transition. The decision must come from the
   conversion state machine: *"would clearing this bit invalidate any locally
   active or adoption-committed tenure?"*
6. State allocation must not silently overflow; failure ⇒ refuse the acquisition
   or controlled withdrawal (quiesce, release what is safe, self-fence if safe
   withdrawal is unprovable). Never "overflowed and continue".
7. Cleanup-retry exhaustion escalates safely (watchdog retry / withdraw / fail
   the resource) — never an ordinary return.
8. Dead-holder purge requires a **completed, incarnation-bound storage fence**,
   before the purge, not only before recovery publish.
9. All incompatible grants ordered after that fence + purge.
10. Probes: live-tenure guard fires, discarded fresh epochs, cleanup exhaustion,
    fence-before-purge violations.

## Answers to my specific questions

- **Q2 (different-mode carve-out):** the concrete PR-live/EX-abandoned case IS
  sound — clearing `holders_ex` leaves PR, a peer cannot get EX while our PR bit
  survives so it still drives the PR BAST path, and the minted epoch is a
  harmless gap. But see item 5: mode-inequality is not a valid *general*
  predicate. Also: define whether a handoff granting EX during an upgrade is
  meant to REPLACE PR or coexist, and when the PR bit is removed.
- **Q3 (`held_overflow`):** refuse-to-clear is the correct safety direction
  (leak = liveness, clear = unfenced writer = corruption). But if correctness
  depends on the table, overflow must become impossible by construction. An
  overflowed mount is unsound for **any** decision that treats "not tracked" as
  "not held" — audit all such uses.
- **Q4 (death purge):** *"Lease expiry alone is a failure detector. It is not a
  fence."* The certificate must be required **before the grant/holder purge**.
  It is sufficient only if it proves a completed, correctly scoped fence: P&A
  succeeded, covers every LUN and every path/initiator, PR keys identify a node
  **incarnation** not a reusable node number, certificate bound to that exact
  dead incarnation + fence op, no replay after rejoin, uncertain SCSI completion
  leaves holders intact. **Dead-node WAITER bits may be cleared unfenced** (they
  confer no access); holder bits may not.

## THREE NEW DEFECTS to file in the ledger

1. **D-SAMENODE-WAITER-CANCEL-COLLISION** (critical) — distinct from blocker 6's
   holder race. Two local attempts on one resource share one waiter bit; one
   attempt's reconcile clears the bit representing the other. The same ambiguity
   corrupts direct-handoff nomination: disk records only "node N", not which
   local request. Exposed by the demoter exemption.
2. **D-RECONCILE-EXHAUSTION-SILENT** (high) — `caw_drop_own_waiter` returns
   normally after 1000 failed attempts. A leaked EX waiter bit has ALREADY caused
   a measured 16-node cluster wedge, so silent exhaustion is not acceptable;
   it must escalate.
3. **D-TRACK-PUBLISH-ORDERING** (high) — a grant must not become usable before
   authoritative local tenure state is published, and local state must not be
   removed before the release is known to have landed; ambiguous SCSI completion
   must be reconciled while the local transition is still owned. Mechanically
   updating the 6 track / 7 untrack sites is NOT enough without these invariants.

Plus a minor: **counter-wrap policy** must be an explicit invariant for the
`generation > reg_gen` / `ex_grant_epoch > reg_epoch` predicates, even at 64 bits.

## NEXT SESSION — start here

Implement the per-resource local request registry in `dlm/dlm_caw.c`:
- Hash table keyed by resource id — model it on the existing `ctx->grant_meta`
  cache (`dlm_caw.h:498`, fnv1a-hashed, own mutex) which already has the right
  shape; note the separate-mutex precedent at `dlm_caw.h:518` (a sibling cache
  needed its own lock because callers hold `ip->i_dlm_lock`, a real spinlock, and
  must not sleep — the registry has the same constraint, check it).
- Entry: state machine + local mode + attempt refcount + observed epoch +
  mutex/condvar.
- Acquire registers the single on-disk request; extra local attempts JOIN by
  refcount (this is the coalescing GPT asked for, done at the cancel boundary
  rather than by blocking the demoter — blocking the demoter mid-drain would
  deadlock, which is exactly why the exemption exists).
- Reconcile may clear waiter/holder bits ONLY as the LAST local attempt and only
  when no ACTIVE local tenure depends on them; downgrade `waiters_ex` when the
  write-capable attempt leaves but a read attempt remains (an over-high
  `waiter_mode` is the measured reader-starvation wedge).
- Adoption publishes ACTIVE under the registry lock → closes the observe-to-track
  window.

`ctx->held` stays as the settle-purge discriminator; it is NOT the fix.
