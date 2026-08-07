---
name: ccloop-c7ee71c6-sess114-GPT-ruling-cancelling-accepted-10-more-blockers
description: sess114 RULE-5 ruling: CANCELLING-vs-JOIN is ACCEPTED for the adopt/cancel race, but 10 more release blockers — RELEASING, last-reference unlock, nod…
metadata:
  type: reference
tags: [mxfs, dlm-caw, gpt-ruling, lreq-registry, samenode-waiter, sess114, stop-ship]
---

# sess114 — RULE-5 ruling on the CONCRETE lreq redesign

Prior: `…sess113-GPT-ruling-lreq-registry-STOP-SHIP` (rejected sess112's
counter-sampling), `…sess113-lreq-verified-code-facts-and-design` (FACTS 1-3).

## The core reduction is ACCEPTED

> "CANCELLING-vs-JOIN is sufficient for the narrow give-up/adoption race,
> assuming FACTS 1-3 are complete and the clear plan is strengthened. You do
> not need a separate ADOPTING state merely to serialize the attempting
> thread against itself."

The argument GPT accepted, verbatim in substance: B is never in a state where
it is *neither* a counted attempt *nor* a published tenure, because publish and
decrement are one critical section; blocking `lreq_join` stops a third party
entering behind the canceller. So the plan, once authorized, stays authorized.

**But the design as a whole is still STOP-SHIP.** Ten blockers.

## Release blockers (verbatim list)

1. Add **RELEASING** exclusion, or equivalent, covering whole-node disk clear,
   joins, and adoption.
2. **Structurally enforce final-local-reference unlock; do not ship
   measure-only.** (My RULE-4 "instrument first" proposal was REJECTED here:
   "You already know the representation permits `tenure[m] > 1` and the unlock
   clears every node bit. A probe discovers the violation *after* the unsafe
   clear; it does not prevent it.")
3. Complete **node-wide effective-mode** handling for conversion, downgrade and
   release to remaining demand.
4. **Never drop an overflow debt record.** Poison-and-omit is unacceptable: the
   worker is left without slot, modes, bits or incarnation. Overflow must be
   representable or cause immediate withdrawal.
5. Add a real **slot-claim incarnation cookie**, or a rigorous substitute
   proved from the claim protocol. Content-memcmp on `resource` ALIASES two
   different claims (ABA: S holds R inc10 → debt → S recycled → S holds R
   inc12 → memcmp succeeds).
6. Specify **last-attempt finish when another thread already owns CANCELLING**.
   Safe protocol: if finish would create the last-attempt condition and
   `op != NONE`, WAIT **without first dropping itself from `attempts`**; after
   the owner releases, atomically decrement AND claim. (Because A still sees B
   as an attempt, A cannot clear holder bits while B waits, and A is bounded.)
7. Define exact per-bitmap clear authorization: the holder test must be
   `others == 0 && for every mode in holder_mask: tenure[mode] == 0` — not just
   `tenure[giveup_mode] == 0`. `others == 0` for all waiter-bit clears is
   "straightforward and safe".
8. **Wall-clock retry deadlines** and finite withdrawal escalation. "1000 × 8ms"
   is not a bound — it ignores CAW latency, SCSI retries, multipath failover.
   Real bound can be minutes. Prefers a SHORT synchronous cancel budget (1-2s),
   then record debt and let the worker continue under controlled exclusion.
9. Track and retry the **post-upgrade old-holder-bit residue** (the 20-retry
   clear-old loop after a PR→EX grant). Not "benign": blocks peers, persists,
   confuses one-effective-mode assumptions, matters at later downgrade.
10. Withdrawal must **stop/fence local I/O before** releasing DLM state.

## The two concrete corruption sequences GPT supplied

**`lreq_release_all` (blocker 1).** U begins whole-node unlock and clears the
node's disk bits → B joins / is already joined, issues a request, lands a new
holder bit, publishes tenure → U confirms its earlier clear and calls
`lreq_release_all` → **B's freshly published tenure is zeroed** → a later
cancellation clears B's holder bit. "Disk confirmation at one instant does not
prove no joined operation re-established the bits immediately afterward."

**Mode-less unlock over a multi-reference tenure (blocker 2).** A and B each
hold local PR; `tenure[PR] == 2`; A calls the mode-less unlock; it clears the
PR bit *and every other node bit*; `lreq_release_all` zeros tenure; B keeps
reading under a hold it no longer has; a peer takes an incompatible lock.

## Answers to my specific questions

- `lreq_finish` publish+decrement during CANCELLING: **SAFE** — but only
  because both the tenure raise and the attempts drop are in the SAME critical
  section. "There must be no counter update outside that critical section."
- `lreq_release_all` during CANCELLING: **NOT SAFE** (blocker 1).
- FACT 4 conversion audit (waiting PR→EX give-up keeps its old PR bit):
  **AGREED, that sequence is unreachable** — but it does not complete the
  audit; the node-wide invariant is "the node's disk holder state continuously
  covers the aggregate remaining local demand, including through conversion and
  final release."
- `find_slot` `-ENOENT` as debt discharge: **NOT sound without a cookie.** A
  bounded scan over independently changing slots is not a linearizable proof of
  absence (scan checks slot 20, peer installs R at 20, scan finds old slot
  empty, returns ENOENT). Without a cookie: require repeated stable scans or a
  global table mutation epoch; keep debt on ambiguous absence.
- `-ESTALE` instead of `rc=0` on identity mismatch: **correct.**
- Poison without withdrawal: "a permanent resource wedge… fail-closed but does
  not satisfy 'ultimately withdrawal/fencing'." Immediate withdrawal for: debt
  overflow, registry/counter corruption, impossible slot identity or duplicate
  claims, inability to maintain the exclusion protocol, repeated shared-LUN
  I/O failure. Threshold "finite and shorter than the cluster's accepted
  unavailability deadline — order 60-300s, not '256 sweeps'".
- `mxfs_mode_can_write()` unification and `recompute_waiter_mode()` at the
  setters: **SAFE** given FACT 5, plus "add assertions rejecting CR/CW at the
  CAW transport boundary so FACT 5 cannot silently become false."
- Checked arithmetic / static assert / fail-mount: **correct**, and apply the
  checked arithmetic to `writers` and every tenure count too.
