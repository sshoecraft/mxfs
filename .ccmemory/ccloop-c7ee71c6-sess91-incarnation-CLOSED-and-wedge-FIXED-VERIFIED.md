---
name: ccloop-c7ee71c6-sess91-incarnation-CLOSED-and-wedge-FIXED-VERIFIED
description: sess91 OUTCOME: 2 defects CLOSED (incarnation-constant-zero + the inc_eq(0,0) recovery wedge, both FIXED AND VERIFIED on 0.11.421), 3 new filed from…
metadata:
  type: reference
tags: [sess91, 0.11.421, closed, FIXED-AND-VERIFIED, recov_tok_eq, incarnation, board-green, ledger]
---

# sess91 outcome — 0.11.421, two criticals closed, three successors filed

Build **0.11.421**, srcversion **C2230B2B7487F93ED23EFF8**, deployed 32/32 caw.
Ledger: **22 OPEN of 55, 13 critical** (was 20 of 51, 13 critical).

## Shipped — dlm/disklock.c only, one file, no header change

`recov_tok_eq(a,b)` — a second, deliberately differently-named comparator for
**descriptor-token identity** (exact encoded equality, so an UNKNOWN compares
equal to the UNKNOWN it was issued from), sitting beside `inc_eq()` which stays
the **cross-source incarnation proof** (zero always fails). Both
`recov_auth_holds()` and `recov_fence_auth_holds()` now use it for
`victim_epoch`, **and both additionally compare `victim_slot`** — which the two
auth issuers have always copied and which nothing ever checked, so a stale auth
could pass against a different slot's descriptor. That hazard was never
zero-specific; it applied to nonzero incarnations too.

`P234-RECOV-NOTOURS` now names which test failed —
`kind=TAKEOVER (descriptor owner is not us)` vs
`kind=TOKEN-MISMATCH (stale or foreign auth)` — and prints both full tuples
(slot, victim node, victim epoch, gen, term). The old wording asserted a
takeover for every failure and offered only the owner tuple as evidence, which
is how it came to print two IDENTICAL tuples as proof of a takeover that never
happened. That cost a full rig investigation to see through.

## The A/B that closes it (identical injection, same rig, same probe)

| marker | 0.11.420 | 0.11.421 |
|---|---|---|
| P237-RECOV-INC-MISMATCH | 3 | 3 (unchanged — guard not weakened) |
| P234-COMPLETE-FENCEFAIL | 3 | 3 (unchanged) |
| P234-RECOV-NOTOURS | **7** | **0** |
| P234-COMPLETE-REPLAYEDFAIL | **7** | **0** |
| P163-RECOVERY-COMPLETE | **0** | **1** |
| P97-SWEEP-DONE | **0** | **1** |
| slot | GUARD stage=2, still frozen at 12 min / 11 retries | **zeroed at t+30s** |

## CLOSED — D-MOUNT-INCARNATION-CONSTANT-ZERO (critical)

The decisive evidence was NOT that the identifier is nonzero (sess88 had that);
it was that the **comparisons discriminate**. All three arms sess88/89 recorded
as never having executed on the rig fired and each took the correct branch:

- `arm=zero` → `P237-RECOV-INC-MISMATCH victim_inc=1634619062121349274
  slot_inc=0 … refusing to publish` + FENCEFAIL rc=-116, no descriptor.
- `arm=nonzero` → `P237-RECOV-SUPERSEDED victim_inc=383883444245855066
  slot_inc=15952125467273129900 — retiring our pending recovery instead of
  guarding a LIVE member` + `P237-COMPLETE-SUPERSEDED`, no guard laid.
- follow-on round → `P237-RECOV-INC-UNOBSERVED` through to
  `P163-RECOVERY-COMPLETE` + `P97-SWEEP-DONE`.

Owner/prover-epoch predicates are exercised POSITIVELY by every completion
(both auth holders require `inc_eq(d->owner_epoch, ctx->epoch)` /
`inc_eq(d->fence_prover_epoch, ctx->epoch)` on real nonzero values).
**Explicitly NOT claimed** and carried onto `D-RECOV-ADVANCE-UNBOUNDED-RETRY`:
the NEGATIVE owner-incarnation arm (a same-node LATER incarnation trying to
advance a predecessor's descriptor — disklock.h:261 "A → B → A within a single
session") was not injected.

## CLOSED — D-RECOV-AUTH-ZERO-VICTIM-EPOCH-WEDGE (critical), found and fixed same session

## Filed OPEN from the RULE-5 ruling — do not lose these

- **D-RECOV-ADVANCE-UNBOUNDED-RETRY** (critical). 11 quiet retries over 12 min
  with the victim's grants frozen, no bound/backoff/classification/relinquish/
  escalation. The -EBUSY source is fixed; the retry structure is not, and any
  other permanent advance failure reproduces the hang. Also owns the negative
  owner-incarnation arm above.
- **D-MONITOR-INCARNATION-DOWNGRADE-TO-ZERO** (high). `disklock.c:1147/1156/
  1358` rebases a KNOWN nonzero cached incarnation to 0 with no `inc_valid()`
  guard. That is what laundered a MISMATCH into the UNOBSERVED arm: round 1
  refused naming E1, round 2 said "the caller never observed the victim's
  incarnation" about the same victim 62s later.
- **D-RECOV-ZERO-EPOCH-DESCRIPTOR-AUTHORITY-UNPROVEN** (high). ~6 cross-source
  sites (`:290 :383 :2558 :3345 :3460 :3881`) still `inc_eq` against
  `d->victim_epoch`, so a zero-epoch descriptor refuses forever through
  takeover / fence_intent / fence_certify / claim / purge-freeze instead of
  through advance. Either prove the seven slot-quarantine invariants or forbid
  zero-epoch descriptors at creation — "refuse and hang" is not a disposition.

## Board — regression gate on 0.11.421

Full 32/caw, 6 chunks, each timeout = sum of that chunk's per-test budgets +
harness overhead (no widening). **27 of 27 functional criteria PASS**;
`open_defects` red by policy only. Notable walls vs budget:
`dir_reuse_coherency` 110/120s and `crash_consistency` 76/90s — both close to
budget under board load, consistent with the existing pace entries;
`crash_consistency` was 18s standalone in sess90.

## Rig state

32/32 mounted on C2230B2B7487F93ED23EFF8, board just run. `virsh -c
qemu:///system start test32` + `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`
is the recipe after any probe run (the probe leaves the victim destroyed; the
pre-fix arm also leaves the slot wedged and REQUIRES a re-prep).
