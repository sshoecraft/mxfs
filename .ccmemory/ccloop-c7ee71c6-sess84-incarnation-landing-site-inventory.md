---
name: ccloop-c7ee71c6-sess84-incarnation-landing-site-inventory
description: sess84: the COMPLETE line-verified edit inventory for landing the nonzero mount incarnation (D-MOUNT-INCARNATION-CONSTANT-ZERO) + the rejoin-activati…
metadata:
  type: reference
tags: [sess84, disklock, incarnation, epoch, proto-gen, recovery-descriptor, fence-certificate, site-inventory, rejoin]
---

# sess84 — incarnation landing: line-verified edit inventory

No code written yet (relay boundary hit during the read pass).  Everything
below is verified against the tree at VERSION 0.11.419.  The sess83 GPT ruling
(`ccloop-c7ee71c6-sess83-GPT-ruling-incarnation-and-token-v2`) is the spec;
this is where each of its 7 landing steps actually goes.

## Blast radius is SMALL and bounded

The whole recovery/descriptor/fence API surface is confined to **two files**:
`dlm/disklock.c` and `dlm/v5_mount.c`.  Verified by grep — no xfs/, pal/,
tools/ or mxfs_clayer/ caller of `mxfs_disklock_recovery_*`,
`slot_holds_incarnation`, or `pending_epoch`.  `v5_mount.c` touches exactly
one epoch-carrying call: `recovery_begin(..., pending_epoch(...))` at :2105.

## Step 1 — the generator

`mxfs_pal_get_random_bytes(void *buf, size_t len)` (pal/pal.h:774) returns
**void**.  Kernel = `get_random_bytes` (infallible).  User = /dev/urandom, and
on open failure it **memsets to zero** (pal/linux/user.c:1487).  So a
draw-until-nonzero loop with a bounded retry IS a correct fail-closed detector
for the only failure mode the PAL has.  Do NOT add a time fallback (ruling Q1).

- `ctx->epoch = 0;` at **dlm/disklock.c:1145** is the ONLY write in the tree.
  Replace with the generator; fail `mxfs_disklock_create()` (return NULL) if it
  yields 0.
- ALSO regenerate at the top of `mxfs_disklock_claim_slot()` (:4157): a ctx can
  claim → release → re-claim, and the ruling requires a **new** incarnation per
  published tenancy.  Generating there also satisfies "before the first claim
  publication".  `claim_slot_noncaw` (:4037) is only reachable from the CAW
  fallback at the bottom of `claim_slot`, so one draw covers both.
- Publication sites that already copy `ctx->epoch` and need no edit:
  claim CAW image :4248, claim non-CAW image :4110, heartbeat :647,
  withdraw :2037, guard :4442.  The feature CRC already folds epoch in
  (`hb_feature_crc`, :161) so identity binding is automatic.

## Step 5 — the REQUIRED-match helpers (the ruling's core)

Add two static helpers in disklock.c and use them everywhere below:

    static bool inc_valid(mxfs_epoch_t e)           { return e != 0; }
    static bool inc_eq(mxfs_epoch_t a, mxfs_epoch_t b)
                { return a != 0 && b != 0 && a == b; }

### The optional-epoch idiom — REPLACE (zero is never a wildcard)

| line | site | today |
|---|---|---|
| 290 | `recov_desc_names()` | `return epoch == 0 \|\| d->victim_epoch == epoch;` — **always true** |
| 2462 | `recovery_begin` | warns P234-RECOV-EPOCH-DRIFT then records the SECTOR's epoch |
| 2954 | `mxfs_recov_cert_proves_exclusion` | `if (victim_epoch && …)` |
| 3069 | `fence_intent` (desc-present path) | `(victim_epoch && …)` |
| 3489 | `recovery_claim` | `(victim_epoch && …)` |
| 3502/3622 | claim / replay_authorized | pass `victim_epoch` straight through to cert check |

Per the ruling, `recov_desc_names()` must **split** into a node-scoped and an
incarnation-scoped API rather than take an optional epoch.  `recov_lease_covers()`
(:293) likewise — its `(…, node_id, 0)` callers in `purge_node` (:1594, :1690)
are legitimately node-scoped and the ruling explicitly permits zero for
"purging after independent fencing/protocol proof"; their *authority* test is
the owner side, which does become a real match.

### Ownership / prover tests — these become real (were `owner_node ==` only)

`d->owner_epoch == ctx->epoch` at **1604, 1702, 2380, 2437, 2750, 2892, 3080,
3368, 3511**; `d->fence_prover_epoch == ctx->epoch` at **2895, 3257**.  Each
must also demand nonzero on both sides.

### Already correct, no edit

`mxfs_recov_cert_proves_exclusion` already refuses `!d->victim_epoch` (:2950)
and `!d->fence_prover_node || !d->fence_prover_epoch` (:3006).  Those are dead
checks today and simply start working.

### `slot_holds_incarnation()` (:3820) — WRONG DIRECTION today

`held = … && hb->epoch == epoch`.  Called with `epoch == 0` against a real
nonzero record it returns **false = "departed"**, and the whole function's
contract is fail-closed ("cannot prove departure → return true").  Add an
explicit `if (!epoch) return true;`.

## Step 3 — nonzero incarnation before a record counts as live

`hb_own_record()` (:457) `cur->epoch == ctx->epoch` becomes real; ctx->epoch is
now guaranteed nonzero so a legacy zero record fails → self-fence.  That is
correct under the proto_gen gate.  `hb_foreign_kind()`'s branch at :482 ("a
different incarnation of this node owns the slot") becomes reachable for the
first time.

## Step 6 — `MXFS_PROTO_GEN` 2 → 3 (include/mxfs/mxfs_super.h:71)

Bump ONLY when publication + validation activate together.  The gate is already
enforced: joiners quarantine until every live current-fs_gen peer validates, the
monitor SCSI-PR-fences a live LEGACY/MISMATCH incarnation (P-VERGATE, :1004-1028),
and a joiner facing an established incompatible cluster withdraws.  So no
mixed-version handling is needed.

## ⚠ THE ACTIVATION HAZARD — dead code that comes alive

**disklock.c:952 "Epoch change = node rebooted"** —
`if (nt->last_epoch != 0 && rhb->epoch != nt->last_epoch) goto fire_dead;`
has NEVER fired (last_epoch is always 0).  With real incarnations it fires
exactly on: same slot, same node_id, ACTIVE, different incarnation = **a node
that crashed and reclaimed its own slot inside the 62 s dead window**.

Chain if left unhandled: fire_dead → expire_cb → `v5_dlm_recovery_complete`
(v5_mount.c:2105) → `recovery_begin(slot, victim, pending_epoch=A)` → the
sector now holds incarnation B.  Today :2462 only WARNS and then adopts the
sector's epoch — i.e. **it would lay a RECOVERY_GUARD over a live rejoined
node's slot**, whose next `hb_cas_own_slot` reads foreign → -EPERM → self-fence.
A remount would shoot the node that just came back.

The step-5 refusal at :2462 closes that (fail closed on mismatch), but then
`P234-COMPLETE-FENCEFAIL` (v5_mount.c:2124) returns rc and says "the pending
marker and heartbeat record stay set for a retry" → **livelock retrying against
a live node**.

Proposed handling (needs the RULE-5 consult before boarding): `recovery_begin`
returns a DISTINCT code (**-EREMCHG**) when the slot holds a live, current-gen,
ACTIVE record of the same node at a *different nonzero* incarnation.  The
v5_mount driver treats it like the existing `-ENOENT` path: clear the pending
marker, log a distinct probe, return 0.

**Why dropping it is sound — both obligation classes are discharged by the
rejoined node itself (verified):**
1. *Journal slice* — claim pass-1 own-stamp reclaim sets `slice_adopted=false`,
   and the ctx comment at disklock.h:665 is explicit: "nobody replayed us, full
   own-slice recovery is safe and REQUIRED".
2. *CAW authority bits* — `mxfs_v5_dlm_settle_own_slot()` (v5_mount.c:1771)
   purges `1ULL << node_slot` with SKIP_TRACKED and logs P225-SETTLE
   "reclaimed N un-adopted authority entries from our previous incarnation".
   (Note `get_stale_slot_mask` skips our own slot, so this is the only path.)

Race safety is already structural: once a guard IS down, claim pass-1 can't
match (flags != ACTIVE) and pass-2 explicitly skips RECOVERY_GUARD slots
(:4218), so the rejoin takes a different slot.  The window is only *before*
`recovery_begin`.

Other newly-live paths to sanity-check: `hb_still_dead_stamp()` (:321),
`vergate_fenced_epoch[]` re-arming per incarnation (:1004) — both become
correct rather than degenerate.
