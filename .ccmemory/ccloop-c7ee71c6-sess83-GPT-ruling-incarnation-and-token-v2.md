---
name: ccloop-c7ee71c6-sess83-GPT-ruling-incarnation-and-token-v2
description: sess83 RULE-5 ruling: random nonzero 64-bit incarnation (NOT my timestamp construction), zero is never a wildcard, and last-writer-wins provenance is…
metadata:
  type: reference
tags: [sess83, rule5, gpt-ruling, incarnation, disklock, token-v2, step5.2, foreign-replay, cil-provenance]
---

# sess83 RULE-5 ruling — mount incarnation + token v2 + provenance capture

Consult sent with the sess83 measurement (all 31 live HB records read EPOCH=0 off
the LUN; `ctx->epoch` written once as 0 and never again).  Verdict: **the finding
is real and blocks 5.2 — fix the incarnation first, under a proto_gen bump.**

## Q1 — incarnation construction: MY CANDIDATE WAS REFUTED

I proposed `epoch = (mxfs_pal_time_real_ms() << 16) | rand16`.  **Rejected**:
only 16 bits of collision resistance when clocks repeat or stick — precisely the
VM-snapshot / bad-RTC / rapid-reboot / pre-NTP cases an incarnation must
tolerate.  The timestamp already exists separately in the HB for diagnostics.

Use an **opaque, nonzero, cryptographically random 64-bit** value:

    do { mxfs_pal_get_random_bytes(&epoch, sizeof(epoch)); } while (epoch == 0);
    ctx->epoch = epoch;

Required properties: equality-only opaque id; nonzero; strong RNG; generated
**before** the first claim publication so the first durable ACTIVE claim, its
feature CRC and every descriptor carry the same value; immutable for the life of
that published slot tenancy; **never reused after evidence the tenancy was
lost**.  If the RNG can fail / lacks entropy, **fail the mount or claim closed** —
never fall back to time.

Lifecycle distinction to encode:
- an UNPUBLISHED failed claim attempt may keep or discard its candidate — it
  never became an identity;
- once PUBLISHED, losing the slot **terminates that incarnation**; that epoch may
  never establish a new tenancy later;
- transient rewrites of the same still-owned record reuse the same epoch.

Rename/comment it `incarnation` — "epoch" invites illegal ordering comparisons.

## Q2 — equality ONLY, never ordering

No listed predicate needs `>`.  Durable identity is the tuple
`(fs generation, slot, node where applicable, incarnation)` compared for **exact
equality**.

If recovery was established for victim `X` and the slot now holds nonzero
`Y != X`, the ONLY sound conclusion is *"the current record is not the victim
incarnation this recovery names"*.  It is **NOT** "recovery of X completed".
Correct transition: stop/abort/quarantine recovery for X; do **not** mutate or
fence Y under authority derived from X's descriptor; re-evaluate through the
normal claim/recovery protocol; mark X complete only from independent durable
completion evidence.

A resurrected older record does not make ordering useful — continuing because a
value is numerically lower would be unsafe.  Mismatch fails closed.  (Caveat
stated: no ephemeral 64-bit id detects an exact rollback of the whole sector back
to X; that needs a non-rollbackable generation source.  Random incarnation kills
practical ABA, not arbitrary sector rollback.)

## Q3 — land as ONE protocol transition; zero is NEVER a wildcard

Given the enforced cluster-wide proto_gen gate, land it as a single transition.
**Do not** ship a release where 0 stays a wildcard in live recovery decisions.
After the bump, zero has exactly one meaning: **no valid published incarnation**
(vacant / purged / uninitialized / legacy).  Never "match any".

Landing structure (develop in pieces, ACTIVATE atomically):
1. nonzero incarnation generator + explicit lifecycle rules;
2. put it in the initial slot-claim image;
3. validate HB CRC + proto_gen + ACTIVE + node/slot identity + **nonzero
   incarnation** before treating a record as live;
4. descriptors require nonzero `victim_epoch`, `owner_epoch`, and
   `fence_prover_epoch` where that role is populated;
5. replace the optional idiom with a REQUIRED-match helper:

       if (!victim_epoch || !d->victim_epoch ||
           d->victim_epoch != victim_epoch)
               return -ESTALE;

6. bump `proto_gen` at the point publication+validation become active;
7. only then build token v2 on the now-real incarnation.

Prefer **separate APIs** for "inspect a legacy/empty record" vs "prove a live
incarnation" — an optional epoch argument recreates the wildcard bug.

MUST fail closed on zero-or-mismatch: recovery begin, takeover/adoption, fence
intent, fence certify, recovery claim, recovery advance, descriptor ownership,
fence-prover ownership, `hb_own_record()`, `slot_holds_incarnation()`.
Zero may be accepted ONLY by non-authoritative paths: identifying a sector as
empty, diagnostic decode, quarantining a legacy record, or purging it after
independent fencing/protocol proof.  Never as evidence permitting replay,
descriptor adoption, fence certification or recovery advancement.

The claim write must publish proto_gen + epoch + ACTIVE + CRC as ONE coherent
sector transition — a new implementation must never briefly publish an ACTIVE
zero-epoch record.

## Q4 — token v2 shape CONFIRMED, plus a required status field

    struct mxfs_auth_token_v2 {
        __be16 version; __be16 class; __be32 flags;
        __be64 resource; __be64 grant_epoch;
        __be64 owner_epoch;            /* mount/slot incarnation */
        __be32 owner_slot; __be32 owner_node;
    } __packed;                        /* 40B */

Normative replay binding: victim slot == owner_slot; descriptor victim
incarnation == owner_epoch; expected resource == resource; required authority
class/mode represented; grant provenance valid and complete.

- **owner_node**: redundant for uniqueness but KEEP it as an independent
  consistency/diagnostic check against slot↔node mapping errors (and dropping it
  likely saves nothing after 8-byte rounding).  `{owner_slot, owner_epoch}` is
  the authoritative identity; owner_node alone may never establish identity.
- **fs_gen**: do NOT add — the log, slice, descriptor and HB are already bound to
  the same fs generation.  Duplicating a mandatory outer binding costs space
  without adding protection.
- **Status/completeness is REQUIRED and must not be overloaded onto
  `class == NONE`.**  NONE currently means all of: no authority required /
  capture failed / could not prove the lock / mixed authorities / unsupported /
  malformed — operationally different conditions.  Reserve now:
  `VALID` (all fields captured under proven mutation authority), `MIXED`
  (contributions with differing provenance merged), `INCOMPLETE` (a contribution
  lacked provable provenance), `WRITE_AUTH` (the captured grant mode authorized
  mutation — include it unless fully implied by `class`).  Reserved bits must be
  zero for v2 or future enforcement rejects the token.  In report-only mode count
  malformed/mixed/incomplete SEPARATELY rather than normalizing to NONE.

## Q5 — capture at dirty time, and LAST-WRITER-WINS IS WRONG

Format time is too late: it should *serialize* provenance, not discover it.
Capture at the earliest point where all of these hold simultaneously: the buffer
is being made transactionally dirty; b_ops/BLFT classification is established;
the resource is known; the authorizing DLM grant is demonstrably held **in a
mutation-authorizing mode**; the local slot+incarnation are still valid.
`xfs_trans_dirty_buf()` is a plausible common seam **provided every mutation path
reaches it** — add assertions/instrumentation to detect paths that mutate before
establishing authority.

**Do not overwrite the in-core token on each dirty.**  A final image can contain
modifications from several transactions/grants; last-writer-wins would claim the
last grant authorized the whole image including bytes changed earlier under
another grant.  Merge semantics:

    no provenance yet            -> install captured provenance
    same complete provenance     -> retain
    different resource/owner incarnation/slot/class-mode/GRANT EPOCH
                                 -> mark MIXED/INCOMPLETE permanently for this
                                    pending image
    capture failure on any contributing dirty
                                 -> mark INCOMPLETE permanently

"Different grant epoch" counts as MIXED even with the same resource and owner
incarnation, unless you can prove the older contribution is absent from the
serialized image — without byte-range provenance that proof is unavailable.
Do **not** collapse MIXED into class NONE; emit an explicit MIXED v2 token in
report-only mode and reject it closed under future enforcement.

**CIL shadow/snapshot:** provenance must follow the exact image of each
checkpoint.  Snapshot provenance when CIL insertion/shadowing snapshots the item;
relogging into a later checkpoint must not mutate provenance attached to an
earlier pending checkpoint; reset only when the pending image is retired and the
BLI lifecycle permits a genuinely new set.  **Audit**: CIL insertion + relogging,
shadow log-item alloc/copy, transaction cancellation, BLI reuse, buffer
invalidation/stale handling, I/O completion + checkpoint retirement.  A cancelled
transaction must not poison a later valid use with a stale MIXED unless its
modifications remain in the buffer image.

## Bottom line (verbatim ordering)

1. Fix incarnation first under a proto_gen bump.
2. Random nonzero 64-bit equality tokens, not wall-clock ordering.
3. Zero is invalid for every authoritative recovery transition.
4. Epoch mismatch = "descriptor no longer applies", not "recovery completed".
5. Token v2 gets an explicit valid/mixed/incomplete status.
6. Capture provenance at dirty/join time, snapshot it with the CIL image.
7. Never last-writer-wins; differing contributing provenance becomes explicitly
   mixed and future enforcement fails closed.
