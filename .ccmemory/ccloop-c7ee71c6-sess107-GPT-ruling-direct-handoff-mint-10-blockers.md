---
name: ccloop-c7ee71c6-sess107-GPT-ruling-direct-handoff-mint-10-blockers
description: sess107 RULE-5 ruling: the RELEASER may mint the grantee's epoch (the CAS is the linearization point) — but 10 release blockers, incl. a NEW latent d…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, dlm-caw, gpt-ruling, direct-handoff]
---

# sess107 RULE-5 ruling — direct-handoff epoch minting

Consult carried the sess106 root (`…sess106-P241-MEASURED-direct-handoff-mints-no-epoch`)
plus the AG escalation found this session. Verdict: **the releaser MAY mint the
grantee's tenure epoch** — but the fix is not two lines. 10 release blockers.

## The core ruling

> A write-authority epoch is minted in the same atomic durable slot transition
> that first grants EX-class ownership for that tenure.

The identity of the node issuing the C&W is **irrelevant**. The holder bit and
`last_ex_slot` identify the beneficiary; the CAS is the linearization point.
Requiring a second grantee CAS adds latency without adding authority — so the
direct handoff keeps its reason for existing (the ~900ms 9-node admission storm).
Adoption is *recognition* of a durable grant, not creation of authority.

Refactor the helper to take the **actual grantee** explicitly —
`caw_grant_epoch_update(s, grantee_slot, mode)` — never `ctx->node_slot`, so no
future third-party grant path repeats this bug.

**Invariant:** every transition from "no write-capable holder" → EX/PW holder
mints a new token: self-promote, direct handoff, PR/CW→EX/PW conversion, recovery
or steal paths, AND same-node reacquisition after release.

## NEW LATENT DEFECT the consult surfaced (not previously ledgered)

`uint64_t ex_grant_epoch = (uint32_t)s->generation` is **not a 64-bit epoch** — it
is a zero-extended 32-bit cyclic token. Two concrete failures:

1. After 2^32 successful slot CASes a tenure token **repeats** — and `generation`
   advances on EVERY CAS (waiter registration included), not just on grants, so a
   hot resource wraps far sooner than a count of tenures would.
2. On wrap `generation == 0`, so a granting CAS mints the **explicitly invalid**
   token zero, which the sess97 rule reads as "namespace restarted, fail closed".

Ruled: a durable 64-bit per-resource sequence is preferred —
`next = s->ex_grant_epoch + 1; if (next == 0) next = 1;` — serialized by the slot
C&W, so it need not equal the CAS generation; it only has to uniquely name the
tenure. At *minimum*, wrap and zero-mint must be detected and fail closed.
Shipping while claiming the current token "uniquely names one tenure" is unsound.

**MY OWN CAVEAT on that design (GPT did not have this fact):** `caw_tombstone_slot`
PRESERVES `generation` but ZEROES `ex_grant_epoch`. So a naive `+1` sequence
RESTARTS at 1 after every tombstone+reclaim of the same resource, reintroducing
exactly the false-match the sess97 zero-rule exists to prevent. The `+1` design is
only correct if the tombstone also PRESERVES `ex_grant_epoch` (alongside the
dir_epoch / last_ex_slot / open_holders it already carries). Then the namespace
never restarts and zero simply never recurs after the first grant.

Residual hazard, PRE-EXISTING and not introduced by either design: if resource X's
slot is tombstoned, recycled by a DIFFERENT resource Y, and X is later re-claimed
at a different slot index, X's epoch namespace restarts from that slot's lineage.
Authority must therefore be validated as the tuple **(resource identity,
ex_grant_epoch)**, never as a globally unique scalar — GPT flagged this
independently and it is an explicit audit item for the replayer.

## Release-blocking items (GPT's list, verbatim in substance)

1. Mint a fresh nonzero epoch in every direct EX/PW handoff CAS.
2. Refactor the mint helper to take the actual grantee, not `ctx->node_slot`.
3. Populate AND validate the grant result on adopted success.
4. Reject write-capable grants with zero/stale/inconsistent epochs.
5. Convert the AG path to use the acquire's threaded grant result.
6. Prove or fix adopt/cancel/reconcile/death-purge linearization and fencing.
7. Handle 32-bit generation wrap; prefer a real 64-bit durable sequence.
8. Gate mixed-version operation, or disable direct handoff cluster-wide during
   upgrade (a LOCAL module param is insufficient — an old node can be the
   RELEASER and hand off with no epoch, and an old GRANTEE will still accept a
   new-style handoff and stamp false authority). Maps onto the open ledger entry
   D-MIXED-VERSION-UNGATED-REPLAY.
9. Audit every transition that can first install EX/PW ownership.
10. Confirm replay binds epochs to the correct resource.

## Item 6 detail — the dangerous race (NOT the abandoned-grant one)

A minted-but-never-used epoch is **harmless**: it just leaves a gap in the
sequence, and a replayer must not assume every minted epoch produced metadata.

The dangerous shape is adopt-vs-clear linearization:
1. grantee observes its holder bit, starts adopting;
2. abort/reconcile clears that holder;
3. a new node is granted EX;
4. the old grantee completes adoption and writes under its earlier epoch.

An epoch proves authority *was* held, never that it *remains* current. Required:
no cleanup path may clear a possibly-live adopted holder unless serialized with
that node's adopt/cancel state, or the node has first been storage-fenced.
Reconcile must be bound to the particular acquire attempt/tenure and its CAS
should compare expected epoch/generation + holder mode, **not merely the node
bit** — otherwise it can clear a later REacquisition by the same node.
*"If the existing abort reconcile can remove a live node's holder based only on
an abandoned waiter observation, direct handoff is not safe, with or without the
epoch fix."*

## Item 3 detail — what the adopt arm must validate

Fill from the exact slot image that established adoption, and for EX/PW verify:
holder bit present; waiter bit gone; mode write-capable as expected;
`last_ex_slot == this node`; `ex_grant_epoch != 0`. Malformed/legacy direct grant
⇒ **fail closed**, never `rc == 0` with zero/stale authority.

Structural defense (GPT item B): make `rc == 0` ⇒ fully-initialized consistent
result an enforced API invariant — init the out-param to INVALID at entry, funnel
every success return through ONE finalization helper, WARN in debug builds on an
EX/PW success with zero epoch.

## Item 5 detail — why the AG reread is false attribution, not cosmetics

`xfs/xfs_mxfs_dlm.c:35083` reads the token as a SEPARATE post-acquire I/O
(`mxfs_v5_dlm_ag_grant_epoch`) and installs it in `pag->pag_mxfs_grant_epoch`,
which `xfs_buf_item_format_segment` stamps lock-free into EVERY buffer-log record
of the tenure. Bad sequence: acquire succeeds → our holder is cleared by
reconcile/purge → another node gets EX and mints → our reread returns THEIR
epoch → we stamp it. Reading a nonzero current epoch is not enough; it must be
tied to the grant THIS acquire returned. Thread the result; drop the lookup.

## PR (item 4)

PR must NOT mint (it confers no write authority, and minting would imply a write
tenure). The PR adopted result must expose **no** write-authority epoch (zero /
invalid status), not the stale slot value. Every PR→EX/PW conversion must mint in
the exact CAS installing the write-capable mode. Refactoring the PR batch arm
itself is follow-on; verifying every PR→write transition mints is blocking.

## Ordering (item 7)

Compute generation/epoch before the C&W, publish in the same 512B image. Validate
the nominated waiter BEFORE installing: `yield_to` is exactly one valid node bit,
corresponds to an eligible EX/PW waiter, slot otherwise grantable, node slot in
range. Do not mint when the CAS only releases. **A C&W that succeeds on disk but
returns an ambiguous transport result must still leave an adoptable image — the
token must not depend on the releaser seeing a successful completion.**

## Upgrade handling (GPT item D)

Existing slots hold stale/zero/near-wrap epochs. New code must NOT "repair" an
already-held EX tenure by assigning an epoch after metadata may already have been
dirtied. Either the grant was atomically minted, or the write tenure fails closed
and is reacquired through a correct transition.

## Bottom line (quote)

> Do not fix only the missing adopt result. That would turn an uninitialized
> authority token into a confidently wrong one.
