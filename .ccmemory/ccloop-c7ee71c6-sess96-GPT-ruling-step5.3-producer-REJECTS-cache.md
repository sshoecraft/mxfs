---
name: ccloop-c7ee71c6-sess96-GPT-ruling-step5.3-producer-REJECTS-cache
description: sess96 RULE-5 ruling: the grant_meta-cache epoch source is REJECTED (release blocker). Thread the epoch out of the granting CAS; durable authority mu…
metadata:
  type: reference
tags: [sess96, step5.3, authority-token, foreign-replay, RULE-5, D-FOREIGN-REPLAY-UNGATED-IMAGES]
---

# sess96 RULE-5 ruling — step 5.3 PRODUCER half

I brought three decisions. **Decision 1 was rejected outright and named a release blocker.**

## D1 — epoch source: hash cache REJECTED, use a CAS out-parameter

My proposal (cache `ex_grant_epoch` in the existing `ctx->grant_meta[]` bucket at
`caw_grant_meta_store`, read it back at the xfs acquire site) is **not acceptable for
certificate provenance**. The cache is fine as a hint; it cannot establish the property
that actually matters.

The needed property is NOT "this epoch came from some successful grant on this resource"
— it is **"this epoch came from THIS EXACT successful grant operation, whose authority is
now being installed on this inode."** A hash bucket cannot prove that.

My monotonicity argument was refuted with a concrete interleaving:

1. acquire A grants epoch 10; 2. A is delayed before installing inode state; 3. the grant
is released, inode reaches NL; 4. acquire B grants epoch 11 and stores 11; 5. **A resumes,
reads 11, takes `i_dlm_lock`, sees NL, and installs EX with epoch 11 off A's completion.**

`mode > ip->i_dlm_mode` only protects the case where someone ALREADY installed EX. It does
not protect a full EX→NL→EX cycle where the OLD completion wins the inode lock. Also:
same-resource stores that preserve the epoch retain it across release transitions;
`releasing` is separate state with its own check/use race; and the underlying generation is
**uint32 — not globally monotonic after wrap** regardless of the uint64 field.

Ruled shape: the successful durable acquire returns an immutable
`{backing_resource, grant_epoch, backing_kind, acquisition cookie}` populated directly from
the successful CAW before it can be confused with a later operation. At the XFS layer,
publish only after validating **under `i_dlm_lock`** that: this completion is still current
(cookie/state-sequence, NOT `mode > i_dlm_mode`), release has not begun, routing still
matches backing_resource/kind, the inode is not reclaiming/withdrawing, and this is a
transition to a NEW DURABLE EX TENURE rather than merely `mode == EX`.

## D2 — coverage gaps

"No certificate → non-proving" is authority-safe **only if the formatter cannot retain or
discover an older certificate**.

- **(i) unpublished/local EX**: hooking the lazy publish worker is valid, but it CANNOT sit
  inside `mode > i_dlm_mode` (the inode is already locally EX). Needs an explicit
  `UNPUBLISHED_EX → DURABLE_EX` authority-state transition, using the worker's own CAW
  result, re-validated under `i_dlm_lock`.
- **(ii) mirror re-affirm sites**: never mint or reactivate there. If release-begin already
  happened the old certificate is permanently dead even though the mirror still says EX.
  Flagged as possibly MORE than coverage loss: if those paths modify recoverability-critical
  metadata at volume, normal committed workloads could become unrecoverable after a node
  death. Product-level correctness question — measure the population.
- **(iii) routing change**: clearing is mandatory but insufficient as a model — it leaves
  the inode non-proving FOREVER because `mode > i_dlm_mode` never becomes true again. A
  backing change IS an authority-tenure transition: revoke → establish new backing durably →
  mint from that acquire result → publish. Format time must also check the certificate's
  immutable backing still agrees with current routing; mismatch = NON-PROVING.

## D3 — revoke set: enumerating the mode=NL stores is NOT the invariant

Clearing at the 11 `mode = NL` sites is necessary cleanup but does not establish
"unpublished at the FIRST release-begin boundary". NL is assigned AFTER the slot is marked
releasing, after unlock/handoff is sent, after a peer can begin acquiring, after EX→PR
demote, after reclaim. **The primary hook must be a centralized release-begin/revoke helper,
not the mode-lowering helper.** Ruled: `mxfs_inode_authority_revoke_locked()` /
`begin_release_locked()` / `install_durable_ex_locked()`; revoke under `i_dlm_lock` BEFORE
any outwardly visible relinquishment or routing change.

The mechanical rename-to-break-raw-stores change **is worth it** for this boundary, and
publication must be centralized too — centralizing revoke while leaving publish scattered
across three mode comparisons is still brittle. Assertions to add: cert ⇒ durable EX;
cert ⇒ !unpublished; cert ⇒ !releasing; cert backing == current routing; non-EX ⇒ no cert.
(The converse — durable EX ⇒ cert — must NOT be asserted: alloc/lookup failure is
legitimately non-proving.)

**RCU/reuse**: `kfree_rcu` at `->destroy_inode` covers memory lifetime but NOT logical
revocation. Clear at reclaim/eviction BEGIN, before removal from the per-AG tree and before
ino reuse can be visible. `ip->i_ino == wanted` is **not** an adequate incarnation check —
immediate reuse gives the same ino. Hold `rcu_read_lock()` across lookup + state/incarnation
validation + dereference + copy, reject stale/reclaiming entries, and validate a generation
or tree-insertion sequence. Define the validated dereference as the authorization
linearization point and prove release is ordered against it.

## Additional release blockers named

1. **uint32 epoch wrap** — a stale record compares equal again after wrap. Needs a proved
   wrap policy (wider durable incarnation, namespace fence, or proven impossibility within
   the stale-record lifetime).
2. **Grant identity must be separate from mode** — `i_dlm_mode == EX` cannot distinguish
   unpublished / durable / releasing / re-affirmed / rebacked EX.
3. **Stale acquire completions** — the out-param fixes provenance, not completion ORDER.
   Validate a per-attempt cookie when installing.
4. **Transaction/CIL tenure crossing** — prove an item modified under grant A cannot be
   formatted with grant B's certificate. Either all items format before release-begin, or
   each item captures the tenure sequence and format re-validates, or crossing forces
   non-proving. Verify explicitly for CIL/delayed logging.
5. **Alloc failure** — preallocate outside the spinlock; failure leaves NULL + non-proving,
   never retains the old certificate.
6. `rcu_assign_pointer`/`rcu_replace_pointer`; never mutate a published certificate.
7. **Recovery transaction atomicity** (restates the sess95 blocker 3) — per-record
   fail-closed authority is not automatically transaction-safe recovery.
