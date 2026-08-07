---
name: ccloop-c7ee71c6-sess115-GPT-ruling-blockers-2-3-WITHDRAWN-two-new
description: sess115 RULE-5 ruling: FACT A accepted — sess114 blockers 2 and 3 WITHDRAWN, snapshot-subtract withdrawn; two new blockers (ICLUSTER quiescence, prov…
metadata:
  type: reference
tags: [mxfs, dlm-caw, gpt-ruling, lreq-registry, samenode-waiter, sess115, iclusters]
---

# sess115 — RULE-5 ruling: the cached-lock model is accepted; blockers 2 and 3 are withdrawn

Facts submitted: `…sess115-cached-lock-model-invalidates-blockers-2-3` (FACTS A-D).
Prior ruling being revised: `…sess114-GPT-ruling-cancelling-accepted-10-more-blockers`.

## Verdict per item

**FACT A ACCEPTED.** *"`tenure[]` is not a local-use reference count… `sum(tenure[]) > 1 ⇒ do not clear` would be incorrect and must not be implemented. It would turn historical shortcut successes into permanent references and prevent normal BAST-driven eviction. The earlier A/B corruption sequence assumed balanced local acquisition/release semantics that this API does not have."*
Refinement worth keeping: buckets are not *strictly* monotone (the convert decrements `conv_from`), but neither a bucket nor the sum represents outstanding users.

**Blocker 2 — WITHDRAWN AS WRITTEN.** Do not build `refs > 1 ⇒ no clear`.

**Blocker 3 — WITHDRAWN in its tenure/effective-count form.** My self-deadlock argument accepted verbatim.

**Blocker 1 — SPLIT.** The linearization requirement STANDS (destructive clear must be linearized against local grant/join/adopt publication) and CANCELLING-vs-JOIN still stands. **Mandatory snapshot-subtract is WITHDRAWN**: under a proven whole-resource exclusion, *"blanket retirement is correct… snapshot-subtract would be conceptually misleading because there are not independent grant references to preserve."* And it was never the real fix anyway — it preserves bookkeeping, not the disk grant that was cleared.

**Blockers 4-10 — NOT reclassified** (their text wasn't in the prompt). *"Any of them that treats `tenure[]` as balanced outstanding demand must be revisited; blockers concerning CAS validation, memory ordering, wakeups, error paths, generation handling, or teardown may remain unchanged."* → next session must re-check 4, 5, 8, 9 against FACT A; 6, 7, 10 look untouched.

## The replacement requirement (this is the new frame)

> A destructive disk transition — eviction, cancellation cleanup, or downgrade — may occur only after the authoritative **upper-layer** resource state has stopped new dependent activity and established that all previously admitted dependent activity is quiescent, or after a DLM-level protocol has provided an equivalent resource-wide exclusion.

Two distinct kinds of state, and `lreq` may only speak to the first:

1. **Transient CAW operations** (grant / convert / cancel / adopt / release attempts) — serialize these with `lreq` op state (CANCELLING, JOIN, RELEASING).
2. **The lifetime of protected XFS activity after `lock()` returns** — `lreq` **cannot** track this; there is no balanced release notification. Must come from `pag_dlm_demoting` (AG), the inode state/drain protocol (1:1 resources), or a NEW mechanism for ICLUSTER.

So my proposed scope was accepted with one qualification: *"`lreq` may prevent one transient attempt from clearing or superseding state required by another transient local attempt. It cannot prove that no already-returned XFS user still depends on the cached node grant."*

Also directed: **stop naming `tenure[]` as if it meant tenure/references** — document it as epoch-scoped historical accounting and exclude it from safety decisions. (Judgement for next session: the *existing* `lreq_plan` holder guard `tenure[giveup_mode] > 0` is still sound as a FAIL-CLOSED "this node was granted m in the current cached epoch, so the bit is load-bearing" predicate — that is not a reference-count use. The naming/doc fix is what is owed.)

## Correct downgrade rule (replaces blocker 3)

> Before weakening the node's disk mode from H to L, the authoritative resource state must establish that no admitted local activity still requires a mode stronger than L, **while preventing new such activity from being admitted** until the conversion commits or aborts.

Valid sources: (A) upper-layer quiescence — mark converting → block admissions → drain → downgrade → publish → reopen; or (B) a genuine balanced desired-mode aggregate, which `tenure[]` is not. CAW conversion still needs operation-level serialization: a stronger request must not complete on the old high mode while a downgrade is committing and then continue after the high bit is cleared — it must either be admitted before the quiescence boundary (forcing the downgrade to abort or pick a stronger target) or wait and then upgrade.

## NEW BLOCKER 1 — ICLUSTER resource-granularity quiescence

My FACT-C hole is CONFIRMED REAL, with the sequence spelled out: `T1` demotes `I1`, `T2` demotes `I2`, same ICLUSTER resource; `T2`'s already-held CAW ensure **finishes** and `T2` continues protected drain activity with no balanced CAW reference covering it; `T1` performs the whole-node ICLUSTER clear; a peer takes an incompatible grant while `T2` is still using it.

**A DLM-level RELEASING state does NOT fix this** — if `T2`'s transient `lock()` ended before `T1` entered RELEASING, `lreq` no longer knows `T2` is active. *"A mere mutex around the final CAW unlock is insufficient; the exclusion must cover the protected drain lifetime, not only the disk operation."*
Valid constructions: shared ICLUSTER admission/drain state + active-drainer count; a release-pending flag that blocks new cluster admissions and waits for all admitted cluster users; or serializing the whole ICLUSTER demote/drain/unlock under a cluster-level coordinator.

## NEW BLOCKER 2 — adoption must be PROVISIONAL

FACT D confirmed real. Ordinary grant CAS races are already covered by the disk CAS itself (whoever goes second miscompares) — **but adoption has no local disk write, so it lacks that natural ordering.** A pre-CAS sequence check cannot close a mutation between the check and the CAS; a post-CAS check only detects damage.

Required protocol: releaser enters RELEASING under the per-resource op lock → no adopter may publish a *usable* grant while RELEASING is active → an in-progress adoption either becomes visible before the release snapshot (aborting the release) or stays **provisional** and retries after → the clear runs only once all pre-existing grant/adopt ops are resolved → admissions reopen. *"An adopter must not let protected XFS activity proceed until its adoption is committed against the current release epoch."* A generation/epoch can implement this **only if it participates in the publication protocol**; a free-running sequence check before the CAS is insufficient.
Post-CAS check is worth keeping as defense/diagnosis: on movement after a successful clear the releaser must NOT return ordinary success — stay in RELEASING and either force the provisional adopter to retry from the cleared state or synchronously reacquire before reopening. Safe only while the adopter is still provisional; if the adoption was already exposed to XFS, repair is too late.
Also fold in direct-handoff/cancellation races: release must not coexist with an outstanding local request a peer can still satisfy, unless the resulting handoff is explicitly rejected/relinquished or adopted under the release epoch.

## Blanket retirement (blocker 1 tail) — validity is per resource type

- **AG:** FACT B sufficient, *assuming every admission path observes `pag_dlm_demoting`* (audit owed).
- **1:1 inode resources:** FACT C sufficient if there is truly only one demoter and every admission path observes `i_dlm_state` (audit owed).
- **ICLUSTER:** NOT sufficient — blanket retirement is unsafe until resource-wide quiescence exists.
- **Any generic/direct CAW path bypassing the XFS gates:** must be separately covered (audit owed).

The governing invariant: **"No post-boundary grant/adoption publication may become usable across a successful destructive clear."** Once that holds, blanket epoch reset is valid.
