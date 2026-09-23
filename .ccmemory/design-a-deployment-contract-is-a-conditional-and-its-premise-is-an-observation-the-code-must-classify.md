---
name: design-a-deployment-contract-is-a-conditional-and-its-premise-is-an-observation-the-code-must-classify
description: DESIGN (Astra s82 ruling, 0.89.15): matching a contract proves the deployment ASSERTED something, never that its premise happened here; classify the…
metadata:
  type: project
tags: [fencing, scsipr, design-ruling, retirement]
---

# A contract is a conditional, and nobody had established its antecedent

Full ruling: `docs/rulings/retirement-proof-obligation-and-observed-transition-classes.md`
(Astra, session 82). It **corrects** the previous ruling and the 0.89.13 package.

## The trap it closes

0.89.13 shipped a deployment clause — *for this LUN, every command accepted from
a **lost nexus** completed or aborted before that nexus's registration
disappears* — and treated "the clause matches this LUN" as a retirement basis.
It is an **implication**. Matching the vendor/product/firmware/LUN establishes
that the deployment made the assertion. It does not establish that **this**
registration disappeared **because that nexus was lost**, and no initiator can
establish that: the target never reports why a registration left its table.

So the same clause was authorising replay after any absence at all, including a
key MXFS itself had replaced — the exact case kind 19 refuses.

## What an initiator can and cannot state

- CAN: the registration is gone, and whether MXFS's own durable PR ledger
  records one of our mounts replacing it (and if so, from which boot).
- CANNOT: why the target removed it. Not from PR IN, not from the PR
  generation, not from waiting longer.

Under the loss clause, **all three** observations leave retirement unproven —
not just the same-boot one. A different boot id proves nothing about the
target: an iSCSI connection, an iSCSI session, a SCSI I_T nexus and an MXFS
boot identity are four identifiers with four different lifetimes, and an
initiator instance (HBA, firmware, hypervisor, another service) can outlive the
restarted component. "No successor record" proves nothing either: an
administrator, an ordinary PREEMPT, a CLEAR or a crash between the PR mutation
and the ledger write all defeat it, and a Write Exclusive gate does not freeze
the PR table.

## The shape that is sound

1. Classify the **observed transition** as an enum, separate from any claim
   (`no-mxfs-successor-observed`, `mxfs-replacement-same-boot`,
   `mxfs-replacement-different-boot`, `victim-registration-present`). UNKNOWN is
   a refusal, never a wildcard.
2. A **clause covers exactly one observation**. Write the clause about the thing
   that can be observed — 0.89.15's is
   `unreplaced-registration-absence-retires-before-purge`. Keep the withdrawn
   clause RECOGNISED and always refused, with the reason printed, so a
   deployment carrying it finds out instead of being certified.
3. Enforce the obligation at the **certificate constructor**, not per kind: a
   predicate taking only `kind` can identify a potentially proof-bearing kind,
   it cannot decide whether the contextual obligations were met.
4. A failed proof must not become a mutable "bad absence" flag another path can
   clear, nor a permanent veto: a later path that really performs a scoped
   abort is satisfying an obligation, not clearing a prohibition.

## The five shortcuts that recreate the defect

1. "different boot id" ⇒ "covered target-side nexus loss".
2. "no successor record" ⇒ "loss was the only possible cause".
3. "Write Exclusive + matching contract" ⇒ "retirement".
4. A new trigger name or durable basis label standing in for missing evidence.
5. Fixing one kind while another keeps the same inference — it only moves the
   bypass.

A **correctly worded, qualified** contract is not inferior to refusal; an
unsubstantiated renamed assumption is. The honest boundary where neither a
scoped completion witness nor an applicable clause exists is "no
replay-authorising certificate", never "probably drained".
