---
name: trap-a-set-built-from-validation-holds-nothing-for-an-obligation-not-yet-started
description: TRAP (sess580/581): 0.82.4 waited on recoveries that had VALIDATED under the PR gate; one certified but unclaimed registered nothing, so the gate lif…
metadata:
  type: feedback
tags: [fencing, scsipr, recovery, design, consult]
---

## What happened

A design consult on the exclusive-write gate said, in one sentence, "account for all outstanding OBLIGATIONS, not merely currently running threads". 0.82.4 built the dependent set from recoveries that had validated their exclusion — the running-threads half — and shipped. The next lap (s580k) failed the same way one second later: slot 1 published, the set emptied, the restore landed, and slot 0 — certified under the gate by this very node ten seconds earlier, standing on the platter, not yet claimed by the mount barrier — found no reservation.

## The lesson

- **A set populated at "I have started" cannot answer "is anything owed".** Registration at validation, at claim, at start — all of them miss the obligation that exists durably and has not begun. If the question is "may this shared thing be released", the answer must come from where the obligations live (here: the recovery descriptors on the platter), not from a mirror kept by the threads that happen to be running.
- **An in-memory set is for the windows the durable state cannot see** — a command issued whose record has not landed, a recovery between validation and publication — and it must be pinned BEFORE the action, not after it succeeds (Astra, sess581).
- **When a consult names two halves, check both were built before the record is marked fixed.** Re-read the consult's own wording against the diff; the measured residual here was named in it verbatim before the first fix existed.

Fix and evidence: CHANGELOG 0.82.6, `docs/pr-fencing-departure.md` "What may lift the gate", `tests/evidence/20260911T184939Z_d0932own_s581a`.
