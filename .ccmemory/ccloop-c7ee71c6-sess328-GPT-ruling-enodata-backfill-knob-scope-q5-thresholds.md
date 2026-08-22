---
name: ccloop-c7ee71c6-sess328-GPT-ruling-enodata-backfill-knob-scope-q5-thresholds
description: sess328 RULE-5 ruling D-513: -ENODATA arm STOP-SHIP (must backfill synthesized LEGACY_INTENT outcome); knob one-shot+slot-scoped + genuine mid-replay…
metadata:
  type: project
tags: [d-513, rule-5, quarantine, foreign-replay]
---

# sess328 RULE-5 ruling — D-513 pre-rig follow-up (3 questions)

## Q1: -EPERM→-ENODATA arm (intent-path quarantined descriptor, no outcome record)
latch+release+no-import is **STOP-SHIP** — recreates terminal-but-uncommunicated
state (peers park forever; remount cannot reconstruct verdict). Required:
**backfill terminalization** while holding the generation-matched recovery lease:
1. Recognize descriptor==QUARANTINED && outcome==EMPTY as legacy INTENT-path state.
2. CAS the EMPTY outcome slot to a synthesized terminal record (publish must be
   allowed even though descriptor already quarantined).
3. Read back canonical, import, latch, release, stop reaping.
Domain = narrowest provable from durable legacy metadata; if none, FSWIDE.
Reason must record provenance: new reason code LEGACY_INTENT (NOT TORN, not plain
POLICY). CAS conflict → normal canonical readback. Transient → retry
terminalization, never replay. If format can't backfill: all nodes must derive
deterministic fail-closed FSWIDE import (inferior, but never indefinite park).

## Q2: freplay_force_refusal knob
Post-success verdict forging = valid **phase-A containment/plumbing** coverage
only. Before the definitive 32-node acceptance: need (a) at least one genuinely
UNAPPLIED POLICY path (note: the sess41 blanket ATOMIC-SKIP gives this naturally —
kill a node mid-write, incident-513 shape) and (b) one genuine MID-REPLAY TORN
path (fail after a deterministic replay prefix, real cancel/unwind, verify no
writes after failure point). Knob must be **one-shot** and **scoped to victim
slot (+recovery generation)** — a global sticky param makes later recoveries
ambiguous. Reads inside quarantined domain still -EIO; don't bypass gate to
observe stale data.

## Q3: Q5 residue relaxation CONFIRMED with bounds
Criterion = zero timeout-CASCADE shutdowns; local dirty-cancel shutdowns counted
separately. Attribution rules: quiescent refusal tests = ZERO local shutdowns; no
local shutdown from ops started after activation / outside domain / waiters that
should park or EIO / secondary timeouts; residue stops growing after import
propagates; residue-node fencing deaths = cascade. Predeclared thresholds @32:
0–3 of 31 survivors acceptable under saturated stress; >3 repeatable or scaling
with stressed nodes → build activation/drain barrier; ~majority = relaxation
cosmetic, fails. Also record exposed-node count (already-dirty domain-overlapping
trans at activation) → metric = shutdowns/exposed.
