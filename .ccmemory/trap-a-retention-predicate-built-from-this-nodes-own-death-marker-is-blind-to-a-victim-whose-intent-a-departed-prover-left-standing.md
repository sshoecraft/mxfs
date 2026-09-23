---
name: trap-a-retention-predicate-built-from-this-nodes-own-death-marker-is-blind-to-a-victim-whose-intent-a-departed-prover-left-standing
description: TRAP (s67f, 0.89.4): the 0.89.3 "dead is not reclaimable" test used the local recovery-pending marker; a lone cold return swept its own previous inca…
metadata:
  type: feedback
tags: [dlm, tauth, recovery, orphan-sweep, retention, d0356]
---

# A retention predicate built from this node's own marker is blind to obligations other nodes created

## What happened (d0356_stranded_prover_return s67f on 0.89.3, 2/tcp)
- A declared B dead, wrote a durable FENCING intent into B's slot (RECOVERY_GUARD, stage 1), had its 21 fence attempts refused (harness knob), unmounted cleanly and RELINQUISHED the attempt (owner 0, descriptor standing).
- B cold-booted and mounted alone. Its mount's orphan sweep ran BEFORE the join gate declared any death. The sweep's dead test (occupant by the slot-node map — which does not map a RECOVERY_GUARD record — and membership view) said dead; the 0.89.3 judging callback looked only at B's recovery-pending marker (unset) → judging=0 → 3 pages taken over, the victim's records retired.
- Minutes later B set the marker, took the attempt over, certified (BOOT_SUCCESSION_ABSENT), sealed the fence-time manifest with entries=0, replayed: notheld=6 → ATOMIC-SKIP → -117 → P241-RECOV-TERMINAL ag_mask=0x3 → cluster-wide AG quarantine; B's reads EIO, A's rejoin mount rc 32 at AG 0.
- The 0.89.3 rationale ("the frozen ACTIVE record keeps the victim the occupant until the death is declared") fails once a prover converted the slot to a descriptor and left.

## The lesson
- A retention/reclamation predicate must be authoritative from the DURABLE object (the platter's descriptor), never from a per-node volatile marker. Markers are hints; "no marker" is not "no obligation". Unknown (unreadable/undecodable) protects. A matching ACTIVE record contradicts "dead".
- Retention ("may its authority history be destroyed?") is a different question from liveness ("is it a live owner?") — keep it in the reclamation predicate, not the occupancy map (Astra 2026-09-19).
- A descriptor nobody advances protecting records forever is the correct fail-closed outcome; the availability answer is adoption of the stranded attempt, never a timeout.
- Still open (consult): run the mount-time orphan sweep AFTER the mount's recovery census, and state the ACTIVE→GUARD→released handoff as an invariant with no durable gap.
- The harness's "B fenced and recovered the departed prover" assertions described the pre-relinquish stranded-owner shape; under relinquish-on-departure a clean departure is settled by the peer's PR-key retirement proof with no fence — assertions must follow the design's current shape (the harness's own NOTE branch already said so).

## Evidence
tests/evidence/20260919T135424Z_d0356spr_s67f-*/B_journal.txt:62-77 (sweep), :88 (marker), :101 (entries=0), :122-142 (refusal/quarantine); fix in dlm/v5_mount.c v5_recovery_judging_cb (0.89.4, srcversion 9FE0EA9A4DEF0C4700F5A41); verified s67h (entries=3, replay complete) and s67k (PASS fails=0, 446 s).
