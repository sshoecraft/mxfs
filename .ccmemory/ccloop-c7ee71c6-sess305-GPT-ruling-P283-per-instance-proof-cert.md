---
name: ccloop-c7ee71c6-sess305-GPT-ruling-P283-per-instance-proof-cert
description: sess305: P283 root PROVEN (concurrent dup release pipelines alias shared rel_state) + RULE-5 ruling: per-instance tenure-bound proof cert, cas_noproo…
metadata:
  type: project
---

# sess305 — P283-RELCERT-CAS-UNPROVED root + GPT ruling

## Root (RULE 4 PROVEN from existing fleet dmesg, no build needed)
All 33 cas_unproved events (0.11.509, 752,428 attempts): res=1076037 hot shared dir,
path=anchored, relstate=RELEASING. Uniform signature at every occurrence examined
(test10 x2, test8 x3): TWO concurrent mxfs_dlm_bast_process release pipelines from two
different kworkers — duplicated P51-REL, duplicated P147-PREUNLOCK (two comms ~10us apart),
duplicated P6H-HANDOFF (identical gen/slot/epoch), two P70-BP EXIT=full with SAME rel_gen.
Both instances ran the proof; the later stamper read the peer's RELEASING (CAS window is
multi-ms). Single-thread flow cannot stamp RELEASING (close_or_defer always leaves
DRAINING/PROVED/DEMOTING right before the stamp). Concurrent dup drains are legal by the
two-slot demoter design (i_dlm_demoter/i_dlm_demoter2, "reachable and entirely ordinary").
The audit on the shared scalar i_mxfs_rel_state is unsound both directions under overlap.

## GPT ruling (Option A)
- Proof authority = per release INSTANCE, not the inode scalar. cert gains proved flag +
  tenure binding (rel_gen etc.); proof body marks it PROVED; CAS consumes the same cert.
- New versioned metric cas_noproof_v2 = CAS entries whose OWN cert was not proved. Steps
  9-10 gate on v2 == 0 over soak, NOT on the legacy cas_unproved (keep it as diagnostic;
  preserve the 33 as evidence of the audit defect, not F1-F4 failures).
- i_mxfs_rel_state downgraded to diagnostic/aggregate; must NOT be a correctness gate
  (step 6 gating must use per-instance state; one scalar can't represent overlap: peer
  finish writes ACTIVE while another instance is live).
- Do NOT serialize the pipeline (Option B rejected: liveness risk, history of swallowed
  BASTs/stuck DEMOTING). CAS-window mutex also rejected. Per-rel_gen dedup allowed later
  as perf opt only, fail-open, never part of the proof argument.
- Duplicate concurrent release itself: NOT a defect by design IF 7 invariants hold:
  (1) only CAS winner publishes authoritative handoff; (2) to_slot part of committed
  transition or pre-CAS msgs tentative+gen-tagged; (3) divergent concurrent to_slot
  choices safe — exactly one commits, loser abandons/reconciles; (4) CAS-loser completion
  must not reset winner state (e.g. loser's finish writing ACTIVE); (5) ancillary effects
  duplicate-safe (waiters, refs, tickets, wakeups); (6) CAS compare covers full tenure
  identity, no ABA via rel_gen reuse; (7) committed transition once, post-CAS effects
  once-or-idempotent+winner-validated. Any unproven → open a SEPARATE verification
  defect (especially handoff publication before winner determination).

## Where
Proof body: xfs_mxfs_dlm.c mxfs_relbar_close_or_defer ~14732; anchored CAS stamp ~19168;
noanchor ~18907; iclus_disk_release ~47242 (own ic->rel_state, busy-gate serialized);
emit/audit ~40269 (P283); dump P280-RELEASE-CERT-TOTAL ~40331.
