---
name: ccloop-c7ee71c6-sess169-GPT-ruling-edge-mint-tenure-token
description: sess169 RULE-5 ruling (#15): edge-triggered mint APPROVED — mint iff can_write(new) && !can_write(prior from cur_slot); cur_slot into helper; caw_ver…
metadata:
  type: project
tags: [mxfs, sess169, gpt-ruling, ex-grant-epoch, epoch-tenure, mint-policy]
---

# sess169 — RULE-5 ruling: D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID fix design (gpt-5.6-sol)

Full ruling text in sess169 transcript (task kplzaeanf). Operative content:

## Q1 — mint policy: option (a) APPROVED, edge-triggered
Invariant: `ex_grant_epoch` changes exactly when a node begins a new continuous write-capable tenure.
`mint = can_write(new_granted_mode) && !can_write(node_held_mode(cur_slot, grantee_bit))`.
PW→EX / EX→PW stay in-tenure (no mint). EX→PR/NL ends tenure. Re-entry after full release mints (holder masks decide, NOT last_ex_slot — tombstone carry keeps last_ex_slot==self).
Option (b) (range gate) REFUTED: more manifest state, ordering semantics consumers deliberately lack, partial-publication crash-consistency problem.
Prerequisite to assert: at most one node write-capable per resource at any time.
On preserve path: EXPLICITLY copy `new_slot->ex_grant_epoch = cur_slot->ex_grant_epoch` (don't rely on image inheritance).
Fail-closed probe: `can_write(prior) && cur_slot->ex_grant_epoch == 0` = concealed continuity loss — assert/log, never mint over it.

## Q2 — signature (ii) APPROVED: pass cur_slot (const, the exact CAS compare image)
`caw_grant_epoch_update(new_slot, cur_slot, grantee_slot, new_mode)`. node_held_mode must inspect ALL holder masks; malformed multi-mode image → classify conservatively write-capable if ANY held mode is write-capable (never silently NL). No new/cur aliasing. Validate grantee bit. Edge table confirmed (claim/handoff/promote-from-PR/compat-add-NL-PR/convert-PR→EX = MINT; any prior PW = PRESERVE).
Extra test cases: (1) writer A→writer B in ONE CAS mints on B's prior mode (A's write-capability in cur_slot irrelevant); (2) same-node release→tombstone→reacquire MINTS.
Dead `_orig` flush function: convert or REMOVE (reactivation hazard) — build forces it since signature changes. DECISION: remove.

## Q3 — last_ex_slot/dir_epoch rules unchanged; same-token republish idempotent
Check for `if (old_epoch == new_epoch) skip_publish()` patterns — token equality must not suppress OTHER manifest metadata updates.
**GATE BLOCKER (goes on #1's list): historical-record lifetime.** A single current-manifest-token cannot prove an older-token record stale — node may release+reacquire while tenure-1 records remain replay-required in the log. Enforcing refusal needs one of: (i) proof no earlier-tenure record can be replay-required after manifest advances; (ii) tenure end forces/checkpoints records before token advance; (iii) historical per-tenure authority info at recovery; (iv) supersession proof before refusal. "Likely the most important remaining proof obligation."

## Q4 — wrap injection: re-arm-and-retry on quiet resource ACCEPTED
Consumable knob consumed on failed CAS attempt is fine — test records and retries until committed gep=1 observed. Run on sacrificial resource (~0→1 deliberately reproduces old token values). Test validates SKIP-ZERO, not wrap uniqueness. Target injection to edge-triggered mint arm ONLY (never fire during preserve). Assert nonzero at commit/stamp boundaries too, not just log sweep.
**Spec obligation: wrap policy must be documented** — skip-zero ≠ uniqueness-forever. Either formally document "overflow unreachable within supported lifetime" (2^64 CAS-rate math) or implement fail-closed exhaustion/incarnation rollover.

## Q5 — caw_verify user-mode test IS the vehicle for the PW arms
Sequence: acquire PW → token T≠0; upgrade EX → still T; downgrade PW → still T; release; reacquire EX → token ≠T, ≠0 (use !=, NOT >). Cover BOTH live paths: convert-upgrade AND compat-add, with branch attribution (drive distinct API calls; assert P274 preserve probe fired). Kernel EX-only + wrap test NOT sufficient for the ledger claim. Defensible ledger statement: kernel EX path regression-tested incl trailer/manifest propagation; PW edge-preservation verified at real CAW protocol layer user-mode; PW-through-XFS unreachable by design.

## Q6 — enforcing-gate prerequisites (beyond #15; most belong to #1's gate design)
1 resource-identity binding (token unique per resource only); 2 no reset/ABA path (format/reuse/rebuild/repair/rollback must change identity in the comparison); 3 wrap policy (above); 4 grant-before-use ordering (failed-CAS speculative epoch must never escape into mirrors/manifests/trailers); 5 revocation/fencing ordering; 6 manifest publication durable BEFORE stamped records can require foreign replay (else false refusal); 7 historical-record lifetime (above, THE blocker); 8 torn/malformed trailer → fail-closed; 9 zero rejected at grant/stamp/publish/mirror-install, not just recovery; 10 relog/copied-buffer paths carry the ORIGINating write's token; 11 manifest selection authenticity (victim/resource/UUID/slot-gen/manifest-gen) before equality has value; 12 no consumer may use token-change as event notification (it's not a grant counter after this fix).

## Implementation queue (this session)
1. Helper rewrite + 5 call sites + remove `_orig`. 2. P274-GEP-PRESERVE + P274-GEP-CONT-ZERO probes (unconditional; rare by construction). 3. caw_inject_gep_wrap knob in mint arm. 4. caw_verify PW subtest (needs sacrificial device — check caw_verify device requirements; NOT the live cluster LUN). 5. Wrap test on rig (fresh file resource). 6. Board. 7. Ledger: #15 rewrite (mark sess108 steps DONE), #1 add historical-lifetime blocker + Q6 list cross-ref.
