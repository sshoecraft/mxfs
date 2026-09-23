<!-- sess456 RULE-5 review -->
# Review #5 of 0.61.1 (2026-09-02 ~01:58Z) — NO-GO

Evidence supplied: chain 78 (6/6 settle arms, 12/12 laps, board 26 PASS + known crash_consistency + policy row), chain 77, docs G1/G2/G3 + D4 audit statement + the 10 STOP-SHIP dispositions.

## Verdict: NO-GO. Conditions (review-#3 mapping): 4 (fresh bracket, no table->EMPTY) MET; 6 (proof token image/invalidation/single-use) MET; 1,2,3,5,7,9 PARTIAL; 8 (I/O gate fails closed on ANY accounting violation) UNMET.
D-377 PARTIAL/NO-GO (the untokened provenance hole); D-0356 PARTIAL/NO-GO (crash-cut state not proven from arm names).

## STOP-SHIP (critical): `untokened` is observable but not fail-closed
A terminal completion with neither a token nor a pending rejection = provenance unknown. mxfs_departure_quiesced() must reject on untokened != 0 (sampled under the acct lock, printed in QUIESCED/NOT-QUIESCED). Preferred: any unclassified untokened terminal completion on a clustered mount marks the account CORRUPT. Alternative: an explicit audited "no-I/O software completion" class separate from untokened, with every remaining unclassified event corrupt. Evidence to close: inject one unclassified untokened completion -> P304-IOCNT-* corruption report -> P304-RETIRE-NOT-QUIESCED -> no clean release/EMPTY, no unregister removing the fence target, dirty/key-retained; plus a call-site audit of intentionally tokenless software completions.

## High: G3 branch coverage — deterministic arms required
1 post-freeze rejection (real submit_ex after FROZEN: after_freeze+rejected_pending increment; delay its wq completion; no release while pending; discount before any carried-token retire). 2 retry carry (transient write error + resubmit: exactly one token across both attempts; freeze between attempts; rejected retry retires the carried token exactly once). 3 orphan (xfs_buf_free with a token, and separately with rejected_pending: corrupt, retained reference, no UAF, no release). 4 overflow/underflow (255 boundary, forced invalid decrement: reject/corrupt, no wrap, no clean release). 5 post-drain teardown submission (inject during freesb / wq destruction / device shutdown: the FINAL assertion, not the drain, prevents release).

## High: release/unregister crash invariant not demonstrated precisely
Invariant: from the first op that relinquishes the active slot until fresh proof the PR key is absent, durable shared state must still identify that key as a fence target. Needs a state table per cut (before release CAS; CAS done/flush not; flush done/before unregister; unregister failed; unregister ok/before re-stamp; final EMPTY; PR capability lost) with decoded sector image, key, state, gen/image identity, READ KEYS, peer action, flush result, admission afterwards. "pr_restamp crash PASS" is not enough. Decisive question: does the release CAS image still NAME THE KEY (RETIRE_PENDING(key)) — if yes the hazard is closed; if it writes an anonymous/empty state it is not.

## Other conditions
- Retire-worker hang/quarantine arm (WORKER-STUCK=0 is not a test of the branch): 5 s bound, whole-DLM-context quarantine, no release stamp, key retained, host admission refusal, eventual reap.
- Direct 0.61.1 evidence for G1 admission refusal matrix (unregistered key, override w/o exclusive, override+exclusive allowed, TCP refusal, reservation_key map refusal; no clustered sb active on refusal) and runtime CAW-loss fail-closed per writer class (byte-identical sector before/after, no plain write, dirty/key-retained).
- Preferably a deterministic same-host PR OUT vs settlement interleaving (pause after proof acquisition while a local PR OUT runs, both orderings: exclusion or proof invalidation, no deadlock).
- Uncapped drain: NOT a safety blocker (do not restore a capped assume-drained path); operational additions later (oldest-token age in stall lines, health state, admin fence/reset; whole-graph quarantine only if designed and tested).
- Ordering (Q5) sound subject to the two invariants: every relevant I/O tokenized or fail-closed corrupt; release CAS leaves a durable key-bearing target until unregister is proven. Workqueue destruction must synchronously discharge pending rejected completions.
