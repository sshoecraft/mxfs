<!-- sess404 RULE-5 ruling: production defaults = enforce=1, release_proof=1, tcp=0; REFUSE clustered RW mount if fua_disable=1 && !tcp (option A); flip g… -->
# sess404 GPT ruling — foreign-replay enforcement production defaults

## Facts given
enforce=0 (today's default) = blanket refusal: victim slices POLICY-REFUSED, AGs quarantined,
survivor EIO (kill1 test8 1008 EIO), victim's committed metadata lost. enforce=1 setter fails
closed unless release_proof_enforce=1 AND NOT(fua_disable=1 && !target_cache_protected).
fua_disable=1 default on the SCST rig (F2 domain). Board runs with enforce=0 today; kill
harness arms knobs explicitly and passes (5 laps on 0.24.2).

## Decision: OPTION A
- Defaults: foreign_replay_token_enforce=1, release_proof_enforce=1, target_cache_protected=0,
  never infer tcp from fua_disable.
- If fua_disable=1 && target_cache_protected=0: REFUSE the clustered RW mount, explicit message
  ("configure a FUA/flush-honouring target with fua_disable=0, or declare
  target_cache_protected=1"). No silent fallback to blanket refusal (B = deferred failure).
  C (leave opt-in) and D (default tcp=1) rejected.
- Reject unsafe runtime param transitions on a mounted cluster (or require unmount/restart).

## Gate before flipping the default (stop-ship items)
1. Fence-time manifest SNAPSHOT for the APPLY class — a live read for an APPLY authority
   decision is a correctness hazard (stop-ship), must be an immutable snapshot tied to the fence/tenure.
2. ICLUS clean-release markers — implement+validate, or explicitly refuse ICLUS configurations;
   never ship "fail closed later" as recovery behaviour.
3. Fleet-wide board with the production-intended defaults (no harness-only overrides) asserting:
   every eligible foreign slice APPLY or valid REDUNDANT_CLEAN; zero unexpected POLICY-REFUSED;
   zero quarantine; zero recovery-attributable survivor EIO; victim committed metadata present;
   post-run metadata checks clean.
4. Targeted crash coverage (single-owner + shared-AG; around commit / clean release / snapshot /
   fencing / replay; replayer death+retry; ownership changes) — coverage over N identical laps.
5. F2 config matrix: (1,0)->mount rejected; (0,unset)->allowed only on verified FUA target;
   (1,1)->allowed with prominent durability-domain declaration; unsafe setter transitions rejected.
6. Fence snapshot race tests (fault injection between snapshot / token check / home writes / replay).
7. Mixed-version: prohibit mixed-version clustered mounts for this transition unless negotiated+tested.
Key criterion: a node death must not discard acknowledged committed metadata or quarantine
otherwise-healthy AGs.
