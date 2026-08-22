---
name: ccloop-c7ee71c6-sess357-cascade-ledgered-gate-recon
description: sess357: fleet re-prepped 0.13.4; cascade ruling banked; 2 new ledger entries (-356 grant-freeze closure, -356 umount dirty-withdraw); gate build rec…
metadata:
  type: project
---

# sess357 — cascade dispositions ledgered, gate-build recon

1. Fleet re-prepped clean after sess356 cascade: 32/32 mounted 0.13.4
   sv 58DCECD6554D8C9F8FD68E6 (265s, converged).

2. RULE-5 ruling on the sess356 race-5 cascade banked as
   ccloop-c7ee71c6-sess357-GPT-ruling-cascade-dispositions-and-gate-order.
   Headlines: build FR preflight/verdict-cache/knob NOW at default 0; F2
   domain-mode (explicit coherence-only knob) binds the FR knob too; the
   out-of-closure grant freeze and the umount dirty-withdraw are BOTH
   separate ledger defects; grant policy = conservative closure + force-
   revoke outside it + DLM fail-fast quarantine error.

3. Ledger now 97 total / 44 open: ADDED
   D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 (blocks negative-path
   108-campaign acceptance) and D-UMOUNT-QUARANTINE-TIMEOUT-DIRTY-WITHDRAW-356.
   Updated #1 next (ruling ordering) and #92/-526 next (race-5 evidence).

4. Gate-build recon (verified in source this session):
   - mxfs_shadow_eval_token (xfs_log_recover.c ~2607) returns true only at
     the enforceable terminal — it is the ruling's shared evaluator.
     Admission predicate == existing txn_all_apply rollup in
     mxfs_report_replay_authority (~2995): n_buf>0 && n_wapply==n_buf &&
     !nonbuf_taint. Class enum note: AG=1, SB=2, INODE=3 — sess356's
     "class=1 + class=3" txns were AG+INODE, all enforceable.
   - Decision site xlog_recover_items_pass2 ~3104-3222; per-item P223 skip
     ~3276 needs bypass for admitted txns.
   - ALREADY IN TREE: mxfs_target_cache_protected (F2 domain knob,
     xfs_mxfs_dlm.c ~40620), replay_gate_enforce per-class bitmask with
     fail-closed setter gated on MXFS_RELGATE_F1/F3/F4_READY consts
     (~40607, all still 0 — steps 4/5/6 code landed 0.11.490/.511 but
     READY flips need rig verification), release_proof_enforce=1 (~40735,
     0444 load-time), m_mxfs_proto_admitted (gen>=4 predicate).
   - Open design decision for next session: reuse replay_gate_enforce
     bits (setter already encodes F1-F4/F2 fail-closed logic) vs separate
     foreign_replay_token_enforce knob per the sess175 Q5 wording. State
     the choice, then plumb verdict + admit arm + desc-failure abort +
     P227-FR-ENFORCE-ADMIT telemetry; GPT diff review BEFORE build.
