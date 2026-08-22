---
name: ccloop-c7ee71c6-sess358-fr-token-enforce-landed-0140
description: sess358: #1 FR token-enforcement machinery LANDED+BUILT 0.14.0 sv 83F8D9B46A01F8AA2AE5911 (separate knob, default 0) — NOT GPT-reviewed, NOT deployed
metadata:
  type: project
---

# sess358 — #1 enforcement machinery landed (0.14.0)

Per the sess357 ruling (ccloop-c7ee71c6-sess357-GPT-ruling-cascade-dispositions-and-gate-order):

## Design decision
SEPARATE `foreign_replay_token_enforce` knob (xfs_mxfs_dlm.c ~40727), NOT reuse of
`replay_gate_enforce` bits: that setter fails closed on F1/F3/F4 READY consts (live
release-certificate-gate prerequisites, all 0), which would make the ruled knob=1 rig
campaign unreachable; the ruling names the separate knob + its own predicate set.
Fail-closed setter: refuses arming when (fua_disable && !target_cache_protected) [F2]
or !release_proof_enforce. Per-mount predicates at use time.

## Mechanism (xfs_log_recover.c / xfs_log.c / headers)
- `se->enforce_cfg` snapshotted ONCE at evaluator creation → one config per slice
  (no half-enforced replay); printed in P273-SHADOW-CAP.
- `mxfs_report_replay_authority` returns bool = this-txn all_apply verdict
  (n_buf && wapply==n_buf && !nonbuf_taint; false when evaluator absent — fail closed).
- `mxfs_fr_enforcement_active(log)`: foreign && se->enforce_cfg && se->capable &&
  proto_admitted.
- ADMIT arm in xlog_recover_items_pass2 (between snlocal-accept and sbclean-skip):
  P227-FR-ENFORCE-ADMIT notice, `se->txn_enforce_admitted` counter (in P273 line),
  sets `mxfs_txn_admitted`; per-item P223 skip gains `!mxfs_txn_admitted`. NOT a
  refusal — no untagged_skips, no quarantine domain, no torn arming; fully-admitted
  replay publishes clean, ANY refusal still fails the whole replay (sess233 semantics).
  XFS_LI_INODE items keep di_changecount gate (authority AND changecount per ruling).
- `mxfs_fr_enforce_preflight(log)` (exported, proto in xfs_log_priv.h), called in
  mxfs_xlog_recover_foreign_slice BEFORE xlog_recover: creates the shared evaluator;
  when enforcement configured and descriptor !capable → ABORT elected recovery with
  plain -EIO/-ENOMEM (reason NONE, no terminal verdict, retryable). Verified
  xlog_recover_cancel is opstate-gated no-op on this path.

## State
Compiles clean: 0.14.0 sv 83F8D9B46A01F8AA2AE5911. NOT GPT-reviewed (required before
deploy), NOT deployed (fleet still 0.13.4). Open review questions: inject one-shot
consumed before preflight (abort eats an armed injection); admit-arm placement.
Deploy needs make clean first (multi-file .c+.h change).
