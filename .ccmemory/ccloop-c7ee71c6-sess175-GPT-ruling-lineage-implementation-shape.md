---
name: ccloop-c7ee71c6-sess175-GPT-ruling-lineage-implementation-shape
description: sess175 ruling 2 (#1 lineage impl): A1 random-u64 lineage RATIFIED; v3 emit may precede proto-gen4 but enforcement hard-gated on admitted gen>=4; eva…
metadata:
  type: project
---

# sess175 — second RULE-5 ruling: lineage discriminator implementation shape (full text in sess175 transcript)

## Q-A: mint source = A1 RANDOM nonzero 64-bit (RATIFIED; A2 global counter REJECTED as unneeded surface)
- Equality discriminator ONLY — no <, >, age, or distance comparisons anywhere, audit tooling included.
- Mint on every fresh-image claim (empty slot OR different-resource tombstone); inherit on same-resource
  tombstone recycle (extend caw_claim_inherit_epoch); preserve in caw_tombstone_slot carry set + frozen manifest.
- Same randomness quality as mba_owner_epoch (mount incarnation); reject zero; FAIL THE CLAIM if secure
  randomness unavailable — no fallback to time/node-id/generation/weak PRNG.
- CAS retry may reuse the candidate lineage for the same logical fresh binding, but must re-evaluate whether
  the eventual insertion point became a same-resource tombstone and inherit then.

## Q-B: v3 emit flip may precede proto-gen 4; ENFORCEMENT hard-gated on cluster-admitted gen>=4
- Report-only phase: emit v3 unconditionally next build; old nodes classify MALFORMED — VERIFY (not assume)
  that MALFORMED has zero apply/skip/abort/admission consequence on every replay path before flipping.
- Enforcement knob must be non-enforcing unless the COMPLETED CLUSTER ADMISSION state (per #14
  D-MIXED-VERSION-UNGATED-REPLAY proto-gen 3->4 + blockers B1-B4) is >=4. A local binary's constant is NOT
  sufficient. Until #14 lands, enforcement impossible regardless of knob.
- Even post-gen4: v1/v2 records stay lineage-less => rejected by the enforcing decision (containment
  treatment); that fail-closed behavior is accepted.

## Q-C: evaluator/manifest changes
- Manifest read: lineage out-param from the SAME frozen 512B slot image, no second read.
- Ordering: token parse/identity -> manifest read + resource/slot validity -> LINEAGE EQUALITY ->
  hold check -> epoch comparison -> rest. Lineage BEFORE holds (a lineage mismatch makes that binding's
  hold bitmap and epoch inapplicable; holds-first would mislabel as not_held). wrong_lineage = terminal
  for lineage-bearing tokens; missing manifest stays the earlier terminal.
- v2-in-shadow: do NOT redefine the samples-1-3 series. Metrics split: legacy_would_apply (unchanged
  semantics, compatibility series) + v2_no_lineage (lineage-less candidates) + enforceable_would_apply
  (passes the FULL future gate incl. v3 lineage). A generic would_apply must not count v2 as
  enforcement-ready. Readiness report: lineage-less fraction, wrong_lineage, enforceable-v3 count,
  malformed/unknown count.

## Implementation start point (next session)
1. dlm/dlm_caw.h: add uint64_t resource_lineage to mxfs_caw_lock_slot (reserved 344->336), static assert 512.
2. dlm_caw.c: mint in fresh-image build path (find the claim-image construction near caw_claim_inherit_epoch
   call sites ~3038-3241); inherit in caw_claim_inherit_epoch; preserve in caw_tombstone_slot; plumb into
   grant result (include/mxfs/mxfs_dlm.h mxfs_grant_result + caw_grant_result_fill) + pag/inode mirrors
   (pag_mxfs_grant_epoch pattern, xfs_buf_item.c:961).
3. Token v3 (48B) in xfs/libxfs/xfs_log_format.h + producer xfs_buf_item.c:1381-1455 + size macro flip +
   parser v3 case; VERIFY MALFORMED-is-observational sweep first.
4. v5_mount.c:5378/5394 manifest reads + evaluator xfs_log_recover.c:2358+ per Q-C.
Rig: test5 killed+restarted by AB harness, NOT re-prepped — MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster
before any board. Version rev on landing: minor bump (new feature) per user convention -> 0.11.463+.
