---
name: ccloop-c7ee71c6-sess361-closure-purge-landed-0142
description: sess361: #3 grant-freeze selective closure purge LANDED+BUILT 0.14.2 sv 3449377248F4455DC4D9A85 — NOT reviewed/deployed; P299-CLOSURE-* markers
metadata:
  type: project
---

# sess361 — D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 fix landed

0.14.2 sv 3449377248F4455DC4D9A85, builds clean. NOT GPT-reviewed, NOT
deployed, NOT rig-verified.

## Shape (sess357 ruling)
- `mxfs_disklock_recovery_purge_out_of_closure` (disklock.c, after
  publish_refusal): gate = QUARANTINED + valid TERMINAL_REFUSED outcome +
  AG_MASK domain + recov_auth_holds (auth REQUIRED, NULL refused). Scans
  65536 lock records under purge_lock/per-I/O ctx->lock; ACTIVE records
  owned by d->victim_node are classified via callback; >0 = out-of-closure
  → exact-image CAS zero (purge_cas_zero, 4 retries, re-read re-classifies);
  0 = frozen. 2s amortized gate revalidation incl. victim/ag_mask identity
  (-ESTALE if moved). NEVER touches the HB sector. Returns 0 on complete
  scan even with I/O fails (safe direction: extra frozen only).
- v5 wrapper checks recov_auth_mask bit + volume shim (foreign volume →
  frozen). xfs classifier: AG→ag_number, INODE/ICLUSTER→XFS_INO_TO_AGNO,
  JOURNAL/SUPER/EXTENT/unknown/agno≥64/≥agcount → frozen (SUPER frozen is
  REQUIRED — refused slice's SB-counter obligations, sbreason=2).
- Call site: mxfs_freplay_publish_refusal prc==0 arm, after
  import_verdict+set_bit, BEFORE recovery_release, gated on
  ocanon.domain_kind==AG_MASK && ag_mask!=0. Covers reap + mount barrier.

## Markers
P299-CLOSURE-GATE / -REFROZE / -WRFAIL / -CONTENDED / -PURGE (summary:
slot victim ag_mask purged kept rd_fail wr_fail nonatomic) / -NOAUTH (v5).

## Gaps for the RULE-5 review
- Publisher crash between publish and purge → out-of-closure grants frozen
  forever (acquire refuses QUARANTINED; no re-purge path). -EPERM conflict
  loser cannot purge (no auth).
- disklock.c:7316 frame-size warning is pre-existing
  (mxfs_disklock_confirm_dead_mask).

## Next
RULE-5 diff review → fix findings → make clean+modules+tools → deploy
32/caw → sess360 dirty-kill repro with 4 assertions (see handoff.md).
Fleet still runs 0.14.1 BDEB75D40B5BE7C21C82EF6.
