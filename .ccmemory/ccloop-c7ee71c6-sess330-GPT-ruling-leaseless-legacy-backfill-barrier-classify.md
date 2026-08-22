---
name: ccloop-c7ee71c6-sess330-GPT-ruling-leaseless-legacy-backfill-barrier-classify
description: sess330 RULE-5 ruling D-513: leaseless backfill_legacy_intent API (auth impossible — claim/cert refuses QUARANTINED); classify-before-acquire both en…
metadata:
  type: project
tags: [d-513, rule-5, recovery, quarantine, mount-barrier, disklock]
---

# sess330 — D-513 follow-up ruling: leaseless legacy backfill + barrier classification

## Disproven sess329 premise (code-verified sess330)
- `recovery_claim` calls `mxfs_recov_cert_proves_exclusion` (disklock.c:4133) BEFORE its owner-reacquire check; the evaluator refuses ANY `F_QUARANTINED` descriptor (4210 → -EPERM). `recovery_replay_authorized` (reacquire) uses the same evaluator. **No node can ever acquire/hold the recovery lease on a quarantined descriptor.** So sess329's pre-replay verdict check (after acquire success) and backfill helper are unreachable for the legacy case; `publish_refusal`'s `recov_auth_holds` gate would -EBUSY anyway (legacy owner = dead old-build node).
- **Mount ordering hole**: admission barrier runs INSIDE `xfs_mountfs` (xfs_mount.c:1089); quarantine-cb registration + `recovery_scan_outcomes` run in `mxfs_dlm_cache_init` AFTER xfs_mountfs (xfs_super.c:3239). `get_recovery_pending_slots` (disklock.c:6328) includes quarantined descs (stage preserved < GRANTS_RELEASED, no outcome check). Barrier can't acquire them → todo never clears → **every mount of every node aborts -EBUSY forever once any slot is quarantined**. Quar map lock is init'd in fill_super:692, `mxfs_quarantine_import_oc` callable at barrier time. Enforcement = DLM acquire gates (ilock entry 28413, post-poll 30696, central 30810, AG 36873) → FSWIDE-admitted mount would die late in log_mount_finish.

## GPT ruling (full text in transcript, sess330)
- **Q1 = (b) leaseless backfill**, NOT a TERMINALIZE lease mode (would rewrite terminal owner fields / weaken cert meaning). Dedicated tightly-scoped API (`backfill_legacy_intent()`), NOT a general auth==NULL form of publish_refusal. Predicate: reason exactly LEGACY_INTENT, FSWIDE only, desc identity+CRC valid, QUARANTINED set, outcome region exactly all-zero; preserve owner/epoch/gen/term/stage/flags; deterministic synthesized bytes; full-record CAS, same durability as normal publish. CAS loss → reread: valid outcome → import; still eligible → retry; nonzero invalid → fail closed, never overwrite.
- **Q2**: barrier classifies each pending slot BEFORE acquire from a stable desc+outcome snapshot: valid terminal → import + mark terminally-disposed for admission (grants stay frozen, stage untouched); legacy all-zero → authless backfill then import; malformed/corrupt → local fail-closed FSWIDE import; live non-quarantined → normal acquire+replay. **FSWIDE import → fail the mount IMMEDIATELY** (explicit "victim domain quarantined; operator repair + remount required", -EIO), before log_mount_finish. AG-mask → admit, serve unquarantined AGs; if mount completion needs a quarantined AG it fails EIO, never bypasses. Backfill persistent-failure at mount → fail closed with explicit terminalization error, not the misleading -EBUSY timeout.
- **Q3**: reap loop: classify BEFORE claim; only if nonterminal attempt ordinary claim; on claim -EPERM RECLASSIFY once (quarantine may have landed between read and claim); if still nonterminal keep existing -EPERM handling. Inconsistent combos (valid outcome w/o terminal desc state, publish -EPERM then readback -ENODATA, unstable snapshots) = fail-closed/retry-terminalization, never backfill-with-lease, never replay.
- **Q4**: keep terminal slots visible at sweep source; ONE shared classifier/terminalizer used by barrier + reap + registration scan; "resolved" means classified-terminal-for-this-admission, retained in quarantine accounting; every later mount imports again.
- Invariants: quarantine terminal+never replayable; only exact all-zero legacy outcome fillable authlessly; nonzero bytes never overwritten; first durable verdict wins; terminal owner/stage/identity unchanged; replay still needs ordinary lease+cert; no timeout proofs.

## Implementation plan (sess330, in progress)
1. disklock.c/h: new `mxfs_disklock_recovery_backfill_legacy(ctx, slot, oc_out)` sharing a static outcome-fill helper with publish_refusal; REVERT publish_refusal's sess329 LEGACY acceptance (back to lease-only, -EINVAL for LEGACY reason). Keep reason code + P241-RECOV-BACKFILL probe name.
2. v5_mount.c/h wrapper for backfill.
3. xfs_mxfs_dlm.c: shared classifier `mxfs_freplay_classify_terminal(mp, slot)` (read_outcome semantics: 0=valid, -EBADMSG/-EPROTO=unreadable-on-quarantined, -ENODATA=legacy quarantine no outcome, -ENOENT/-EAGAIN=nothing terminal — see disklock.c:3799-3847). Reap loop: classify before acquire (move sess329 post-acquire block), reclassify on acquire -EPERM; publish-race -ENODATA arm → re-arm retry, NOT backfill. Barrier loop (~47603): classify per slot before acquire, terminal → resolved-mask + import; after clean cut, if m_mxfs_quar_fswide → xfs_alert + return -EIO fail-fast; distinct abort message when remaining todo is quarantine-blocked.
4. Fix wrong sess329 comment ("recovery_claim() does not refuse a QUARANTINED descriptor" — it does).
5. Then: knob scope (sess328 Q2), make clean build, VERSION 0.12.1→0.12.2, ledger #90 update, rig per Q7 plan.
