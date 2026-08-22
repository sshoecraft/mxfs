---
name: ccloop-c7ee71c6-sess334-d513-6-stopships-landed-0.12.3
description: sess334: ALL 6 sess333 stop-ships + C cleanup LANDED, 0.12.3 sv 9A89E570C5BFE0C1276D062 builds clean — NOT deployed, NOT rig-verified; next = Q7 rig…
metadata:
  type: project
---

# sess334 — sess333 stop-ship fix set LANDED, 0.12.3 built

Tree: VERSION 0.12.3, mxfs.ko srcversion `9A89E570C5BFE0C1276D062`, make clean && make modules clean (no warnings in touched files). NOT deployed to the fleet; fleet is DOWN and needs re-prep.

## What landed (work order: ccmemory ccloop-c7ee71c6-sess333-GPT-ruling-d513-0.12.2-review-6-stopships)

All in `xfs/xfs_mxfs_dlm.c` except item 4 (`dlm/disklock.c`):

1. **A** — `mxfs_barrier_classify_slot` API changed: returns 1 + `bool *fswide` out-param (never -EIO). All barrier FSWIDE exits now: `terminal |= bit` FIRST, then `goto abort_fswide` — a common label before the function end that defers `drained & ~replayed & ~terminal` and returns -EIO. Applied at: poll-phase classify, round-loop classify, -EPERM reclassify, publish-terminal-fswide, and both new unconditional gates.
2. **B** — new `mxfs_freplay_import_verdict(mp, slot, oc, src)` (just after `mxfs_quarantine_import_oc`): validates outcome==TERMINAL_REFUSED, reason ∈ {POLICY_REFUSED_COMPLETE, PHYSICALLY_TORN, LEGACY_INTENT_QUARANTINE}, domain ∈ {FSWIDE, AG_MASK}, AG_MASK ⇒ nonzero ag_mask, `oc->victim_slot == slot`; any failure logs the ACTUAL record and imports NULL (fail-closed FSWIDE). Used by classifier case-0 ("classify"), backfill-return ("legacy-backfill"), publish-conflict readback case-0 ("publish-conflict").
3. **D** — reap's publish/conflict state machine factored into `mxfs_freplay_publish_refusal(mp, slot, fv, rrc)` (after classify_terminal; returns 1 terminal / 0 transient, releases lease + latches internally per the original reap semantics). Reap caller now 12 lines (re-arm tag "freplay-publish"). Barrier replay site passes `&fv` (was NULL), invalidates cached views BEFORE publish, on terminal sets terminal-bit then AG admits / FSWIDE → abort_fswide; transient leaves the slot in the cut (poll bound → -EBUSY unchanged).
4. **backfill identity** — `mxfs_disklock_recovery_backfill_legacy`: `d->victim_slot != (uint16_t)slot → -EPROTO` (P241-RECOV-BACKFILL-IDENT) after desc parse, before QUARANTINED check. Comment documents why nothing further is checkable (legacy = flag + all-zero outcome; desc CRC binds sector identity which travels with a byte copy).
5. **-EPROTO fail-closed** — classifier -ENODATA arm: `brc == -EBADMSG || brc == -EPROTO` → import NULL FSWIDE (was -EBADMSG only; -EPROTO retried forever).
6. **FSWIDE gates** — unconditional `m_mxfs_quar_fswide` check at barrier START (right after NULL checks) and at the successful-admission boundary (before the completion notice/`return 0`); both `goto abort_fswide`.
+ **C cleanup** — round-loop -EPERM reclassify -EAGAIN → `quarblocked |= bit`.
+ stale `xfs_log.h` digest_valid contract comment fixed (said refusal must not publish without digest; sess327 ruling says it publishes with DIGEST_VALID clear).

## Verification state
Code-landed only. NOT yet: ledger #90 entry update, deploy, GPT's 7 pre-rig unit checks (in sess333 memory), Q7 rig verification plan (sess325 memory) + sess328 Q3 residue thresholds. Rig needs `./run.sh 32 caw prep_cluster` first (mkfs; aged fs lost). fence-class board tests stay SUSPENDED.

## Next session
1. Update ledger #90 next-step (./defects.sh flow, hand-edit OPEN_DEFECTS.json entry).
2. Consider a RULE-5 diff review of THIS landing (sess325/sess333 precedent: post-landing review caught real holes both times) before rig time.
3. Then the Q7 rig verification plan.
