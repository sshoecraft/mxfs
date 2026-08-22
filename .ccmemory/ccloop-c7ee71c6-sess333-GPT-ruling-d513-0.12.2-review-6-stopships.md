---
name: ccloop-c7ee71c6-sess333-GPT-ruling-d513-0.12.2-review-6-stopships
description: sess333 RULE-5 review of 0.12.2 D-513 landing: 6 STOP-SHIPS (A barrier -EIO defer, B backfill-return validation, D barrier must publish refusals, bac…
metadata:
  type: project
tags: [d-513, rule-5, stop-ship, mount-barrier, quarantine, backfill]
---

# sess333 — RULE-5 diff review of the sess331/332 D-513 landing (0.12.2 sv 0C47E91907CFA130AFB6520)

GPT reviewed the full implementation (disklock backfill_legacy + publish_refusal gate, shared classifier, reap rewiring, barrier classify/terminal masks, knob one-shot/slot/shape-4). Verdict: **do NOT run the rig**. Stop-ship on A, B, D + 3 additional blockers. C (reclassify -EAGAIN not entering quarblocked in round loop), E (shape-4 countdown counts only non-skipped applied items), F (one-shot consumed pre-shadow-alloc) ruled ACCEPTABLE.

## Stop-ships to land (sess333+)
1. **A — barrier -EIO exits skip late-death defer.** ALL barrier exits after `drained` accumulates must run `mxfs_v5_dlm_mount_defer_late_deaths(drained & ~replayed & ~terminal)` (common `abort_fswide:` label). Trap: `mxfs_barrier_classify_slot` returning -EIO means the caller never set the slot's `terminal` bit — change API to return 1 + `bool *fswide` out-param; caller sets `terminal |= bit` FIRST, then jumps to the common abort. Same ordering for an fswide refusal newly published by inline replay.
2. **B — classifier -ENODATA brc==0 arm imports ocb unvalidated.** Backfill's "first durable verdict wins" return can hand back a raced record; must validate exactly like the case-0 arm (outcome==TERMINAL_REFUSED, known reason, valid domain, nonzero AG mask) else import NULL fail-closed FSWIDE; log the ACTUAL record, not "synthesized FSWIDE". Fix = ONE shared `mxfs_freplay_import_verdict(mp, slot, oc, src)` helper used by classifier case-0, backfill-return, and the reap -EPERM-conflict readback case-0 (dedupes 3 sites). Note `mxfs_quarantine_import_oc` already fails closed on unknown domain_kind/empty mask — the gap is unknown outcome KIND with a parseable AG-scoped domain field.
3. **D — barrier replay publishes NO refusal (the target defect survives on the mount path).** Lone-survivor cold start: mount acquires lease → replay refuses → nothing published → -EBUSY → infinite restart loop, no operator-facing quarantine ever. Barrier must pass &fv and run the SAME publish/conflict/import/latch state machine as the reap path, factored into one shared helper (returns 1 terminal / 0 transient-caller-re-arms): publish under held lease → import canonical → latch → release; -EPERM → readback canonical (validated) / -ENODATA readback → release+reclassify; transient → retryable, never latched. On terminal: `terminal |= bit` (never `replayed`); AG-scope admits; FSWIDE → terminal-first then common abort. Also invalidate cached views before publishing (torn replay applied a prefix).
4. **Backfill predicate**: GPT wanted reason/scope checked against the existing descriptor — IMPOSSIBLE, desc has no such fields (verified: struct mxfs_recov_desc disklock.h:398 has stage/epochs/gen/fence cert only; legacy = QUARANTINED flag + all-zero outcome, which IS the signature; disklock.h:529 comment confirms). Implementable core: add `d->victim_slot != slot → -EPROTO` identity check in backfill (desc CRC binds fs_gen/node_id/epoch of the SECTOR, which travel with a byte-copied record — victim_slot field is the only slot binding), + comment why nothing further is checkable.
5. **-EPROTO from backfill reread must fail closed** (classifier -ENODATA arm treats only -EBADMSG as fail-closed; -EPROTO currently retries forever). Handle -EPROTO == -EBADMSG → import NULL.
6. **Unconditional FSWIDE admission gate**: check `m_mxfs_quar_fswide` at barrier START and at the successful-admission boundary (before the final `return 0`, ~line 48007), not only after a terminal classification of a todo slot. (Quarantine cb registration happens post-xfs_mountfs so no async import during barrier, but the gate is cheap belt-and-suspenders; a preexisting-FSWIDE-with-empty-todo mount must still refuse.)

Also do C's cleanup while there: round-loop reclassify -EAGAIN → `quarblocked |= bit`.

## Pre-rig unit checks GPT wants (fold into Q7 plan)
backfill rejects wrong-shape sectors byte-preserved; raced unknown-kind record → FSWIDE fail-closed; -EPROTO → immediate fail-closed; FSWIDE abort preserves unrelated late death; lone-node torn mount publishes TERMINAL_REFUSED + returns -EIO; AG-scope refusal → terminal not replayed, hb sector NOT zeroed by cohort_complete; preexisting FSWIDE + empty todo still rejects mount.

## Code geography (0.12.2)
classifier xfs_mxfs_dlm.c:46256; import_oc:46181 (fails closed already on unknown domain); reap refusal-publish block 46515-46725 (the -EPERM conflict readback 46599-46703 is the state machine to factor); barrier_classify_slot 47396; barrier loop 47571-47878 (poll phase 47626, round loop 47695, NULL-verdict replay call 47813, tail defer 47909, final notice/return 48001-48007); backfill disklock.c:3795; recov_outcome_fill 3593; recov_desc_of/outcome_of validation 386-446. Reap re-arm idiom: set_bit(MXFS_REAPF_FREPLAY)+mxfs_reap_sched.

After landing: make clean && make modules (multi-file), VERSION 0.12.2→0.12.3, ledger #90 update, THEN rig per sess325 Q7 + sess328 Q3 thresholds. Fleet is DOWN; re-prep required (./run.sh 32 caw prep_cluster).
