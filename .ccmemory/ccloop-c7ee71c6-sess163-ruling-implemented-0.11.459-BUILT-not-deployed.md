---
name: ccloop-c7ee71c6-sess163-ruling-implemented-0.11.459-BUILT-not-deployed
description: sess163: RULE-5 ruling on sess162 wiring (A refuted→fixed, B/C ratified, D=4-before-5) implemented, 0.11.459 sv F6077665 BUILT. Deploy+measure NEXT.
metadata:
  type: project
tags: [mxfs, sess163, foreign-replay, authority, begin-release, P247, RULE-5]
---

# sess163 — consult done, ruling implemented, 0.11.459 BUILT (NOT deployed)

Build: **0.11.459 sv F6077665E740E6ED1A6B472**, builds clean. Ledger unchanged: 28 open / 17 critical.

## The RULE-5 ruling on the sess162 begin_release wiring (full text in sess163 transcript)

- **(A) REFUTED — phantom arms must invalidate AT DETECTION**, not ride the backstop: retaining a proving cert after wire-loss detection permits stale authority tagging during any intervening logging/lock-drop, and re-acquire must never start while the old tenure appears live. Backstop stays reserved for uninstrumented paths. Post-phantom reacquire must mint fresh tenure (gen++ satisfies).
- **(B) RATIFIED** — evict placement after P237/durability arms is correct; the real invariant is "before relinquishment becomes PEER-EFFECTIVE", not "eviction begin" (peer-visible activity under a held grant is legitimate; a successful P237 CAS is itself a proving act). Failed P237 needs no phantom handling (unpublished = no wire grant ever believed; UNPUBLISHED_EX fails closed at the gate).
- **(C) RATIFIED** — retained wire-PR with no in-core cert is sound (PR is cache state, never image authority), but cert!=NONE on the retain path is a BUG to surface, plus lifecycle requirements (noino BAST unlock exists; recreation must adopt wire state — both already true).
- **(D) STEP 4 BEFORE ACTIVE STEP 5** — without the descriptor/freeze, purge-before-DONE makes the exact-match gate deterministically false-reject acked-undestaged updates. Shadow-mode parts of 5 (parser, evaluator, counters, prospective-decision recording, fault-injection tests with injected epoch source, capability check requiring a valid frozen descriptor before enforcement) MAY land early. Additional hazards to close in step 4/5: match full authority namespace (class+agno+epoch+victim/slice identity+recovery incarnation); epoch non-reuse proof; keep transaction-atomic rejection; tenure-release invariant (older-epoch images must be destaged-or-represented at release — comparing only the victim's FINAL slot epoch is unsafe without it); descriptor/DONE crash-resumable + serialized; DONE-before-purge with real flush/FUA ordering.

## What landed in 0.11.459 (all xfs/xfs_mxfs_dlm.c)

1. `mxfs_inode_authority_phantom_loss_locked()` (+`mxfs_auth_phantom_n`, **P247-AUTH-PHANTOM-LOSS** warn when cert was proving) called at all 3 phantom arms before their NL stores: P108-REACQUIRE, P-TCPEX-REACQ, phantom-undo (all under i_dlm_lock). Their NL stores now classify relclean.
2. Backstop chokepoint comment: NO known late-revoke population remains; any P246-AUTH-LATE-REVOKE = uninstrumented release path = wiring bug.
3. P6R-RETAIN arm: **P248-RETAIN-CERT-ANOMALY** ratelimited warn if auth_state != NONE (lockless u8, diagnostic).
4. Evict site-(f) comment reworded to the ratified invariant + failed-P237 rationale.
5. /proc authority stats "relinquish" block now prints `phantom_loss`.

## NEXT (task #3, unchanged): deploy + measure

`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` then a board lap. Assert: release_begin>0, release_clean>0, **backstop==0 strictly** (post-A-fix there is no legitimate population), phantom_loss≈0 (each hit is a real wire/cache divergence — investigate), pub_live==0, P248 absent; RULE-0 timings. Then tick ledger items 1+2 in D-FOREIGN-REPLAY next-field and proceed to step 4 (recovery descriptor + IMAGE_REPLAY_DONE + victim freeze — overlaps D-FOREIGN-SLICE-INTENTS-ABANDONED #7), with step-5 shadow parts fair game per (D).

## Housekeeping

- Memory compaction STARTED: [[compiled-inode-authority-certificate-design-arc]] folds sess95-101 (9 notes). Remaining uncompiled clusters, largest first: lreq/waiter-cancel sess111-125 (~20), fence lifecycle sess132-142 (~12, reference-type), authority-measure sess102-110 (~11), bast-dispatch sess126-131 (~7), fence/descriptor sess62-93 (~30, several subarcs). Backlog was 202.
- dlm+pal awareness doc refresh still due.
