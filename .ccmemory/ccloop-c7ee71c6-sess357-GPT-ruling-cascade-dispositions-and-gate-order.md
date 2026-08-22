---
name: ccloop-c7ee71c6-sess357-GPT-ruling-cascade-dispositions-and-gate-order
description: sess357 RULE-5 ruling: enforcement machinery build NOW at knob=0; F2 domain knob binds FR-enforce too; grant-freeze = NEW defect (closure classify +…
metadata:
  type: project
---

# sess357 GPT ruling — race-5 cascade dispositions + gate order (full text in sess357 transcript)

Presented: sess356 mixed-run cascade (refused replay → AG2 quarantine → victim-held
root-ino grant frozen → 4 clean umounts -110 → dirty withdraw → root livelock).

## Q1 — implementation order
- Build foreign preflight + per-txn verdict cache + `foreign_replay_token_enforce` (default 0) NOW.
  One whole-txn verdict, zero side effects before preflight completes, shadow and enforce consume the
  SAME cached verdict. Inode = authority AND di_changecount; untokenized dquot/icreate reject txn;
  descriptor-read failure aborts elected recovery; adopted capable=0 keeps blanket refusal.
- **F2 domain-mode requirement BINDS foreign_replay_token_enforce too** (tokens rely on release/epoch
  durability). fua_disable=1 rig: knob=1 permitted ONLY with explicit coherence-only domain admission
  (separate knob, never inferred from fua_disable), plus proto_admitted>=4, homogeneous fleet,
  release_proof_enforce=1, cluster-coordinated setting. Coherence-only runs count only toward the
  coherence-only campaign — NOT stable-media/default-on qualification. B2-B4 + steps 7-10 still block
  general default-on.

## Q2 — frozen victim-held grants outside refused domain: SEPARATE LEDGER DEFECT
Policy = conservative (a)+(b): after fence + txn classification, build conservative CLOSURE
(resources named by refused images; inode resources conservatively associated with refused buffer
images; txn-level deps; anything ambiguous/unreadable). Then:
1. Refused/ambiguous closure → stay frozen; reject NEW waits immediately with distinct
   terminal-quarantine error; cancel existing waits same way; operator/repair clears.
2. Successfully replayed resources → normal recovery revocation/regrant after replay+flush/epoch order.
3. Provably outside closure, no outstanding recovery obligation → recovery FORCE-REVOKES dead owner's
   grant after fencing; advance/publish recovery ownership epoch before peer regrant (recovery
   revocation, NOT fabricated release certificate).
Ambiguous buffer→inode mapping ⇒ inode goes IN the closure. Dead owner alone is not a freeze reason.
This defect BLOCKS acceptance of negative-path 108-capture campaign + any default-on.

## Q3 — clean umount dirty-withdraw on frozen grant: SEPARATE DEFECT
Quarantine is not local DLM corruption. Required: (1) DLM returns distinct terminal-quarantine error
instead of 5-min wait; (2) umount acquires root/teardown grants BEFORE its irreversible commit point;
(3) on that error pre-commit: abort unmount, stay mounted degraded, report, do NOT withdraw;
(4) dirty withdraw reserved for real corruption/membership loss/post-commit failure.

## Final ordering
1. Preflight/cache/knob at 0. 2. F2 domain admission (explicit coherence-only knob). 3. Scoped
dead-grant disposition + DLM fail-fast quarantine errors. 4. Umount escalation fix. 5. knob=1 on rig
(all predicates). 6. Coherence-only capture campaign. 7. Stable-media/B2-B4 before default-on.
