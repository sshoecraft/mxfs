---
name: ccloop-c7ee71c6-sess356-race5-mixed-fail-refusal-cascade
description: sess356: races 6/7 verified 2/2 all variants; race-5 mixed run FAIL — dirty-kill replay REFUSED (no gate, #1) → grants frozen → 4 clean umounts -110…
metadata:
  type: project
---

# sess356 — race 6/7 closure verification + race-5 mixed run cascade

## Races 6/7: verification COMPLETE on 0.13.4 (sv 58DCECD6554D8C9F8FD68E6)
- blind CYCLES=2 run 2: PASS (seq +2, chain=12, one lineage retire, 0 deaths)
- suspend CYCLES=1 run 2: PASS (window 2s, chain=13)
- Totals: blind C1 2/2, blind C2 2/2, suspend 2/2.

## Race 5 mixed run (tests/clean_depart_mixed_death.sh, NEW) — FAIL
Victim test30 (slot 27) dirty-killed under metadata load (append+touch loop
in own dir under /mnt/shared); clean umounts test26-29 (slots 18/6/14/23)
launched concurrently. Timeline (2026-08-15 18:24-18:33Z, T0=18:24:43Z):

1. t+62s: death declared, P238-FENCE-DONE, P236-RECOV-CLAIMED, P238-RECOV-LEASE
   — all correct. Replay started.
2. Replay REFUSED both txns: P227-FR-ATOMIC-SKIP sbreason=2 (=MXFS_SBCLEAN_CLASS
   — txn has class=1 + class=3 v3-tokened images, so #94's SB clean-skip
   correctly didn't apply; the LEGACY BLANKET atomic-skip refused). Shadow:
   P273-SHADOW-EVAL WOULD_APPLY=10 ENFORCEABLE_WOULD_APPLY=10 — tokens all
   valid. => the missing #1 enforcement gate is the sole reason.
   P241-RECOV-TERMINAL reason=1 ag_mask=0x4; AG2 quarantined CLUSTER-WIDE
   (P240-QUAR-IMPORT on all peers). #90 containment worked: no suicide.
3. Victim-held grants stay frozen forever after refusal. The 4 umounts wedged
   on root-ino=128 EX ~5min → DLM -110 (ETIMEDOUT) → "DLM inode lock
   unrecoverable ... shutting down" → P-WITHDRAW → P163-WITHDRAW-STAMP
   (voluntary death). ZERO P163-CLEAN-DEPART fleet-wide (release never
   written — NOT an EMPTY-arm miss). Peers declared the 4 dead 62s after
   withdraw (correct). Their slices replayed fine (P163-RECOVERED x4,
   18:32:20-53).
4. End state: survivors alive but root-ino grant livelocked (endless
   P7B-BASTNOTIFY ino=128 storm; test1 wedged in root-dir create).

## Conclusions
- #1 (D-FOREIGN-REPLAY-UNGATED-IMAGES) is now the proven blocker of ANY
  non-snlocal dirty-death recovery: sess348's race-2 pass was almost
  certainly via P227-SNLOCAL-ACCEPT; a victim sharing dirs with live peers
  refuses => quarantine => held-grant freeze => cluster degradation.
- Race-5 rerun requires #1's gate landed first. #92 disposition blocked.
- Possible new ledger arm (consult GPT): refusal freezes victim-held grants
  OUTSIDE the quarantined domain (root ino in AG0 vs quarantine AG2),
  converting scoped containment into effective cluster-wide root-dir outage
  + forced withdraw of any node needing that lock >300s.
- Test-script lesson: over ssh, `A && nohup loop & echo` parses as
  `(A && loop) & echo` — the loop never detaches and holds the ssh channel
  open. Use `A || exit 1; setsid nohup loop </dev/null >/dev/null 2>&1 &`.

## Rig
DEGRADED: AG2 quarantine durable, test30 destroyed, test26-29 withdrawn,
root-ino BAST storm. MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster before
anything.
