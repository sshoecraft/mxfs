---
name: AAA-ccloop7251-sess5-END-release-path-rearchitecture
description: sess5: publish deadlock killed (bounded batch + eager-demote + Wave A); drc+cc@8 green; orphan-proceed 250ms tunes fairness front; GPT consult landed
metadata:
  type: project
tags: [ccloop-72513a13, sess5, dlm, bast, release-path, publish]
---

# sess5 (ccloop 72513a13) — bast/release-path re-architecture

Build lineage AB52387F → 2D16C7289B814113AC40EEE (0.11.17). All changes in
xfs/xfs_mxfs_dlm.c + xfs_mount.h + xfs_inode.h + pal/linux/xfs_super.c +
dlm/dlm_caw.c. state.md has the full per-build ledger.

## Landed and validated
1. **make_durable reverted to passive settle** (sess4's active-iflush caused
   cross-node D-states). srcversion after revert == AB52387F exactly.
2. **Bounded publish batch** (5s wait_for_completion_timeout, self-freeing
   workers, m_mxfs_pubdrain_active teardown guard): broke the measured
   cross-node bast-worker cycle (publish drain iclus claim remote-waiting
   470s while its own AG release work sat queued behind it).
3. **Eager-demote publish**: routed children run their OWN bast_process at
   publish (platter authoritative before dirent exposure) instead of claiming
   the contended cluster. Fixes pop-then-fail claim hole (cwr exp="" class).
   Live-holder abort → claim fallback (old primitive, safe post-2) →
   relist+seen-guard (fixes 146s soft-lockup re-pop spin).
4. **Wave A** in publish_unpublished: async fdatawrite all in-scope routed
   children + ONE log force before the batch → per-child pipeline 5-9ms →
   <1ms (P138 sa 1423→4us, sc 3966→4us, sd 2600→650us). drc 116/120 PASS.
5. **caw_unlock_backoff default 1**: measured orphan bit (all nodes EXIT=full
   yet bit stuck; unlock CAS lost 100 tight retries to waiter churn).
6. **caw_orphan_reclaim default 1 + gate v3** (never override live demoter;
   dwork idle; 10s age) + **demoter forensics** (MXFS_SET_DEMOTER stamps
   pid/comm/line/ns; P126 prints them — instantly disproved two leak
   theories: dem_line=14552 = live slow DWORK demotes).
7. **P15-ORPH-PROCEED (CAW)**: idle orphan-live entry (zero holders, gen
   unmoved) proceeds to the ANCHORED unlock after the resource-scoped orphan
   clock shows ≥250ms persistence — replaces the per-handoff 3s starve-force
   tax (cc convoy root). The no-qualifier version STOLE undiscovered wins
   (winner poll ≤25ms vs µs nudge-bast) → fairness starved 10/50 rounds; the
   250ms version fixed cc (13-14s green ×2 boards) but fairness then
   NO_TERMINAL at 30s — ⚠ OPEN FRONT.

## GPT RULE-5 consult (full text in sess5 transcript, ~search P15-REL-ABORT)
Diagnosis confirmed: orph=1 abort is CIRCULAR (live token + no users + gen
unmoved = exactly "proceed to unlock"); slot-wide gen is wrong unlock anchor
(waiter churn ≠ re-grant). Structural recs not yet implemented: (B) gate
local reacquire while release in flight via true local grant cookie (bump at
grant-publication, not prebump); (C) rebase-loop unlock (clear own bits from
FRESH image, retry to success, local-cookie cancel); (D) one-shot waiter
registration (no polling churn on the slot).

## ⚠ NEXT: dlm_fairness@8 NO_TERMINAL (30s budget)
The 8-node create→mv→rm churn on ONE shared cluster crawls. Bracketing A/B
evidence: 0ms proceed = win-stealing starvation (FAIL=3, 10-38/50 rounds);
250ms = too slow overall (NO_TERMINAL). Open question: why does ~every
fairness handoff enter bast_process with mode already NL (the strand shape)?
Suspect: the nudge-driven bast lands BEFORE the winner's ≤25ms poll discovery
on nearly every handoff (bast_pending set at entry-NL, abort, 25ms dwork
re-arm serialization). RULE-4 next: count P15-REL-ABORT orph=1 with age<250ms
per fairness run + measure winner discovery latency (win-CAS→mode=EX gap).
Candidate fixes: (a) on entry-NL abort, NUDGE the local poller (wake the
in-flight acquire so discovery is µs — kill the strand at birth); (b) GPT
(B)+(C) proper. Also fairness knob=0 corruption note from sess4 is still
ex_close_release_ms=0-default fixed.

## Operational lessons (hard-won this session)
- Boards MUST run from fresh MXFS_FORCE_PREP; churned clusters degrade fio
  to 48-59% and cascade pre-asserts. PASS-run logs don't archive.
- blockers= in P-WAIT-EXTEND / hex in P-ACQ-STUCK are HEX BITMAPS (bit i =
  i-th join slot), not counts.
- dmesg survives module reload — cross-check probe counts vs uptime/etimes
  (two false "zombie/leak" alarms).
- P126's work_busy checks i_dlm_bast_work only — blind to dwork/trans-defer
  demotes (their comm shows in dem_comm now).
- 8-board on 2D16C728: rows 1-9 + 20 green (fio 141%, cc 13s); 10 fairness
  active front; 11-19 pre-assert cascade from fairness kill (they pass when
  run after a healthy row-10).
