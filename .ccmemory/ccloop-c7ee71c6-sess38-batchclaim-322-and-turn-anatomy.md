---
name: ccloop-c7ee71c6-sess38-batchclaim-322-and-turn-anatomy
description: sess38 part2: 322 = PR batch-claim fix (storms gone, P6H-PRCLAIMBATCH); tail root = EX rotation x turn-cost (p50 58ms = drain-dominated); grace 40->1…
metadata:
  type: project
---

# sess38 part 2 — 0.11.322 + the quantified turn economy

## Builds this session
- 319 (BC10942A): CREATEINT tag-survival A/B/C fixes + P-CI probes. Mechanism correct, net loss.
- 320 (F6A4AA3C): create_intent_ex default 0 + tests/drc_straggler_report.sh.
- 321 (D0098983): P139-TAILCENSUS (per-wait) + P139-LOCKTOTAL (whole-acquire) unconditional >800ms census.
- 322 (A5D3929F): PR-BATCH fixes — (a) BATCH-COMPLETION-ON-CLAIM: first ticket member's winning claim CAS admits all still-registered shared-class siblings (P6H-PRCLAIMBATCH, engaged 9-11/node/lap); (b) release-side P6H-PRBATCH guard relaxed !slot_has_holders -> no-exclusive-class-holders. RESULT: per-wait >800ms admission storms GONE (TAILCENSUS=0); rounds still 6-7 (wall unchanged — tail moved to EX rotation).

## RULE-4 measured turn economy (the dir_reuse wall, 32/caw)
- Wall = 2 EX rotations/round (wave1+wave2) x 32 turns x turn-cost + wrbar/presync/dc/rm (~7s fixed).
- Turn cost (inter-P6H-HANDOFF realms deltas, in-burst): p50=58ms p90=140ms. Components measured: handoff->adopt discovery p50=2ms p99=40ms (nudge chain GOOD); grace idle tail (knob dir_ex_batch_grace_ms, was 40 -> A/B at 10: rounds 6->7, LOCKTOTAL max 5.0->3.9s; bash inter-op gap measured 1.2-1.3ms so 10ms is safe); REMAINDER ~45-128ms = holder work + RELEASE DRAIN (Invariant-1: log_force+iflush+blkdev_flush per dirty dir-EX handoff) = dominant slice.
- P6H-ADOPT elapsed on dir: p50=180ms p90=1562 max=3928 = queue wait (rotation position), NOT discovery.
- LOCKTOTAL >2s events = EX waiters' rotation waits ending in ADOPTION (adopt path bypasses the per-wait census — blind spot, by design now).
- grace=10 left set via sysfs on the RUNNING cluster only; code default still 40 (sess7 old A/B said 25 hurt cc@32 — re-evaluate with a board before changing default).

## NEXT (in order)
1. FULL 32/caw BOARD on 322 defaults (first board since 317; protects 318-322 work). Budget ~20min. Watch cache_coherency (grace interactions), crash, zsl.
2. Drain-cost reduction under RULE 4: does the dir release drain use whole-log xfs_log_force(SYNC) vs targeted commit-LSN force? Region: __mxfs_dlm_dir_inode_durable xfs_mxfs_dlm.c:6500+, many knobs (dir_release_flush_leaf=1 etc). Sketch: force only the dir's last commit LSN + flush only dir blocks; keep Invariant 1 (peer must read durable current image).
3. If turn p50 reaches ~30ms => rotation ~1s, waves ~2.5s, rounds ~11s => 9-10 rounds inside 120s box = PASS with margin. Then dir_reuse x3 + ledger updates (D-DIR-REUSE + D-32NODE-SHARED-DIR-CREATE-PACE need re-measure; D-READDIR-PEER-CACHED-DIR-PACE separate).
4. Then authority family (3 untouched defects) + D-DIRVIEW-NONCONVERGE + D-MATRIX-UNMEASURED.
- presync ~2.5s p50 + wave p50 round-over-round growth still unexplained (open threads).
8 OPEN defects; criteria NO.
