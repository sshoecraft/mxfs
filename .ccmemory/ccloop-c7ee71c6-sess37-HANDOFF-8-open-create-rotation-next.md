---
name: ccloop-c7ee71c6-sess37-HANDOFF-8-open-create-rotation-next
description: sess37 HANDOFF: 8 OPEN; board 317=20/21 green except dir_reuse (7 rounds); grace 40→120 REFUTED (rounds/handoffs flat) — next: why create tenure-batc…
metadata:
  type: project
---

# sess37 handoff — exact resume point

## Tree/cluster state
- VERSION=0.11.317 (srcversion 7EEBFAFD487442C3CC17EAB) deployed cluster-wide at 32/caw, boarded **20/21** (only dir_reuse FAIL, 7 rounds vs floor 8). All records written: CHANGELOG 311-317, ledger (teardown-leak FIXED AND VERIFIED; 3 pace entries progress_sess37), awareness dlm/xfs/pal sess37 deltas, ccmemory sess37-armgate + sess37-handoff-retention memories.
- 8 OPEN: 3 pace (DIR-REUSE-32-FLAKY = only board FAIL; 32NODE-SHARED-DIR-CREATE-PACE; READDIR-PEER-CACHED needs native-XFS paired number), 3 authority (FOREIGN-REPLAY-UNGATED-IMAGES, RELEASE-BARRIER-OPEN, INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY), MATRIX-UNMEASURED (rig-blocked), DIRVIEW-NONCONVERGE-SESS25.

## dir_reuse round anatomy (fully instrumented in-test: DRCph markers + DCSTK sampler)
create own ~3s | **wrbar (rotation tail) 8-9s** | sync 2.2-3.0s | dc-real 0.10-0.15s (FIXED this session) | ls 0.1s | lookups 1.6-2.4s | rm 3.3-3.4s ≈ 17s/round, need ≤12.5s.

## REFUTED this session (do not retry)
- dir_ex_batch_grace_ms 40→120 live A/B: rounds still 7, dir handoffs flat (~200-294/lap). EX-tenure batching does NOT engage for the create rotation.
- HYPOTHESIS FOR NEXT SESSION (unverified): each create = bash open(O_CREAT) → lookup half takes dir PR, insert half needs EX → per-create PR→EX upgrade cycle (sess51 precedent in dlm_caw.c ~line 11960 comment). The EX tenure ends because the node itself re-enters via PR (or the streak PR-batch grants strip it). MEASURE: per-op mode sequence on the dir during one create phase (P13-INSTR GRANT-POLL / ilock_begin mode trace on watch_ino), count PR→EX upgrades vs pure EX re-acquires per node per round. If upgrade-cycle confirmed: fix shape = create-path holds dir EX across lookup+insert (xfs_create already has the dp ILOCK; the DLM mode requested for the LOOKUP half is the question) or upgrade-in-place fast path (convert own PR→EX in one CAS when no other holders — the convert compatible-upgrade path at dlm_caw.c ~4790 already does this — why isn't it hit? measure).
- Also next: sync phase 2-3s (32-node log-force+flush herd — coalescing exists for release-side, check create-phase sync path), rm cohorting (GPT rx: dir-EX cohort hold + per-ICLUSTER tenure batching → 4-5 tenures not 128).

## Watch items
- 5 P6H-HANDOFF without matching P6H-ADOPT (310 vs 305 in one anatomy run) — expected to be abort-reconciles (P6H-ABORT-RECONCILE); verify count matches when convenient.
- P6H-ADOPT reads=3-31 before adopt (wait includes queue turn — not necessarily nudge loss; measure handoff→adopt latency by pairing realms if adopt-latency becomes the lever).
- caw_direct_handoff/evict_retain_pr default ON — any new flake in boards: A/B these knobs FIRST.
- fio_perf jumped (seqW 2152→5341 MiB/s, randW 167k→248k) on 317 — retention removed eviction protocol churn; keep an eye that it's stable, could also be run-to-run variance.

## Criteria: NO — 8 OPEN vs RULE 6 zero-defect bar.
