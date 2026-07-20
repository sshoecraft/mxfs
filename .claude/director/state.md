# Director State — MXFS v5

**Updated**: 2026-03-24 ~04:00 CDT
**Phase**: Phase 6 — remaining 1/40 directory entry loss
**Current task**: Worker dispatched to investigate and fix (task ID: bpjz6ag1y)
**Waiting for**: Worker report

## Session Progress

### Fixes implemented and validated
1. Per-node XFS log slices (Phase 5) — 0 errors, independent log counters
2. Cross-node LSN check suppression (Phase 6a) — 0 "Structure needs cleaning"
3. Directory data block cache invalidation (Phase 6b) — block-format dirs protected
4. Stale-at-init (Phase 6c) — first DLM acquire always reloads → 9/10 pass (was 7/10)

### Current pass rate
- 9/10 concurrent mkdir runs: 40/40
- 1/10: 39/40 (single dir lost)

### Worker infrastructure
- worker.py at ~/src/mxfs/worker.py
- Layered context: worker-system.md + worker-methodology.md + task brief
- Worker reads settings.json for effort level
- Worker runs in -p mode with bypassPermissions
- Tested and working

### Disproved hypotheses
- Storage flush not reaching disk → DISPROVED (blkdev_issue_flush didn't help, BAST verify shows correct data)
- Fast-path stale check → NO-OP (BAST sets mode=NL, fast path never entered when stale)
