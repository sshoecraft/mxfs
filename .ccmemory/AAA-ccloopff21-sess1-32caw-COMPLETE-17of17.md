---
name: AAA-ccloopff21-sess1-32caw-COMPLETE-17of17
description: MILESTONE: 32/caw COMPLETE 17/17 fresh single-build on 0.10.74 (84FCBF6F), all post-crash-recovery + post-cutoff 20260712T201747Z. dir_reuse@32 PASS…
metadata:
  type: project
---

## 32/caw = 17/17 PASS, all fresh on 0.10.74, verified via:
`python3 scripts/matrix_check.py --since 2026-07-12T20:17:47Z --nodes 32` -> "32/caw: 17/17 PASS (fresh)" / "MATRIX 100% PASS"

Three revalidate_cell.sh runs this session, all CELL-GROUP OK, all probe_sweep CLEAN
(total_hits=0), all build=84FCBF6FF9F30138E2B5836:
- `revalidate_cell.sh 32 g2` (dlm_membership, crash_consistency, fence_during_write,
  fault_netpartition) — run_id 20260712T201823Z
- `revalidate_cell.sh 32 g1` (precond_readiness, cache_coherency, strong_consistency,
  posix_multi, mmap_coherency, zero_silent_loss, dlm_fairness, scaling_curve,
  dlm_scaling, rsync_paired, soak, dlm_lock_correctness) — run_id 20260712T202157Z
- `revalidate_cell.sh 32 dr` (dir_reuse_coherency alone) — run_id 20260712T202944Z,
  24/24 rounds clean, ~35min wall (well inside the 5380s budget), 32/32 nodes.

This closes out the historically hardest cell (dir_reuse@32 was the sole remaining
gap across ~15 prior ccloop sessions per memory history — mkdir_storm dirent-loss
family, now fixed via 0.10.71/0.10.73/0.10.74's three root-cause fixes).

## Remaining for the full 1/2/4/8/16/32 criteria
16, 8, 4, 2, 1 nodes still need a FRESH single-build sweep on 0.10.74 (existing
criteria.json passes for these predate 0.10.74 and are provenance-murky per
daf50d34 sess1's concern). Same revalidate_cell.sh pattern:
- 16: `revalidate_cell.sh 16 nodr` + `revalidate_cell.sh 16 dr` (dir_reuse@16 budget
  140*16+900=3140s)
- 8/4/2/1: `revalidate_cell.sh N full` each (17 tests in one run.sh invocation,
  smaller N so full fits in one go; dir_reuse budget auto-computed by run.sh)

Then final gate: `python3 scripts/matrix_check.py --since 2026-07-12T20:17:47Z`
(no --nodes filter) must show ALL of 1/2/4/8/16/32 @ caw as 17/17 PASS (fresh)
before writing YES to the criteria-met marker.

Cluster state: all 32 VMs up, 2-path mpatha, no need to re-run mpath_up.sh for
smaller N (they're a subset of the same fleet). SCST/mpath survives across N
changes — only the FS gets fresh mkfs+mount per revalidate_cell run.
