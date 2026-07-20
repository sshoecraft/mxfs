---
name: sess45-uv-fix-locus-consumer-refresh-xfs_inode-695
description: sess45 fix locus for cache_coherency uv (reader side): mxfs_dir_force_evict ALREADY defaults to 1 (so the MODIFY-path evict is on, yet uv still fails…
metadata:
  type: project
---

## sess45 — cache_coherency uv: the READER-side fix locus (final lead before relay)

Continues [[sess45-cachecoherency-uv-drevalidate-fastpath-no-reload-FIX-ENTRY]].

### KEY: `mxfs_dir_force_evict` ALREADY defaults to 1 (xfs_mxfs_dlm.c:1995). So the MODIFY-path
unconditional evict (mxfs_dlm_dir_modify_refresh, 2627→2668 fall-through) is ON, yet uv STILL fails.
=> the fix is NOT the modify path; it's the READER path. (Consistent with sess10: force_evict didn't
fix the lost-update.) Also note force_evict's evict happens on node1's OWN rm of node1_file*, which
captures node2's state at THAT moment (possibly mid-burst), and node1's later test-e READS don't
re-evict — so node1 reads a mid-node2-burst snapshot (the 20-gone/10-present).

### READER refresh entry point: `mxfs_dlm_dir_consumer_refresh(dp)` (xfs_mxfs_dlm.c:2470), called from
xfs_inode.c:695 (a read/lookup path — confirm which: likely xfs_dir_lookup or xfs_readdir wrapper).
This is the reader-side sibling of the modify refresh; it runs with NO ILOCK and takes ILOCK_SHARED.
For uv, node1's `test -e` lookups must trigger an EFFECTIVE cold-reload of $D's DATA blocks here.
NEXT SESSION: read mxfs_dlm_dir_consumer_refresh (2470-2560) — it is almost certainly gated on
(new_incarn || i_dlm_dir_gen != evicted_gen) and that gate is FALSE for node1 (its i_dlm_dir_gen for
$D never advanced — the evict-ring DIR_MODIFY was deduped/async-late, and the SHARED acquire
fast-paths). Candidate fix: in the consumer refresh, when multi-node and the dir is peer-shared,
FORCE the data-block evict (like dir_force_evict does for the modify path) so node1's lookup
cold-reads $D. MEASURE perf (RULE 0: tcp_dlm_scaling) — sess38 disabled per-lookup refresh for CAW
perf; under TCP+fua_disable the cold read hits the coherent shared cache, likely cheaper. Verify:
`./run.sh 2 tcp cache_coherency` → node1 stops seeing node2_file21..30; then full `./run.sh 2 tcp`
for 17/17. Likely also fixes dir_reuse leaf-hash (same class). Build EF006296 is the current
known-good 14/17 baseline; KEEP the partial-iwrite fix
([[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]]).</body>
