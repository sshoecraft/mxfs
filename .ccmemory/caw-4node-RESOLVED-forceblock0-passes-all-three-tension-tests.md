---
name: caw-4node-RESOLVED-forceblock0-passes-all-three-tension-tests
description: RESOLVED: at dir_force_block=0, 4/caw cache_coherency + zero_silent_loss + dir_reuse_coherency ALL PASS 4/4. The sess4 "tension" was an artifact of c…
metadata:
  type: project
---

## 4/caw force_block tension RESOLVED — fb=0 passes ALL three (sess3, 2026-07-07)

Supersedes [[caw-4node-COMPLETE-PICTURE-two-paths-fb0-vs-fb1]] and
[[caw-4node-BREAKTHROUGH-forceblock0-passes-coherency-dirreuse-stalls]] (the "dir_reuse stalls at
fb=0" claim there was WRONG — see below).

### The result (build B6F0D45F, mpatha, MXFS_EXTRA_MODARGS="dir_force_block=0")
| 4/caw test          | fb=0 result            |
|---------------------|------------------------|
| cache_coherency     | **PASS 4/4** (confirmed x2, ~48s) |
| zero_silent_loss    | **PASS 4/4**            |
| dir_reuse_coherency | **PASS 4/4** (336s wall) |

The earlier "dir_reuse fb=0 STALL/timeout" was a MEASUREMENT ERROR: I shell-`timeout`'d run.sh at
250-300s, but run.sh's OWN workload-derived budget for 4/caw dir_reuse is **140*N = 560s**
(run.sh:355, CAW branch; the FUA-per-op platter-publish pace is load-bearing correctness, not waste
— see the sess6 comment there). Given the real 560s budget, fb=0 dir_reuse PASSES 4/4 in 336s (well
within budget, RULE-0 OK). The sess4 fb=0 sf->block race (-117) is evidently fixed by the ~30 dir_*
coherence params added since.

### So Path A works: fb=0 is the fix for the 4/caw coherency corruption
fb=1 (current default) forces block-format dirs → the shared subdir's single dir block (agbno9/AG) is
a hot cross-node RMW hotspot → file-data/torn-RMW aliasing → dir3 CRC → SHUTDOWN. fb=0 = natural XFS
(shortform dirs in-inode) → no shared dir block → genuinely coherent. fb=1 was a sess67 workaround for
the (now-fixed) sf->block race; on CAW/multipath it TRADES that for the block-collision corruption.

### REMAINING WORK to close the criteria (next steps, in order)
1. **Full 4/caw suite at fb=0** — verify NO regressions vs fb=1 (esp. strong_consistency, posix_multi
   [both were never run at 4/caw], mmap_coherency, crash_consistency, integrity, fault tests, soak,
   rsync_paired, dlm_*). Run in batches (foreground 10min cap): coherency batch, then fault/soak batch.
2. **Ladder validation at fb=0**: run FULL suite at 1, 2, 8, 16, 32 caw. sess67 chose fb=1 default
   because 2/tcp passed 17/17 at fb=1 — MUST confirm fb=0 doesn't regress 2/8/16/32-caw. Watch 32/caw
   dlm_scaling (separate perf blocker, [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]]).
3. **Flip the default** `int mxfs_dir_force_block = 1;` -> `= 0` (xfs_mxfs_dlm.c:7908) ONLY after the
   full-ladder validation passes at fb=0. Then re-run the whole ladder at the DEFAULT (no modarg) to
   confirm the criteria at ship config. Rev the patch/minor version per CLAUDE.md.
4. Remove the light P-AGLOW probes (xfs/libxfs/xfs_alloc.c) before the FINAL criteria run.

### CAVEAT
Require 3 consecutive clean runs per test before trusting (sess117 variance). cache_coherency fb=0
confirmed x2 already. Build B6F0D45F. Cluster: 4 nodes mounted (fb=0).
</body>
