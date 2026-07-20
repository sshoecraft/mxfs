---
name: caw-16node-session-state-dlm_scaling-fixed-coherency-variance
description: ccloop 0d6e174d state: dlm_scaling FIX validated SAFE (build 8B203AA4, valid_epoch-gated private skip); cache_coherency PASSES with it (variance-driv…
metadata:
  type: project
---

## ccloop 0d6e174d — consolidated state (2026-07-06/07)

Supersedes [[caw-16node-dlm_scaling-FIX-validepoch-safe-but-marginal]]. Read
[[caw-16node-dlm_scaling-ROOT-PROVEN-private-dir-fua-storm]] for the root.

### dlm_scaling FIX — DONE + VALIDATED SAFE (build 8B203AA4, clean, probes removed)
Param `dir_priv_ex_skip=1` (default). Gate = `i_dlm_mode==MXFS_LOCK_EX && !i_dlm_dir_contended
&& i_dlm_dir_valid_epoch==0`, applied at xfs_da_btree.c owned_ex (~3090) + xfs_dir2_data.c
mxfs_dir_addname_coherent_refresh (~2087). Skips the private-dir FUA storm (~5860 dir-FUA/node → few).
- **PROVEN SAFE**: cache_coherency PASSED 16/16 WITH the fix (run 014522Z). P-PRIVSKIP probes (now
  removed) showed 0 engagement on shared dirs (valid_epoch>0 disqualifies them), full engagement on
  dlm_scaling's private subdir (ino=131, valid_epoch=0).
- **WORKS**: dlm_scaling 14-15/16 (was 0/16). The 1-2 marginal nodes fail only `rate>=floor` (complete
  2000 ops, dip <50/s) = 16-node throughput variance, NOT a fix defect (worse on contaminated runs).
- `#include "../dlm/v5_mount.h"` added to xfs_da_btree.c for MXFS_LOCK_EX.
- Build chain: D8BEF5A5(base)→98D240B3(v1 !contended, REGRESSED cache_coh)→8B203AA4(v2 +valid_epoch,
  SAFE)→787CCEE8(v2+probes)→8B203AA4(probes removed = FINAL).

### THE REAL 16-NODE BLOCKER: coherency variance + contamination (PRE-EXISTING, not my fix)
- cache_coherency standalone at 16 is ~50% FLAKY: FAIL 0/16 (runs 012756Z, 014825Z) vs PASS 16/16
  (run 014522Z) on identical fresh clusters. Failure = rotating victim node, content empty (writes
  don't land before barrier). SESS50-STARVE EX-handoff + durability drain race on the concurrent
  same-dir create (cross_visibility: 16 nodes → 1 shared dir).
- CONTAMINATION: running dlm_scaling then cache_coherency → cache_coherency test#2 FAILs 0/16 (test1
  showed 3 shutdowns + SESS50-STARVE, degraded by prior test). Memories' proven lever = MXFS_SETTLE_MS
  (run.sh inter-test sync+drain; caw-16node-ROOT-cumulative-backlog-settle-fixes: settle=8000 → 11/12).
- criteria.json shows cache_coherency PASSED 16/16 on base D8BEF5A5 (18:08) — CAN pass, variance-gated.

### ENVIRONMENT (characterized — NOT the bottleneck)
Shared LUN = /home/steve/disk.img (50GB) via SCST vdisk_fileio on /dev/nvme0n1p2 (Samsung 990 EVO
Plus 2TB, rotational=0, only 12% util). clyde 94GB RAM. So 16-node failures are NOT disk-bandwidth —
they're FUA round-trip latency (~3-5ms/FUA read measured via dlm_scaling speedup) + DLM handoff
coordination + coherency-drain races. Reducing redundant FUA I/O is the right lever (dlm_scaling fix
did this for private dirs; shared dirs need within-tenure dedup, NOT yet attempted).

### CLUSTER HYGIENE (critical, learned hard)
- ALWAYS `scripts/caw_preflight.sh 16` before a run. NEVER kill run.sh mid-test (leaves mxfs mounted →
  next prep power-cycles 7-10 nodes → 5min slow prep → false timeout). run.sh TEST_TIMEOUT=300s;
  external timeout must be >= preflight + ~40s formation + 300s. `virsh destroy+start` reboot all 16
  after heavy runs (SESS50-STARVE + shutdowns accumulate, nodes won't rmmod).
- run.sh args: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1 [dir_priv_ex_skip=0 to A/B]" ./run.sh 16 caw <tests...>`.

### NEXT (ranked)
1. Reboot clean → run FULL 16/caw suite with MXFS_SETTLE_MS=8000 → baseline what passes with the fix.
2. dir_reuse_coherency 16/caw: SEPARATE root (EIO node3/4), unaddressed.
3. Intra-test cache_coherency variance (settle won't fix it) — the deep residual race.
4. Then 32/caw (never run). Then re-run 1/2/4/8 on final build → marker.
Marker NOT written.
</body>
