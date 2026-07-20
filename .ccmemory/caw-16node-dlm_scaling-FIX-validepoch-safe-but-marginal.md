---
name: caw-16node-dlm_scaling-FIX-validepoch-safe-but-marginal
description: dlm_scaling fix v2 (build 787CCEE8): +valid_epoch==0 guard makes it SAFE for cache_coherency (skip no-op there, P-PRIVSKIP=0) but marginal 15/16 (tes…
metadata:
  type: project
---

## dlm_scaling fix iteration (ccloop 0d6e174d, 2026-07-06) — SAFE now, but two open issues

Continues [[caw-16node-dlm_scaling-FIX-private-ex-fua-skip]] [[caw-16node-dlm_scaling-ROOT-PROVEN-private-dir-fua-storm]].

### Signal evolution (param `dir_priv_ex_skip`, both sites: xfs_da_btree.c owned_ex + xfs_dir2_data.c addname-platter-check)
- **v1 (build 98D240B3): `EX && !i_dlm_dir_contended`** → dlm_scaling PASS 16/16, but REGRESSED
  cache_coherency (clean A/B PROVED: skip=1 FAIL 0/16 empty-content, skip=0 PASS 16/16). Hole:
  cache_coherency subtest1 is a SINGLE shared dir with concurrent mkdir+create from all 16; a dir is
  briefly EX && !contended BEFORE the first peer BAST → skip fired → stale-base addname RMW clobbered
  dirents. `!contended` catches in-flight BASTs but misses COMPLETED handoffs during an earlier NL window.
- **v2 (build 787CCEE8): `EX && !contended && i_dlm_dir_valid_epoch==0`** → SAFE for cache_coherency:
  P-PRIVSKIP-ADD/RD = 0 on ALL nodes during cache_coherency (skip never engages on shared dirs;
  valid_epoch bumps >0 on first cross-node handoff, maintained on CAW at xfs_mxfs_dlm.c:15593-15597).
  BUT dlm_scaling now only **15/16** — test14 alone failed `rate>=floor` (completed 2000 ops, rate
  dipped <50/s). valid_epoch==0 is occasionally too strict → skip disengages on some ops → less
  throughput margin than v1. P-PRIVSKIP fires fine on the private subdir (ino=131 valid_epoch=0
  dir_gen=0 contended=0 mode=5=EX).

### Probes currently IN THE TREE (build 787CCEE8, REMOVE before final)
- P-PRIVSKIP-ADD (xfs_dir2_data.c) + P-PRIVSKIP-RD (xfs_da_btree.c), gated on mxfs_dirwr_enabled,
  log ino/gen/mode/contended/valid_epoch when the skip engages. Used to prove no-op on shared dirs.

### TWO OPEN ISSUES (both must resolve for 16/caw green)
1. **dlm_scaling margin** (15/16 → 16/16): valid_epoch==0 too strict, or test14 is borderline LUN
   variance. NEXT: re-run to see if 15/16 is stable or variance; if stable, find why one node's private
   subdir loses skip margin (spurious valid_epoch bump? or split read/write gating — keep read-side Site1
   loose but write-side Site2 strict?).
2. **cache_coherency PRE-EXISTING flakiness at 16** (INDEPENDENT of my fix, P-PRIVSKIP=0): standalone
   cache_coherency FAILs 0/16 with ROTATING VICTIM (node16 this run: "content of node16 got=empty" —
   its writes didn't land). This is the documented SESS50-STARVE EX-handoff starvation on the
   concurrent-same-dir create (cross_visibility = 16 nodes hammer ONE dir). criteria.json shows
   cache_coherency PASSED 16/16 on base D8BEF5A5 (18:08) so it CAN pass — variance/cluster-state
   dependent. This is the REAL long-standing 16-node blocker; my dlm_scaling fix is orthogonal.

### CLUSTER HYGIENE (learned the hard way this session)
- ALWAYS `scripts/caw_preflight.sh 16` before a run; NEVER kill run.sh mid-test (leaves mxfs mounted →
  next prep power-cycles 7+ nodes → 5min slow prep → false timeout). run.sh per-test budget TEST_TIMEOUT=300s;
  cache_coherency budget=300s (TIMEOUT_BUDGETS.md). Give external timeout >= preflight + formation(~40s) +
  300s. Do a virsh destroy+start reboot of all 16 after many heavy runs (SESS50-STARVE slowness accumulates).
- Builds this session: D8BEF5A5 (base) → 98D240B3 (v1 !contended) → 8B203AA4 (v2 valid_epoch) → 787CCEE8 (v2+probes).
</body>
