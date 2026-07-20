---
name: sess43-FIX-dir-force-block-default-on-passes-dir-reuse
description: sess43 FIX (build 422E6DC6): dir_force_block DEFAULT=1 eliminates cross-node sf→block conversion divergence → dir_reuse_coherency 2/tcp PASS (drc-FAI…
metadata:
  type: project
---

## sess43 — dir_reuse_coherency 2/tcp FIXED by dir_force_block DEFAULT ON (+ P43/P43B guards)

### THE FIX (build 422E6DC6, KEEP): two parts in xfs/xfs_mxfs_dlm.c
1. **`int mxfs_dir_force_block = 1;`** (was 0/off). Forces new MULTINODE dirs to BLOCK format at mkdir (mxfs_dir_should_force_block guard: multi-node + DIR + shortform only). Eliminates the cross-node sf→block CONVERSION divergence: with the dir born block (single-node mkdir conversion only), two nodes can't independently convert a fresh shared dir and split logical-block0 (node1 fsb15 / node2 fsb14).
2. **P43 + P43B** block→shortform format-revert guards in mxfs_dlm_reload_inode (fix the self-revert sub-case; defense-in-depth, harmless under force_block).

### EVIDENCE (drc_cap2, build 226E02D6 with MXFS_EXTRA_MODARGS=dir_force_block=1, clean reboot):
`PASS dir_reuse_coherency (nodes_pass=2/2)`, 24 rounds, **drc-FAIL=0, drc-RDMISS=0, doubles=0** (zero same-incarnation double-conversions). P42-SFCONV=24 = exactly the single-node mkdir force-conversion. ~280s wall (force_block adds NO perf cost — unlike dir_merge which was ~50s/round = RULE-0 timeout).

### WHY this works now when sess18 said force_block is ineffective:
sess18 tested force_block ALONE on a 40-session-OLDER build whose block0 RMW still clobbered (concurrent same-block lost-update). The intervening coherency fixes (per-AG drain-before-release, FUA-fresh acquire-reload/evict, P43/P43B, etc.) closed that gap. So now: force_block removes the conversion-divergence LAYER, and the existing RMW coherency handles the shared single block0. Both layers covered → PASS. [[sess18-CORRECTION-transition-redherring-sameblock-rmw-is-root]]

### REFUTED this session: dir_force_block + dir_merge together — CORRECT (drc-FAIL=0 through 5 rounds) but dir_merge reads the peer's full dir per-create → ~50s/round → would TIMEOUT (RULE 0). force_block ALONE is fast AND correct. Leave dir_merge=0.

### STILL TODO before writing criterion-met ("2 node dlm=tcp test 100% successful"):
1. VERIFY default-config (build 422E6DC6, NO modarg): force_block=1 active by default, dir_reuse PASS. (running task b1zay7pae)
2. STABILITY: ≥2-3 consecutive dir_reuse PASSes (bug was intermittent — failed run #2 at round ~10).
3. FULL SUITE: `./run.sh 2 tcp` (17 tests) 100% PASS — confirm force_block=1 default doesn't regress other criteria (cache_coherency, crash_consistency, posix_multi, etc.).
### OPERATIONAL: don't TaskStop drc_cap2 mid-flight (leaks module refcnt=1 → mkfs prep fails → virsh reboot). [[sess43-killing-drc-cap2-midflight-leaks-module-refcount]] [[sess43-PASS-dir-reuse-fixed-P43-P43B-fmtrevert-guards]] [[sess43-residual-is-crossnode-concurrent-grow-divergence-not-self-revert]]
</body>
