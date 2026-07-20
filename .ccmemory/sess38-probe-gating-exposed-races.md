---
name: sess38-probe-gating-exposed-races
description: sess38 CRITICAL: probe-gating sweep (build 4450524B) exposed 2 latent races zsl now FAILS — printk throttling was masking them. Diagnose w/ dirwr=1.
metadata:
  type: project
---

# sess38 — probe gating exposed latent races (zero_silent_loss now FAILS)

## State
Build `4450524B39BD9FF35494E07` = full probe-gating sweep (~46 sites via 4 agents +
manual batch; ALL routine `mxfs: P*` prints now behind `mxfs_dirwr_enabled ||
mxfs_instr_enabled`, dlm/ via caw_instr_on()-style helpers). Diff-reviewed vs
`*.c.backup` files (STILL IN TREE — xfs/, pal/linux/, dlm/, libxfs/): every gate is
print-only, no functional code gated (incl. dlm_caw lock paths — verified by hand).
Deployed to 16 nodes.

## Result: zero_silent_loss FAILS on the gated build (passed 4× on probe-noisy builds)
- Run 1: iter2 silent=1 — `node11_dir84` created-then-lost in shared dir
  (creator mkdir OK, touch ENOENT, pre/post_drop=1599). The sess15 silent=1 class.
- Run 2: iter1 catastrophic — EUCLEAN/EIO storm on ≥5 nodes, 1590/1600 lost,
  test7 dmesg: **"corrupt dinode 131, (btree extents)" at xfs_iread_bmbt_block →
  Corruption of in-memory data (0x8) at xfs_trans_cancel (xfs_trans.c:1061) →
  shutdown**. The KNOWN P133/P134 family: hot shared-dir dinode nextents torn
  vs its own durable bmbt leaf.

## Interpretation (hypothesis, RULE 4 step 1 — not yet instrumented)
The ~36k printk/run cluster-wide (875 P-SFDIR-RELOAD + 876 P-DIR-SEQ + 750
P23-SLOWPATH per node, etc.) were acting as serializers/throttles in the dir
reload/release/writeback hot paths. Gating them = full-speed concurrency =
two latent race classes reopened. Same lesson as instr=1-hides-races, one
level down. These are REAL mxfs bugs; the FS must be correct at full speed.
DO NOT un-gate prints to "fix" it; do NOT widen timeouts.

## Next steps
1. Diagnose with `mxfs.dirwr=1` (designed for exactly this: P133/P134 dinode+bmbt
   revert detectors + dir traces, low-rate write-side). Reproduce zsl, harvest the
   P133-DIRINO-REVERT / P134 / P-SFDIR-RELOAD timeline for ino 131.
2. Beware dirwr=1 may re-mask the race partially (timing). If so, selectively
   enable single detectors (mxfs.dirwr levels: 1=low-rate write-side, 2=per-IO).
3. Root-fix the torn dinode-vs-bmbt write for the shared dir; then the
   created-then-lost single-dirent class (may share the root).
4. After fix: zsl must pass repeatedly on the GATED (silent) build, then
   verify_ship.sh end-to-end (~52 min; start once, block on log in foreground
   chunks). Remove *.c.backup files when sweep is final.
5. Opus (user-run session) is fixing SCST block_count leak on scratch disk2;
   scst.service restart needs a coordinated window between runs.

Related: [[sess38-run14d-recovery-and-probe-gating]], [[sess15-run14d-wedge-recurrence-and-silent1]], [[sess31_lessons]].
