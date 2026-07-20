---
name: sess14run-tdscaling-cost-is-settle-loop-required-asynckick-minor-help
description: sess14(ccloop) RULE-4: tcp_dlm_scaling cost localized — the dir-EX-release pincount settle loop is ~35% (skip→45s→29s) but REQUIRED (protects dir-DAT…
metadata:
  type: project
---

## sess14 (ccloop) — tcp_dlm_scaling handoff-cost localization (RULE 4, measured)

Current build **AA8C4934** = fua defaults (fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1) + readdir DABUF_MAP_HOLE fix + coord.sh barrier -C fix + async log-kick. Passes 1/tcp 16/16, 2/tcp 17/17, 4/tcp 17/17 (tcp_dlm_scaling still ~41-52s vs 60s window = marginal but passing).

### A/B measurements (diagnostic params, default 0, KEPT for future A/B)
The dir-EX holder-side release path (xfs_mxfs_dlm.c ~5788-5835) bounds tcp_dlm_scaling throughput (~46-52s for 150 rounds × 3 ops × 4-way; one node always finishes fast ~7-17s = DLM unfairness).
- `relflush_skip=1` (skip per-release blkdev_issue_flush): elapsed UNCHANGED ~44s → the flush is NOT the cost.
- `relsettle_skip=1` (skip the `while(pincount>0) usleep` settle loop): max 45s→**29s** → the settle loop is ~35% of the cost.
- BUT the settle is REQUIRED: defaulting relsettle_skip=1 broke the full suite (dir_reuse 0/4, fence/netpartition 3/4). The settle's pincount==0 wait protects the dir-DATA flush (mxfs_dir_flush_data_blocks runs BEFORE the inode drain mxfs_ail_drain_inode_to; the drain only covers the dinode, not dir data blocks). So it is NOT redundant with the drain's own pin==0 loop.
- `xfs_log_force(mp, 0)` (async CIL kick) added before the settle loop: trims it ~10% (45→41s, more balanced 40/40/40 vs 52/17/52/46). SAFE (still waits pincount==0). KEPT.

### Implication for reliability
The remaining settle cost (~12s, 41 vs 29) is genuine durability wait (log write + AIL insert before dir-data flush) — inherent. tcp_dlm_scaling stays marginal. To get real margin would need either: (a) a way to make dir-data durable without the full per-release inode-settle (e.g. FUA-write dir blocks so they're durable independent of inode pin state — then settle could be inode-only/shorter), or (b) reduce handoff COUNT (longer hold quantum, but that worsens the fairness asymmetry). Both non-trivial; defer.

### Criterion status: 1/tcp ✅ 2/tcp ✅ 4/tcp ✅(marginal) 8/tcp ✗ (DABUF holes + empty-content). NOT met.
See [[sess14run-4tcp-CAN-pass-17of17-tdscaling-flaky-margin-46to52s]] [[sess14run-HANDOFF-final-1and2tcp-100pct-4tcp-16of17-8tcp-needs-hole-and-content-work]].
