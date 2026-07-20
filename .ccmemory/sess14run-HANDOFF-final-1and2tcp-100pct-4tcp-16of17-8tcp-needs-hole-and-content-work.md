---
name: sess14run-HANDOFF-final-1and2tcp-100pct-4tcp-16of17-8tcp-needs-hole-and-content-work
description: sess14(ccloop) FINAL HANDOFF build 70F91E1B: 1/tcp 16/16 + 2/tcp 17/17 = 100%. 4/tcp 16/17 (tcp_dlm_scaling marginal). 8/tcp broadly fails (DABUF_MAP…
metadata:
  type: project
---

## sess14 (ccloop 4cb2d0a2) FINAL HANDOFF — build 70F91E1B (KEEP, deployed)

### Source changes this session (ALL KEEP, in 70F91E1B)
1. xfs/xfs_mxfs_dlm.c DEFAULTS: `fua_disable=0`, `fua_always=1`, `dir_epoch_adopt=1`, `dir_epoch_convert_gate=1`. Cluster is a **LIO** target (lsscsi=LIO-ORG, iscsi_target_mod) → FUA reads REQUIRED; gated fua_always=0 is NOT reliable (defaults gated run = crash_consistency 3/4 + dir_reuse 0/4).
2. xfs/xfs_dir2_readdir.c: bump `i_dlm_dir_gen` ONLY after a successful reload (fixes DABUF_MAP_HOLE from fresh-leaf+stale-extent-map when reload trylock-bails). PROVEN: 4/tcp dir_reuse reliable after this (was the round-23 shutdown).
3. tests/suite/coord.sh: coord_barrier `-C $MXFS_NODES` (instant rendezvous, was `-W 2` = ~10s/round). Cut dir_reuse 4/tcp 465s→205s. Speeds ALL coord tests.
4. tests/tcp/tcp_dlm_scaling.sh: harmless `mxfs-TDS ... elapsed=` /dev/kmsg diagnostic.

### REVERTED (do NOT re-add as-is)
- A DABUF_MAP_HOLE "EIO+arm-reload instead of EFSCORRUPTED" guard at xfs_da_btree.c invalid_mapping (build FF6B0C59). It SELF-AMPLIFIES: arming MXFS_IF_DIR_RELOAD + i_dlm_stale on a hole triggers reload attempts that bail and create MORE holes → regressed 4/tcp dir_reuse to 0/4 (holeguard fired 10×/node). Reverting restored 4/4. If retried, must NOT arm reload from inside the hole path, and must eliminate holes at the SOURCE (reliable reload), not convert them.

### RESULTS (criterion = 1/2/4/8 tcp FULL suite 100%)
- **1/tcp = 16/16 PASS** (incl fio_perf, fio_vs_xfs_baseline — FUA fine single-node).
- **2/tcp = 17/17 PASS** (incl tcp_dlm_scaling 2/2).
- **4/tcp = 16/17**: dir_reuse now reliable. ONLY tcp_dlm_scaling marginal: standalone elapsed ~44s for ranks 2-4 (rank1 ~7s — one node always finishes fast = DLM unfairness) vs 60s window; in-suite (after soak) 2/4 nodes exceed 60s. FUA vs gated = identical ~44s (NOT a FUA cost) → it is pure dir-EX handoff throughput: 1800 serialized cross-node ops, per-release Invariant-#1 drain at xfs_mxfs_dlm.c ~5788-5818 (settle usleep loop + 2× log_force + mxfs_dir_flush_data_blocks + mxfs_ail_drain_inode_sync + blkdev_issue_flush ~25ms).
- **8/tcp = broadly FAILS**. Two distinct bug classes amplified at 8-way: (a) **DABUF_MAP_HOLE shutdowns** — test7/8 took 17-18 each (the readdir fix only covers readdir; CREATE/LOOKUP also map blocks vs a stale extent map when reload bails under heavy contention); (b) **empty-content reg-file coherency** — cv/cwr/rv checks read peer files as EMPTY (exp=content got=, di_size=0 family, sess45/79). 635/765 checks pass; ~130 fail on these two classes.

### NEXT SESSION
1. **8/tcp DABUF_MAP_HOLE**: eliminate holes at the SOURCE — make the dir extent-map reload at the modify/lookup/readdir prelocks RELIABLE under contention (the trylock-bail is the root). Options: bounded-retry the reload; or a blocking reload where only IOLOCK is held (readdir/lookup sites). Do NOT use the reverted in-hole EIO guard.
2. **8/tcp empty-content**: peer reg-file reads empty (di_size=0). Reg-file BAST-release durability / FUA-read-of-inode-cluster at scale.
3. **4/tcp tcp_dlm_scaling**: reduce dir-EX handoff latency without breaking Invariant #1 (the per-release drain dominates). Or characterize whether the in-suite 2/4 fail is consistent.
4. INFRA: a failed run leaves nodes mounted → next prep_fs mkfs hits "device busy". Clean with umount+rmmod on test1..8 before re-prepping.
Cluster test1-8 via `virsh -c qemu:///system`. Criterion NOT met. See [[sess14run-BREAKTHROUGH-LIO-fua-defaults-plus-barrier-perf-fix]] [[sess14run-FIX-readdir-dabuf-map-hole-gen-bump-before-reload-bail]] [[sess14run-STATUS-2tcp-17of17-4tcp-16of17-tdscaling-marginal]].
