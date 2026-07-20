---
name: AAA-ccloop7251-sess4-FINAL-fairness-root-is-close-demote
description: sess4 FINAL: dlm_fairness free-inode-has-blocks corruption A/B-PROVEN triggered by 0.11.11 ex_close_release demote (=0 → PASS 8/8/8s); next = default…
metadata:
  type: project
---

# dlm_fairness corruption: A/B-proven trigger (sess4 final act)

Deterministic repro (knob=0, fresh mkfs+boot): `MXFS_FORCE_PREP=1 ./run.sh 8
cawd prep_cluster && ./run.sh 8 cawd dlm_fairness` → "XFS Corruption: Free
inode 0x85(=133) has blocks allocated" + trans_cancel shutdown ~25s in.

Single-variable A/B: `MXFS_EXTRA_MODARGS="ex_close_release_ms=0"` (disable the
0.11.11 write-once close-demote) → **PASS 8/8 in 8s**.

Interpretation: the eager per-file EX release at close multiplies inode-
cluster-buffer handoffs in fairness's create→mv→rm churn; a concurrent
same-buffer RMW from a pre-free image clobbers an ifree's dinode-zero →
next ialloc traps (double-alloc/lost-ifree family, 0.10.120 headline class).
The demote is the TRIGGER; the deeper root is the shared-cluster-buffer RMW
race it widens.

Next session:
1. Make ex_close_release_ms default 0 when icluster_dlm=1 (the demote FIGHTS
   cluster grant retention — iclus solves the cold-foreign-stat problem the
   demote was built for). Consider default-0 everywhere pending root fix.
2. Retest knob=1 fairness (ghost dirents got=1-2, no crash) with demote off.
3. Root-fix the buffer race for the knob=0 path (or accept demote-off).
4. Then remaining 8/cawd cells (fio_perf_vs_xfs, scaling_curve, dlm_scaling,
   rsync_paired, fence_during_write), drc perf levers, AG admission fix,
   4-condition 32-node ladders (criteria).

Build at session end: 7D47BD41736A988E1062B93 (0.11.16 + grant_seq + sticky
routing). All other 8/cawd cells green at knob=1 — see
AAA-ccloop7251-sess4-END-sticky-routing-fairness-open.
