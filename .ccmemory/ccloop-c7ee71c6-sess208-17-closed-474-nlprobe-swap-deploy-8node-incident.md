---
name: ccloop-c7ee71c6-sess208-17-closed-474-nlprobe-swap-deploy-8node-incident
description: sess208: #17 closed in ledger (29→28); 0.11.474 P95-NL-UNDER-HOLD probe built; module_swap_deploy.sh reform w/o mkfs → 8-node wedge/shutdown incident…
metadata:
  type: project
---

# sess208 — #17 closed, near-miss probe, reform incident

## Done
- #17 D-IUNL-LIVESKEW-REFUSES-PENDING-WINDOW-GRAFT-471 marked FIXED AND
  VERIFIED in OPEN_DEFECTS.json (entry idx 71) citing sess207 evidence.
  Ledger 29→28 open.
- 16 more clean rsync_paired laps on .473 (54 total across sess207+208,
  zero P95-OPEN-PROTECT-FAIL fleet-wide), incl. 6 laps immediately after
  chunk-2a DLM churn (dlm_fairness dlm_membership scaling_curve
  dlm_scaling — all PASS). Plain lapping does NOT reproduce #18.
- 0.11.474 (sv 56C5B006156E12856799D4F): added P95-NL-UNDER-HOLD
  near-miss probe in mxfs_dlmtr_rec (xfs_mxfs_dlm.c ~1266): fires on any
  granted→NL lowering while i_dlm_ex_holders||i_dlm_pr_holders — the P95
  hazard class REGARDLESS of the microsecond race landing. Prints ino,
  line, om, os, ns-state, exh, prh, acq, open_n, imode, pid, comm.

## scripts/module_swap_deploy.sh (NEW)
Deploys tree's mxfs.ko to fleet WITHOUT mkfs (preserves aged fs):
parallel umount+rmmod ×32 → prep_node.sh form test1 → join 2-32 →
rewrite .cluster_marker.json. TRAP: pkill -f 'rsync|fio' inside the ssh
command matches the remote shell's own cmdline → kills session rc=255;
use pkill -x.

## INCIDENT (uninvestigated at session end — sess209 priority 1)
After the swap-deploy reform on the aged fs, first workload touch →
8/32 nodes (test2,6,7,14,21,27,29,32) lost mounts within ~2min:
- test2: P-NOINO-DRAIN-STUCK ino=12585547 try=8 (AIL min frozen) →
  P-NOINO-RELFENCE-WEDGE → shutdown → withdraw slot=16. SESS50-STARVE
  ino=12585547 waiters=40 waiters_ex=40 h_ex=10000 before death.
- Victims show P5N-AG-ORPHAN-NAK (stranded CAW AG holder bit,
  src=bast-rx repair=0) and post-withdraw reservation conflicts.
- Survivors: P238-FENCE-DONE + P163-RECOVERY-PENDING slots 27, 1
  (~60s later = downstream).
- CAVEAT: cross-node event ordering NOT established — my sweep used
  head -6 of full dmesg and P5N strands appear at test32 t=25114
  (pre-swap, during normal board runs!) so strands may PREDATE the
  parallel teardown. Time-window everything before concluding.
Likely new RULE 6 defect: reform-on-existing-fs (production rolling-
restart flow) → stranded-AG/NOINO wedge cascade. Root before ledgering:
(a) strand provenance (mass umount vs pre-existing), (b) what froze ino
12585547's release fence, (c) why P5N repair=0 from bast-rx when
ag_strand_repair cell passes.

## Rig state at session end
DEGRADED: 24 mounted on .474, 8 down. VERSION 0.11.474. Marker says
32/caw sv 56C5B006156E12856799D4F but run.sh refuses (not all MOUNTED).
Recovery = ./run.sh 32 caw prep_cluster (mkfs, loses aged fs) AFTER
evidence collection.
