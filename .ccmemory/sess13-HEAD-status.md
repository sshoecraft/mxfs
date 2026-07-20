---
name: sess13-HEAD-status
description: sess13 HEAD: build CF359E6C DEPLOYED+validated (14-15/16, flaky shared-dir churn). DOUBLE-GRANT REFUTED. Residual=serialized-stale shortform reload.…
metadata:
  type: project
---

## HEAD sess13 end. Criterion `./run.sh 2 tcp` 100% = NOT met. Marker NOT written.

## BUILD CF359E6C — DEPLOYED + validated both nodes. Full suite runs observed this session: 15/16 and 14/16 (residual rotates {crash_consistency, tcp_dlm_scaling, dlm_fairness} — flaky, same shared-dir-churn root). The `lkt_ino` param add is inert unless set, no regression. CF359E6C = F967E0F5 (CONVBLK) + sess13:
- xfs_mxfs_dlm.c/.h: `mxfs_dlm_yield_basted_cached_ags` (MODE-A AG<->dir deadlock; DEAD CODE, 0 fires — keep or revert) + `mxfs_dlm_dir_modify_reload_prelock` (MODE-B pre-ILOCK shortform reload; insufficient alone) + `lkt_ino` P-LKT filter param.
- xfs_inode.c: prelock-reload calls in xfs_remove/create/rename (before xfs_trans_alloc*).
- dlm.c: lkt_ino guard in mxfs_lkt_record.
- tests/tcp_scaling_capture.sh, tests/tcp_lkt_doublegrant.sh (RULE-4 harnesses; FOREGROUND only).

## DIAGNOSIS STATE (the residual = ONE root, shared shortform-dir concurrent churn):
- **DOUBLE-GRANT REFUTED** (decisive, RULE-4): P-DOUBLEGRANT=0 + P-STALEMASTER-GRANT=0 (always-on) at a failure. TCP DLM serializes dir-EX correctly. No 2nd double-grant path exists (refutes sess12 lead). [[sess13-doublegrant-REFUTED-serialized-stale]]
- **Release durability sound** incl. shortform (bast_process barrier !in_ail&&!pinned covers the shortform dinode; mxfs_dir_data_durable returns true vacuously for FMT_LOCAL but in_ail handles it). NOT the gap.
- **Root = serialized-but-STALE modify/reload**: node holds dir-EX legitimately, RMWs a shortform base missing a durable change. Leftover is the node's OWN n1_rN (nlink=1, rename+rm reverted). Two live candidates: (1) read-side SCST cache-vs-platter coherency at acquirer reload (P34D: coherent read == stale base); (2) within-node release-timing self-revert.

## NEXT SESSION decisive step (tooling ready in CF359E6C): run tcp_dlm_scaling with `MXFS_EXTRA_MODARGS='lockwr=1'`; ~2s into the run set the dir-inode filter ON THE NODE (no clyde orphan): `ssh node 'sleep 2; echo $(stat -c %i /mnt/shared/.tcp_dlm_scaling) > /sys/module/mxfs/parameters/lkt_ino &'`. On failure `echo <dino> > /sys/module/mxfs/parameters/lktdump` both nodes; read the DIR's cross-node GRANT/REAFFIRM/REMOTE-RELEASE/UNLOCK timeline (now un-flooded by child GRANT-LOCAL noise) correlated with the resurrected dirent's realns to decide candidate (1) vs (2), then fix. If (1): fix the inode-cluster read coherence point (cf [[sess85_lessons]]). If (2): the within-node create→rename→rm release interleaving reverts the node's own removal.

## HARD LESSONS: (a) NEVER run_in_background + wait/until-loop/poll — orphans *.output files → ccloop Stop hook (keepgoing.py counts them) fires "Background command still running" forever. FOREGROUND everything; if a setter must run mid-test, background it ON THE NODE via ssh (returns immediately, no clyde orphan). [[feedback-never-background-wait-poll]] (b) ALWAYS virsh destroy+start BOTH nodes before a run (contaminated cluster → mkfs rc=1/module-not-loaded = false FAILs). test1=DHCP .114, test2 .182 (harness uses DNS names). NFS /src from 192.168.1.4.
[[sess13-doublegrant-REFUTED-serialized-stale]] [[sess13-modeB-writeside-laggy-heartbeat-not-stale-read]] [[sess13-two-failure-modes-and-p91-falsepos-resurrection]]
