---
name: ccloop-c7ee71c6-sess36-HANDOFF-310-built-teardown-fix-unverified
description: sess36 HANDOFF: 0.11.310 BUILT NOT DEPLOYED/BOARDED (teardown_arm_gate fix); NEXT = teardown_leak_repro A/B (gate=0 then 1), then 32-board on 310; 9…
metadata:
  type: project
---

# sess36 handoff — exact resume point

## Tree state at relay
- VERSION=0.11.310, mxfs.ko srcversion **A664F66CA55D872C8BEE618** — BUILT, **NOT deployed, NOT boarded**. Cluster still runs 309 (086FA2DC) prepped 32/caw with 3 sustained_load runs of history.
- 310 delta: `mxfs.teardown_arm_gate` (default 1; 0=legacy A/B) — P6G-REL-STALE stranded-release deferral skips the dwork arm (no igrab) when `xfs_is_unmounting(mp) || xfs_is_shutdown(mp) || !mp->m_mxfs_dlm`; prints P6G-REL-STALE-TEARDOWN instead. Files: xfs/xfs_mxfs_dlm.c (~17150 site + extern at 119), pal/linux/xfs_aops.c (knob decl).
- NEW tests/teardown_leak_repro.sh [N] [cycles]: prep → 10s cross-node churn in one shared dir → mid-churn `xfs_io -x -c 'shutdown -f'` on odd ranks → umount -f + rmmod all → census P142-DWORK-LASTREF / P202-LEAKED / P6G-REL-STALE-TEARDOWN per node. Exit 0 = no leaks. Leaves cluster torn down (re-preps each cycle itself).

## IMMEDIATE next steps (RULE 4 order)
1. Deploy 310 (any prep does it — tree build is copied by prep_cluster).
2. A/B: `tests/census_p.sh N "echo 0 > /sys/module/mxfs/parameters/teardown_arm_gate"` then `tests/teardown_leak_repro.sh 8 4` seeking the captured signature (P6G-REL-STALE + P142-DWORK-STALE pag=NULL + P142-DWORK-LASTREF). Note: repro script re-preps each cycle which RESETS the knob to default 1 — set gate=0 AFTER each cycle's prep, or export MXFS_EXTRA_MODARGS='teardown_arm_gate=0' for the prep (prep_node.sh consumes MXFS_EXTRA_MODARGS).
3. Then gate=1 (default) same cycles: expect P6G-REL-STALE-TEARDOWN lines, zero P142-LASTREF/P202.
4. Full 32-board regression on 310 (chunks A-D as usual). Expect 20/21 (dir_reuse pace).
5. Ledger: D-DWORK-TEARDOWN-LASTREF-LEAK dispositions on the A/B outcome (entry has full analysis_sess36 field).

## Session-36 full context
See ccmemory: sess36-three-closures-board-green-10-open, sess36-unmount-leak-ROOT-bast-notify-qfalse, sess36-END-matrix-caw-column-green-309, sess36-FINAL-mount-degrades-closed-9-open. CHANGELOG through 310. 
**5 defects closed this session** (COLDREAD, MKDIR-LOSS, CAW-YIELD, UNMOUNT-BUSY-INODES, MOUNT-DEGRADES); 2 split out (DIRVIEW-NONCONVERGE, DWORK-TEARDOWN-LASTREF). **9 OPEN**. Criteria: NOT production ready.
