---
name: ccloop-c7ee71c6-sess36-FINAL-mount-degrades-closed-9-open
description: sess36 FINAL: MOUNT-DEGRADES closed (rmrf residual = first-run-vs-rerun detector artifact, matched-tree control); 9 OPEN; 5 closures this session
metadata:
  type: project
---

# sess36 FINAL addendum (after the END note): D-MOUNT-DEGRADES-WITH-USE closed

## The rmrf-residual attribution (do not re-walk)
sustained_load's rmrf phase deletes THE PREVIOUS RUN'S tree (test source line ~77 says so explicitly). Every historical "fresh fast" rmrf (5-15ms) was a FIRST run deleting nothing; every "aged slow" one (~0.7-1.6s) was a re-run deleting ~640 cross-node-created entries. Controls on 309:
- 6-run series: 10(first)/1133/701/1253/1583/1309ms — flat in aging dose (including a back-to-back re-run with ZERO aging), binary in tree-presence.
- Idle 4min: no decay (not a backlog). ag_strand_repair: no reset (killed the board-order hypothesis — board chunk-D rmrf 7-13ms was fast because each board's sustained_load is its mount's FIRST).
- MATCHED-TREE control (GPT's closure gate): fresh mkfs, 3 consecutive runs → 7ms / 1354ms / 1414ms. Fresh-with-tree INSIDE the aged band. Mount age severed.
The real 1.3s delete cost = delete-side face of D-32NODE-SHARED-DIR-CREATE-PACE (recorded there; that entry now tracks create AND delete faces).

## Session totals (sess36)
- 5 defects FIXED AND VERIFIED: COLDREAD-STALE-SPLIT, SILENT-MKDIR-LOSS, CAW-YIELD-STARVATION, UNMOUNT-BUSY-INODES, MOUNT-DEGRADES-WITH-USE.
- 2 honest splits opened: DIRVIEW-NONCONVERGE-SESS25, DWORK-TEARDOWN-LASTREF-LEAK.
- 12 → 9 OPEN. Builds 305-309. Boards 306+308 = 20/21. Matrix caw column green 1-16, 32=20/21.

## The 9 OPEN (attack notes in the sess36-END memory)
PACE: DIR-REUSE-32-FLAKY, SHARED-DIR-CREATE-PACE (now incl. delete face), READDIR-PEER-CACHED-DIR-PACE — all = protocol IO per shared-dir handoff; ledger lever = reader-state/writer-gate redesign.
AUTHORITY: INODE-CLUSTER-PUBLISH, RELEASE-BARRIER (umbrella), FOREIGN-REPLAY.
OTHER: MATRIX (rig-blocked columns only), DIRVIEW-NONCONVERGE (repro hunt), DWORK-TEARDOWN-LASTREF (narrow; flush bast wq before pag teardown).

## Rig at handoff
32/caw prepped on 0.11.309 (086FA2DC), mount has 3 sustained_load runs of history. dmesg dirty. Tree==deployed==309. CHANGELOG through 309. Criteria: NOT production ready (9 OPEN).
