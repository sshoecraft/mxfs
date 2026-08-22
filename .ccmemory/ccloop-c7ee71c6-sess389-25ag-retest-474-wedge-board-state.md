---
name: ccloop-c7ee71c6-sess389-25ag-retest-474-wedge-board-state
description: sess389 END: tree 0.20.0 (mkfs -d cap, MXFS_MKFS_OPTS passthrough, agcount warns), rig 64AG sv 4411027355A6F7FDD3BAF6F; 25-AG retest wedged shared sl…
metadata:
  type: project
tags: [sess389, 0.20.0, agcount, 474, relfence, board, handoff]
---

# sess389 end state

TREE 0.20.0; module sv 4411027355A6F7FDD3BAF6F (== 0.19.42 kernel code; 0.20.0 only added mkfs -d + prep passthrough). RIG: 32/caw, 128 GiB LUN, 64 AGs (default -n 32), all 32 mounted, module 4411.
Board 32/caw: 26 PASS, rsync_paired FLAKY (genuine FAIL recorded during the 25-AG lap; clears by root-cause fix), open_defects POLICY. Ledger 52 open.

## 25-AG correctness retest (MXFS_MKFS_OPTS="-d 50G" prep -> agcount 25)
- mkfs warning fired (agcount 25 < 32, 7 shared slots); mount P-AGCOUNT-COLLISION fired on EXACTLY slots 25-31 (journalctl -k — prep clears dmesg after mount!).
- lap 1 all PASS; lap 2: test7 (slot 30, AG5) and test32 (slot 31, AG6) -> P-AGTRY-LOCALBUSY storms on the shared AG -> P-AILMIN stuck inode items -> P-NOINO-DRAIN-STUCK try=8 -> P-NOINO-RELFENCE-WEDGE -> shutdown -> withdraw; rsync barrier never completed. test26: P87-TARGET-TIMEOUT stage=ilock ocomm=rsync x6 -> P86 split published under protest + P88-PUBOB-UNREPAIRED x3. Mechanism: ILOCK held across the CAW poll for the SHARED home AG pins the AIL-min item / defeats the repair's ilock stage. Same build at 64 AGs: 13 aged laps, 0 wedges.
- Evidence extract: tests/logs/ag25_incident_sess389.txt (full dmesg copies were session scratch). Ledger: D-NOINO-RELFENCE-AIL-FREEZE-474 + D-RSYNC-LAP-PACE-AG-SHARING-388 updated; PACE-388 stays OPEN (ruling: nodes>agcount must be correctness-supported; it is not) until 474's ILOCK-across-CAW-poll root is fixed.
- Restore trap: prep escalated to virsh power-cycles of test1/7/32 (did not release mxfs after shutdown); my 190s wrapper cap killed the d385 wrapper but the orphan run.sh kept /tmp/mxfs_run.lock and finished the prep (~4 min). Never cap a prep under ~300s; wait for the lock holder.

## Harness overhead (RULE 0)
Standalone run.sh single test: ~40s overhead (dirent_durability 67s test -> 106s wrapper; a 100s cap ABORTED it). Use walls + 40s + 12s x (n-1).

## Next
1. #474 root: no ILOCK held across a CAW poll for a contended AG (ruling-2 handoff protocol / ruling-3 inode reserve) — the remaining correctness hole under AG sharing; then re-run 25-AG 3 laps (0 wedge) to close PACE-388.
2. AGI (#1) closure: on-disk AGI unlinked chain-walk audit (chk_mxfs unmounted after a lap, or a tool) per the sess389 ruling.
3. Continue the RULE-6 queue. CRITERIA NOT MET.
