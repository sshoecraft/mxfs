---
name: ccloop-c7ee71c6-sess47-END-372-closed-fence-shipped
description: sess47 END (0.11.377 ship config): D-REAP-IFREE-372 FIXED+VERIFIED; inocl fence shipped; crash_consistency clean-window PASS; 11 OPEN of 39 (4 crit)
metadata:
  type: project
---

# sess47 END — state for the relay (FINAL, supersedes earlier same-name)

## RIG: 32/caw SHIP CONFIG (icluster_dlm=0, open_tracking=1, inocl_fence=1) on 0.11.377 (C4B4990D457D8BEA45793F2), 32/32 mounted, falsifier sweep CLEAN.
Board green this session: cc 654/654, zsl 644/644, dirent 30r/0loss, rsync_paired 18-22s ×8, matrix 9/9 ×7 (incl. knob=1), **crash_consistency PASS 204/204 [24s/90s] at knob=0/377** (the sess46 queue item — first clean-window pass; start-load gate 13.86; NOTE: outer `timeout` for run.sh must be ~150s = 90s criterion + harness overhead, a 100s outer cap falsely Terminates).

## CLOSED: D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372 → FIXED AND VERIFIED (0.11.375)
mxfs_ifree_unlinked_preflight (predecessor PIN, nonblocking, GPT-hardened). Repro tests/reap_midlist_repro.sh: REPRODUCED-on-374 → CLEAN ×6 across 375-377, both scenarios, both knob configs. Probes P-UNLREM-* permanent.

## SHIPPED: inode-cluster time-travel fence (0.11.377, mxfs.inocl_fence=1 default, 0644)
Closes the decoded rsync-rename producer arm (fossil di_next_unlinked via cold-FUA-read-in-unflushed-window; case file: ...-sess47-rsync-rename-producer-fossil-nextunlinked; ring test2:/root/transcommit_incore_1785706689.dmesg). Soak: 6 aged cycles (incl. one with 260s true-idle gap — the fossil's formation pattern) + knob=1 pass: ZERO P53/shutdowns fleet-wide; fence closed 46+ windows; no perf cost. **P53-IUNLINK-MISMATCH with fence=1 = falsifier.**

## LEDGER: 11 OPEN of 39 (4 critical): FOREIGN-REPLAY-UNGATED-IMAGES (sess17 design ready), INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (campaign: GPT items 2-4, knob=1 clean-load board, default-ON+PROTO_GEN), CROSSNODE-OPEN-UNLINK (TCP arm only), RSYNC-RENAME-361 (fence soaking — promote only after ≥8 more clean aged cycles w/ idle gaps AND P53 stays zero).

## RELAY QUEUE (in order)
1. RSYNC-RENAME-361 fence soak: aged cycles w/ idle gaps (protocol: lap → `tools/mxfs_sshpass.sh test1 "sleep 260"` → lap → matrix → falsifier sweep `dmesg | grep -cE 'P53-IUNLINK|Shutting down|error -117|P-UNLREM-NOPREV'`). Standing rule: any shutdown → `dmesg > /root/<tag>.dmesg` BEFORE recovery.
2. icluster campaign: GPT items 2-4, knob=1 clean-load full board, default-ON decision.
3. FOREIGN-REPLAY (certified replay, sess17 design). 4. TCP rig wiring (CROSSNODE TCP arm + MATRIX-UNMEASURED).

## DO-NOT-RE-DERIVE (sess47)
- Reap-worker authority-flag restore is STRIPPED by inactive-side DLM acquire; key off i_unlinked_bucket (survives).
- xfs_iunlink_lookup ASSERTs !RECLAIMABLE — raw rcu radix probe for walks hitting frozen shells.
- di_next_unlinked = dinode 0x60 (in corruption dumps); not in logged core → survives reuse-create (fossil mechanism).
- P53-IDEMPOTENT carve-out absorbs producer events where old_ptr==next — check its count when hunting.
- MXFS_EXTRA_MODARGS='icluster_dlm=1' MXFS_FORCE_PREP=1 = knob=1 deploy (param 0444 runtime).
- Ledger status convention: OPEN vs {FIXED AND VERIFIED, RESOLVED, DISPROVED, FIXED-VERIFIED} → count OPEN only.
