---
name: ccloop-c7ee71c6-sess179-B1-LANDED-464-board-PASS-new-defect-dirty-slice-release
description: sess179: #14 B1 LANDED+verified (0.11.464 sv 66F51D07, board 27/27, 0 spurious); vergate mixed_build arm added — refusal PASS, exposed NEW critical D…
metadata:
  type: project
---

# sess179 — B1 landed, B4 arm built, new critical defect found

## B1 (D-MIXED-VERSION-UNGATED-REPLAY) — DISCHARGED
0.11.464 (sv 66F51D070BC971F72E39387) deployed 32/caw, full board 27/27
applicable PASS (runs 20260810T060719Z chunk1 15 tests + 061402Z chunk2 12
tests), 0 spurious "C7 protocol admission" alerts on all 32 nodes.
Implementation:
- xfs_mount.h: bool m_mxfs_proto_admitted (after m_mxfs_cluster_proto_gen).
- xfs_super.c fill_super: set after C7 gate chain (~3059) for both admitted
  envelope branches; else-branch of has_envelope if (~3125) for plain XFS.
- xfs_log.c: static mxfs_assert_proto_admitted() (envelope && !admitted ->
  alert + -EPROTO), called pre-xlog_recover (goto out_destroy_ail),
  pre-xlog_recover_finish, and at mxfs_xlog_recover_foreign_slice entry.

## B4 — PARTIAL: tests/vergate.sh mixed_build arm (new)
Stamps envelope cluster_proto_gen +1 (stamp_gen helper), dirty log via
fsync + XFS_IOC_GOINGDOWN NOLOGFLUSH (ioctl 0x8004587d flag 2) + umount.
Refusal legs PASS: gen+1 mount refused rc=32, ZERO recovery lines; gen
restored -> SAME dirty log replays ("Starting recovery"). Durability leg
FAILS (file=0) -> new defect below. B4 closes when arm fully PASS.

## NEW: D-SHUTDOWN-UMOUNT-CLEAN-RELEASE-DIRTY-SLICE (critical, ledgered)
Umount of a forced-shutdown fs logs "released heartbeat slot 0 (clean
teardown)" while the slice is DIRTY. Remount = pass-2 fresh claim ADOPTED,
P227-TOKENSUM untagged=7 wskip=7, ATOMIC-SKIP -> fsync'd file LOST. No
death -> no survivor election. Violates "only completed recovery produces
a CONSUMABLE sector". Distinct from D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE
(clean release consumes stamp even if pass-1 worked). Next: RULE-5 consult
(shared with #10 item 1) on teardown state + who replays; then fix; verify
= mixed_build arm PASS.

## Notes
- Loop-device mounts: no PR support, single_node=true, writes UNTAGGED
  (tokened=0) — token minting inactive on loop rigs.
- Board split into 2 foreground chunks (15+12 tests) fits 10-min cap;
  walls 494s/523s from timestamps.
- Ledger now 71 records / 28 open (new entry appended, #14 next refreshed).
