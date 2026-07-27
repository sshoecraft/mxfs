---
name: ccloop-c7ee71c6-sess11-B-withdraw2-membership-fix-and-boards
description: sess11: withdraw@2 survivor-shutdown FIXED (dead node never left lease membership; unregister-at-recovery-complete + P164 dead-set gates). v0.11.111…
metadata:
  type: project
tags: [withdraw, membership, dlm, lease, rule6-disposition, boards]
---

# sess11 — withdraw@2 membership fix (v0.11.109→111, srcver A3D8E7A1078425C8281B2CF)

## Defect (RULE 4 proven, first-ever withdraw@2 run)
Survivor (test2) force-shut down 220s after a clean P163 recovery: root-dir ino=128 PR
acquire retried against `master=<withdrawn node>` (P-LKTIMEOUT-REMOTE ×~180, P34-ACQ-SLOW
dur_ms=184522) → rc=-110 → "DLM inode lock unrecoverable" → SHUTDOWN_CORRUPT_INCORE.
Cause chain: TCP mastership = active_nodes[hash % count] where active_nodes ⇐
mxfs_lease_get_active_nodes (ACTIVE|JOINING only). The P163 withdraw/death recovery path
(v5_lease_expire_cb → recovery_complete/v5_recovered_cb) purged DLM state but NEVER
`mxfs_lease_unregister_node` — and the zombie (force-shutdown FS stays mounted) kept its
discovery announces + lease renewals running, so its lease entry stayed ACTIVE forever.
At N=2 root ino hashes to the victim w/ p=1/2 and no membership churn ever remasters.
(N≥16 passes were partial-coverage luck: grant caching + 1/N exposure.)

## Fix (dlm/v5_mount.c + dlm/lease.c)
1. `mxfs_lease_unregister_node(dead)` in BOTH `mxfs_v5_dlm_recovery_complete` (elected)
   and `v5_recovered_cb` (deferred survivors) — before their refresh. Placement matters:
   unregister only at recovery completion, AFTER the slice replay, preserving the sess9-D2
   freeze (mastership must not migrate off the dead node while its journal is unreplayed).
2. P164 dead-identity set (`dead_nodes[32]` ring in mxfs_v5_dlm): noted at fence
   (expire cb), declare_dead, GOODBYE. Gates: v5_discovery_peer_cb + v5_peer_connect_cb_tcp
   reject retired ids (P164-DEAD-REJECT). NO filtering in v5_refresh_active_nodes
   (deliberate — would remaster at fence time, re-opening the torn window; comment in code).
   Node ids are per-mount random uuids → dead id never legitimately returns; rejoin = new id.
3. Victim: mxfs_discovery_stop at withdraw (announce silence). Lease RENEWALS deliberately
   left running — they hold the entry ACTIVE until the complete-unregister = D2 freeze
   (stopping them made survivors SUSPECT the victim ~2s in → remaster 4s pre-replay-complete,
   measured). Post-unregister renewals ignored ("unknown node", now pr_warn_ratelimited).
4. tests/withdraw_recovery_test.sh: CREATOR default test6→test$N (was silently populating a
   bare mountpoint at N<6); creator==victim → exit 2.

## Verified (RULE 6: FIXED AND VERIFIED)
- withdraw@2 PASS ×3 across .109/.110/.111; withdraw@4 PASS; withdraw@16 PASS (115s).
- Freeze ordering proven in-trace (.111): slice replay done 478.588 → flush#2 → purge+
  unregister 478.613 → MEMBERSHIP active_count=1 478.614 → COMPLETE banner 483.14 (the
  4.5s gap = disklock_purge_node zeroing lock records, NOT late replay). Zombie renewals
  arrive ~500ms post-unregister and are ignored. NOTE for future readers: the
  "peer joined — flushing" prints during recovery are mxfs_dlm_peer_joined_flush REUSED
  by the foreign-replay worker (before+after slice) — NOT a membership join.

## Boards at v0.11.111 (A3D8E7A1) — ALL VERIFIED-DEPLOY
- 1/tcp 15/15 applicable (dlm_membership/fence/netpartition/tcp_dlm_scaling are
  min_nodes=2 in criteria.json — structurally N/A at 1).
- 2/tcp 19/19 + withdraw. 4/tcp 19/19 + withdraw. 16/tcp 20/20 + withdraw
  (fio_perf_vs_xfs FAILed once in-chunk at host load ~100 — seqW 64%<70%; standalone at
  load 44 → seqW 695MiB/s PASS. Same clyde-saturation disposition as sess10's 32-node flaps).
- 32/tcp NOT re-verified at .111 (still at .108 standalone-green; test17-32 destroyed).
  Low-risk delta but re-run withdraw@32 + dlm_scaling@32 when VMs are up next.

## Watch items added
- W-replay-agmeta: foreign replay writes AG meta w/o cluster AG locks (PROBE-A
  AG-META-WRITE-NOT-HELD storms during every recovery). Dead grants are frozen but
  OTHER survivors' AG EX grants are not — concurrent survivor-writer vs replayer is
  theoretically possible at N≥3. No observed failure; needs a targeted test someday.
- criteria.pve.json + criteria.physrig-2tcp.json exist for the physical-PvE phase
  (user: the two physical PvE boxes are powered on — test on them after VM matrix).
