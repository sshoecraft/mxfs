---
name: sess-tcp-dlmfairness-PASS-via-harness-3of3
description: dlm_fairness now PASSes 3/3 via ./run.sh 2 tcp dlm_fairness (build A3E2842C, non-CAW slot claim). The AG0 inobt-corruption wedge is FIXED. Remaining…
metadata:
  type: project
---

## CONFIRMED FIX (build A3E2842CCEF45CB87CF67FD)
`./run.sh 2 tcp dlm_fairness` = PASS 3/3 (nodes_pass=2/2). The non-CAW verified disklock slot
claim (dlm/disklock.c mxfs_disklock_claim_slot_noncaw) gives nodes UNIQUE slots 0,1 → distinct
preferred AGs → no more shared-AG0 inobt freemask corruption / FS shutdown wedge. repro_pm_loop
15× = 14 PASS / 1 got=1 (rare stale-readdir, partly a loop artifact: repro_pm_loop rm-rf's the
shared dir between iters = ABA stale-dir; run.sh mkfs's fresh each run so the harness path is
clean). df_diag 20× caught zero got=1.

## Target is LIO, not SCST
sg_persist shows vendor "LIO-ORG" and NO PR support (register = -EOPNOTSUPP, no-op). So the
SCSI-PR-register I added to the TCP path (v5_mount.c) is a confirmed NO-OP (harmless; can be
removed later). LIO also REJECTS the COMPARE_AND_WRITE CDB (sense 0x5/0x24) — that's why the
CAW slot-claim never worked and the non-CAW fallback is required. (CLAUDE.md dev-notes already
say "LIO target drops FUA / mkfs O_SYNC not durable" — consistent.)

## run.sh prep flakiness (NOT a code bug)
run.sh prep_cluster umount is non-forcing (`umount $MNT 2>/dev/null`, backgrounded); if a prior
run left the mount busy it fails to unmount → mkfs returns 1 → ABORT. Fix between runs:
`fuser -k /mnt/shared; sleep 1; umount; rmmod` (or run tests/setup/reset2_tcp.sh). Consider
hardening run.sh prep umount with fuser -k + retry.

## REMAINING for 2/tcp 100% (showstat 2 tcp): 8 PENDING scripts to port —
dlm_membership(fault), scaling_curve(barrier), dlm_scaling(barrier), rsync_paired(barrier),
crash_consistency(fault), fence_during_write(fault), fault_netpartition(fault),
tcp_dlm_scaling(barrier, tcp manifest). Reference sources in tests/cluster/*.sh. The "fault"
ones (node kill/fence/partition) are hardest — crash_consistency needs foreign-log-replay
(sess17, only 3/6 done). See [[sess-tcp-FIX-noncaw-slot-claim-unique-ags]].
