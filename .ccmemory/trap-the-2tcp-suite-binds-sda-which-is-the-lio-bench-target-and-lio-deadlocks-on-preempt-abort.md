---
name: trap-the-2tcp-suite-binds-sda-which-is-the-lio-bench-target-and-lio-deadlocks-on-preempt-abort
description: TRAP (s173): 2/tcp run.sh defaults DEV=/dev/sda = test32's LIO bench LUN, not the QNAP; LIO deadlocked on PREEMPT AND ABORT of a dead node and crash_…
metadata:
  type: feedback
---

**What happened (2026-09-23, s173, 0.89.78):** the 2/tcp suite FAILed crash_audit (240/300 s) with test2 left off. It looked like an MXFS recovery hang. It was the storage target.

- On test1/test2, `/dev/sda` is the **20 GiB LIO bench LUN on test32** (`iqn.2026-09.mxfs.bench:lun0`, naa.60014054d58465342454e43482d4c554); the QNAP is another disk. `run.sh` defaults DEV=/dev/sda for tcp and the marker recorded `rig=liovm`, so every 2/tcp suite since the bench target was stood up (2026-09-22) ran on LIO — although `data/rigs.json` says the QNAP is the 2/tcp rig's LUN and the bench target is for target-restart laps only. Record: D-2TCP-SUITE-BINDS-SDA-AND-RUNS-ON-THE-LIO-BENCH-TARGET-NOT-THE-QNAP.
- On LIO, PREEMPT AND ABORT against a virsh-destroyed node **deadlocked the target**: `iscsi_trx` in `core_scsi3_pro_preempt → core_tmr_lun_reset → core_tmr_drain_state_list → target_put_cmd_and_wait`, `iscsi_ttx` in `iscsit_close_connection → kthread_stop`, `iscsi_np` in `iscsit_stop_session`. The target then served no initiator at all (test1 IN LOGIN/REOPEN, sda transport-offline for 8+ min). Last night the same lap passed on the same target — it is intermittent.
- MXFS on the survivor did what the design says when its own storage vanishes: P302-PROUT-ABORT-FAIL → P238-FENCE-BLOCKED-AMBIGUOUS → heartbeat stuck in disk read (P278-HB-STALL) → P131-SELF-FENCE AUTHORITY_LEASE_EXPIRED → withdrawal bounded by iSCSI replacement_timeout (P163-WITHDRAW-STAMP rc=-5). The fence retry worker then loops in `msleep` (D state, but voluntary switches rising) — waiting, not deadlocked.

**How to apply:**
- Run 2/tcp verdicts on the QNAP: `MXFS_RIG_TAG=qnap MXFS_DEV=/dev/disk/by-id/wwn-0x6e843b6393a5a6ed918bd4f4fdb8e7d6 ./run.sh 2 tcp ...`.
- When a death lap fails with the survivor self-fenced, **read the target's kernel first** (test32 dmesg / D-state stacks), before any MXFS hypothesis.
- `hostload` in suite lines is clyde's load; 30 on 2026-09-23 came from the user's own job in `~/training/src` (29 python workers) plus the game-server container — not the rig, and not the cause here (test32's own load was 3).
