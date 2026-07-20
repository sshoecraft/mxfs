---
name: sess14-scst-wedge-host-reboot
description: sess14 (run 14d31183) 2026-06-10 — SCST target wedge root-caused: leaked D-state iscsi_conn_cleanup threads pin device cmd counts, strictly-serialize…
metadata:
  type: project
---

# sess14 — SCST target stack wedge → clyde reboot (2026-06-10)

## Context
Build `9C2D4FA6` (dir RELFLUSH fix from sess13) VERIFIED good: dpn=100 storm via
`scripts/p133_storm_errcap.sh 100` returned expected=1600 visible=1600 silent=0,
zero HOLEs/shutdowns/P108 across 16 nodes. The one residual
`P119-NONEX-FLUSH-SKIP ino=131` was from xfsaild with incore==disk — harmless.

## The failure
`tests/criteria/zero_silent_loss.sh --iters 3 --dpn 100 --mode 1` failed twice,
NOT from mxfs: the SCST target on clyde wedged.

### Mechanism (proven from host dmesg + /proc stacks)
- SCST executes COMPARE AND WRITE and WRITE SAME as strictly-serialized cmds:
  block device, wait for outstanding cmds to drain, exec, unblock.
- A serialized cmd exceeded the initiator 60s timeout → guest EH ABORT_TASK →
  abort can't complete ("deferring ABORT", cmd in EXEC_CHECK_BLOCKING) →
  escalation LUN_RESET → NEXUS_LOSS → conn drop.
- Each conn drop spawns `iscsi_conn_cleanup` kthread stuck FOREVER in
  `close_conn` msleep loop (33 accumulated, all D-state) — they pin command
  refcounts, so the per-device outstanding count NEVER drains again.
- From then on EVERY strictly-serialized cmd (mkfs's WRITE SAME zeroing the
  slot table, any CAW) blocks forever in EXEC_CHECK_BLOCKING **even on a quiet
  LUN**. Ep2 proved this: first WRITE SAME of mkfs starved 60s pre-TM on an
  otherwise idle device right after a fresh session login.
- Visible guest-side as: mount hung in bdev_pipelined_read, 180s read timeouts
  DID_TRANSPORT_DISRUPTED, reservation conflicts (NEXUS_LOSS drops PR regs),
  `P51-INSTR caw ... ret=280` (0x118 = SCSI RESERVATION CONFLICT).
- `systemctl stop scst` hangs "deactivating" (scst_uid stuck in
  scst_acg_del_lun msleep). Module unload impossible (D kthreads). ONLY a
  host reboot clears it. Session logout/login does NOT (leaked state is
  per-device, not per-session).

### Detection recipe (fast)
- `ps -eo stat,comm | awk '$1 ~ /^D/'` on clyde → any `iscsi_conn_cleanup` = wedged.
- `sudo dmesg | grep EXEC_CHECK_BLOCKING` on clyde.
- All VMs share ONE host iSCSI session (host-device passthrough) — one guest's
  EH escalation (LUN reset, nexus loss) hits every node; PR registrations are
  per-I_T-nexus = shared across all 16 VMs.

## Secondary findings
- `scripts/sess88_workload_a_modeN_baseline.sh` flaws: (a) run() kills local
  ssh at timeout but the REMOTE bash keeps running → overlapping iterations
  (two concurrent mkfs+mount pipelines observed on test1); (b) umount/rmmod
  failures are silently ignored before NODE0 does sg_persist --clear + mkfs.
- mkfs_mxfs zeroes the CAW slot table via BLKZEROOUT → one WRITE SAME(16) of
  65600 blocks — a strictly-serialized cmd that's the canonical starvation
  victim/trigger at SCST under concurrent CAW load. Consider chunking or
  regular-write fallback if wedges recur on a HEALTHY target.

## Recovery
`scripts/clyde_boot_recover.sh` — @reboot cron (self-disarming): waits scst +
disk1b target, iscsiadm login (node.startup=manual!), waits /src NFS, then
`ccloop --resume-run <id>` headless. /etc/scst.conf already persists disk1b.

## State at reboot
- zero_silent_loss NOT yet passed (infra-blocked, mxfs side looks fixed).
- Remaining criteria: zero_silent_loss, crash_consistency, fence_during_write,
  scaling_curve, posix_semantics --nodes 16, then full verify_ship.sh.
- After boot: `scripts/cluster_reset_n.sh 16` then re-run zero_silent_loss.

Related: [[test-cluster-scst-stack]], [[sess13 work in resume.md of the run]].
