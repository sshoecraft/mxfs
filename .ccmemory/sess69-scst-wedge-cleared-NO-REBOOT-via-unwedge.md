---
name: sess69-scst-wedge-cleared-NO-REBOOT-via-unwedge
description: sess69: CLEARED the 1d7h SCST host wedge WITHOUT reboot via scst_unwedge.ko (sess43/47 procedure). Sessions 14-68 wrongly concluded reboot-only.
metadata:
  type: project
---

## sess69 (ccloop 14d31183) — SCST host wedge CLEARED with NO reboot

Sessions 14,15,67,68 (and the sess68 handoff) declared the SCST/iSCSI host wedge
"unrecoverable, only a host reboot fixes it (RULE 2 = user's call)" and sat
blocked for ~5 sessions. **That was WRONG.** The documented sess43/sess47
no-reboot recovery (`scst_unwedge.ko`) applies to THIS exact wedge and cleared it
in seconds. Always run the unwedge procedure before ever concluding "needs reboot".

### The wedge (re-confirmed this session)
- 92 D-state threads, load 92, portal 3260 NOT listening, 90 `iscsi_conn_cleanup`
  in `close_conn` msleep, `iscsi-scstd` in `scst_suspend_activity` (do_exit
  teardown), `modprobe -r scst_vdisk` in `scst_acg_del_lun` msleep. global
  `/sys/kernel/scst_tgt/suspend=1`. Backing sd devs `transport-offline`,
  `inflight=0` (NOT a block-layer hang — pure SCST cmd-state deadlock).
- Root = SCST scsi-atomic A↔B deadlock on vdisk **disk1**: a CAW (op 0x89,
  lba 131089) and one overlapping READ(10) (op 0x28, same lba) each registered
  the other as its `scsi_atomic` blocker; CAW also blocked 88 more readers.
  `scst_suspend_activity` waits forever on those held cmds → all teardown wedges.

### The fix (exact steps that worked — REUSABLE, no reboot)
1. Diagnose (read-only, /proc/kcore). disk1 is mid-unregister so it is OFF
   scst_dev_list — must walk **vdev_list** (needs scst_vdisk.ko symbols at the
   REAL path `/lib/modules/$(uname -r)/extra/dev_handlers/scst_vdisk.ko`):
   ```
   SCST_TEXT=$(sudo cat /sys/module/scst/sections/.text) ... (.data/.bss/.rodata)
   VD_*=$(sudo cat /sys/module/scst_vdisk/sections/.{text,data,bss,rodata})
   sudo gdb -q -batch -ex "set confirm off" \
     -ex "add-symbol-file .../scst.ko $SCST_TEXT -s .data $SCST_DATA -s .bss $SCST_BSS -s .rodata $SCST_RODATA" \
     -ex "add-symbol-file .../dev_handlers/scst_vdisk.ko $VD_TEXT -s .data ... -s .bss ... -s .rodata ..." \
     -ex "core-file /proc/kcore" -x scripts/scst_atomic_wedge_diag.py
   ```
   Find: the CAW (op 0x89, blockers=1, blocked_cnt=large) and the ONE READ whose
   blocked_cnt=1 (it blocks only the CAW). Confirm mutual edges by dumping each
   cmd's `scsi_atomic_blocked_cmds[]` array.
2. Break ONE edge (module self-verifies under dev_lock; -EBUSY no-op if wrong):
   ```
   cd scripts/scst_unwedge
   sudo insmod scst_unwedge.ko blocker=0x<READ> blocked=0x<CAW>   # blocker=READ holding edge, blocked=CAW to requeue
   sudo rmmod scst_unwedge
   ```
   dmesg shows `scst_susp_wait ... returned 0` + `__scst_resume_activity suspend_count 0 left`.
   Instantly: D-state 92→0, conn_cleanup 90→0, modprobe+scstd complete, suspend→0.
3. Restart userspace target (scstd had died in do_exit; scst_vdisk got unloaded):
   `sudo systemctl restart scst` → portal LISTENS on 3260, disk1/disk1b targets back.
4. Re-login loopback backing sessions (idempotent), they auto-reconnect from REOPEN:
   loop `iscsiadm -m node -T iqn.2026-05.local.mxfs:$t -p 127.0.0.1:3260 --login`
   for t in disk1b disk1 disk1n2..disk1n16 → all 17 sd devs go `running`.
   disk1 shared LUN = /dev/sdd on clyde.

This session's actual values: CAW=0xffff8a681dd7e5c0, READ=0xffff8a5ea461a680
(addresses are per-wedge; re-diagnose each time).

### After recovery — proceed to verify the candidate fix
NFS /src/mxfs exported (fsid=4321). test2-16 running, test1 was shut off (start it).
Do clean `scripts/cluster_reset_n.sh 16` + `tests/reset4.sh 16` (deploys module),
then run the 4 failing criteria. Candidate fix to deploy = **2D460CA3** (sess68,
on NFS) per [[sess68-host-loopback-deadlock-and-sharpened-p67-probe]].

Links: [[sess47-scst-wedge-pr-recovery-procedure]] [[sess43-scst-unwedge-and-p136]] [[sess68-host-loopback-deadlock-and-sharpened-p67-probe]]
</body>
