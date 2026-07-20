---
name: sess51-scst-caw-read-wedge-full-recovery-proven
description: sess51 (run14d): PROVEN end-to-end recovery of the SCST CAW↔READ atomic wedge + stale-PR-blocks-mkfs, incl. recreating disk1 device after del_device.…
metadata:
  type: project
---

## sess51 (ccloop 14d31183) — SCST wedge full recovery, EXECUTED + PROVEN

The recurring blocker: after FS shutdowns, disk1 has a stale "Write Exclusive, registrants only" PR reservation + 16 ghost registrants. `fresh_cluster_mount`'s `sg_persist --clear` FAILS to clear because **register-ignore won't STICK** (generation increments but key never appears) — root is a **CAW↔READ atomic deadlock** parking all commands behind a device-block. Confirms [[sess47-scst-wedge-pr-recovery-procedure]].

### DO NOT just `del_device disk1` (what I did first — made it worse)
`del_device` → `scst_acg_del_lun` → `scst_wait_for_tgt_devs` = `while(cmds>0) msleep(100)` UNBOUNDED. With commands wedged it spins forever; `scst_uid` (the single SCST sysfs work thread) goes D-state → **ALL SCST mgmt is now blocked** (can't add disk1b targets either). `close_conn`/`iscsi_conn_cleanup` multiply (49) D-state, can't abort atomic-blocked cmds. del removes disk1 from `scst_dev_list` but it stays on scst_vdisk `vdev_list` (mid-`vdisk_del_device`).

### THE WORKING RECOVERY (no host reboot — RULE 2 respected)
1. **Find the wedged cmds** (disk1 is off scst_dev_list → use vdev_list; needs BOTH module symbols):
   `VKO=/lib/modules/$(uname -r)/extra/dev_handlers/scst_vdisk.ko` (NOT .../extra/scst_vdisk.ko).
   `sudo gdb -batch -ex "add-symbol-file scst.ko <.text> -s .data <> -s .bss <> -s .rodata <>" -ex "add-symbol-file $VKO <vdisk .text/.data/.bss/.rodata>" -ex "core-file /proc/kcore" -x scripts/scst_atomic_wedge_diag.py`. Section addrs: `sudo cat /sys/module/scst{,_vdisk}/sections/.{text,data,bss,rodata}` (run cat AS ROOT — `$(cat)` in the gdb line runs unprivileged → "Permission denied").
   → prints disk1 cmds: ONE CAW `op=0x89 blocked_cnt=49`, ONE READ `op=0x28 blocked_cnt=1` (holds the back-edge), 48 READs blocked_cnt=0, all same lba.
2. **Verify cycle**: READ#1.blocked_arr==[CAW] and CAW.blocked_arr[0]==READ#1 (A↔B).
3. **Break it**: `cd scripts/scst_unwedge; sudo insmod scst_unwedge.ko blocker=<READ#1 addr> blocked=<CAW addr>; sudo rmmod scst_unwedge`. (blocker=the READ w/ blocked_cnt=1, blocked=the CAW.) dmesg "edge removed, cmd requeued". INSTANTLY: scst_uid→S, disk1 gone, conn_cleanup→0. Full cascade recovery.
4. **disk1 is now DELETED** — recreate it: `echo 'add_device disk1 filename=/home/steve/disk-1.img;async=1;o_direct=1' > /sys/kernel/scst_tgt/handlers/vdisk_fileio/mgmt`. PR is now generation=0 CLEAN.
5. **Remap LUN 0 → disk1** on all 16 iscsi targets: for t in disk1 disk1n2..disk1n16: `echo 'add disk1 0' > /sys/kernel/scst_tgt/targets/iscsi/iqn.2026-05.local.mxfs:$t/luns/mgmt`. (copy_manager LUN3 add gives I/O error — ignore, VMs don't use it.)
6. **Re-login host iscsi** (host=clyde IS the initiator, IQN iqn.2004-10.com.ubuntu:01:68299635f96d; VMs get the by-path passthrough): for each target `sudo iscsiadm -m node -T iqn.2026-05.local.mxfs:$t -p 127.0.0.1:3260 --login`. by-path symlinks reappear.
7. Start VMs, prep SEQUENTIALLY (parallel prep = NFS contention → most fail NOT_LOADED), run.

### Topology facts
All 16 targets (disk1, disk1n2..16) map LUN0→ONE shared SCST device "disk1" (/home/steve/disk-1.img). disk1b is a SEPARATE clean device on the SAME file but has only 1 target (can't give 16 nodes distinct nexuses without mgmt, which the wedge blocks — so disk1b bypass is NOT viable once mgmt is wedged; unwedge is the only path). Host has the 16 sessions; each = a PR registrant nexus.
