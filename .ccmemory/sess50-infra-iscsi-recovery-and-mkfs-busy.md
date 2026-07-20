---
name: sess50-infra-iscsi-recovery-and-mkfs-busy
description: sess50 (run14d) INFRA: after FS shutdowns, 3 VMs (test5/9/14) failed virsh-start (iSCSI LUN dead ENXIO) — fix = iscsiadm logout+login of disk1n{5,9,1…
metadata:
  type: project
---

# sess50 (ccloop 14d31183) — INFRA recovery notes (cluster wedged after FS shutdowns)

After test_cross_write_read corrupted dir-444 and shut down the FS on several nodes, the cluster needed full recovery. Two distinct infra wedges hit:

## 1. VMs fail to virsh-start: iSCSI LUN dead (ENXIO)
test5/test9/test14 went to `shut off` and `virsh -c qemu:///system start testN` failed:
`Could not open '/dev/disk/by-path/ip-127.0.0.1:3260-iscsi-iqn.2026-05.local.mxfs:disk1nN-lun-0': No such device or address`.
The by-path symlink existed (→ sdf/sdj/sdo) and the iSCSI session was logged-in, but `dd if=/dev/sdf` gave ENXIO — the SCST-backed LUN was dead. `iscsiadm --rescan` did NOT fix it.
**FIX (worked):** logout+login the affected targets on clyde:
```
for t in disk1n5 disk1n9 disk1n14; do
  sudo iscsiadm -m node -T iqn.2026-05.local.mxfs:$t -p 127.0.0.1:3260 --logout
  sudo iscsiadm -m node -T iqn.2026-05.local.mxfs:$t -p 127.0.0.1:3260 --login
done
```
After that sdf/sdj/sdo read OK and `virsh start` succeeded. (SCST service stayed `active` throughout — do NOT restart it first; targeted re-login is enough. RULE 2: never reboot clyde.)

## 2. mkfs "device is busy (mounted?)" with nothing mounted
The loaded mxfs module opens /dev/sda at insmod (CAW disklock heartbeat — kworker/R-mxfs threads, module refcount>0), so `mkfs_mxfs /dev/sda` (O_EXCL) fails and `rmmod mxfs` fails "Module in use". Manually prepping nodes (insmod) THEN running reset4 → reset4's `rmmod` (lib.sh fresh_cluster_mount ~245) fails RMMOD_FAIL → insmod File-exists → mkfs busy → RESET_FAIL.
**Correct flow:** do NOT manually prep+insmod before reset4. Use `scripts/cluster_reset_n.sh 16` (virsh destroy+start) so VMs boot with NO module loaded; its prep_tcm_node loads the module, and reset4/fresh_cluster_mount mkfs's on the FIRST node in a window where rmmod succeeds. At 06:50 this session that exact sequence gave `RESET_OK: 16 nodes mounted`.
CAVEAT: cluster_reset_n's parallel `cat prep_tcm_node.sh | ssh 'bash -s'` on 16 nodes at once intermittently PREP_FAILs ~12/16 (NFS read contention on mxfs.ko); running prep SEQUENTIALLY (one node at a time) succeeds on all. And destroy+start can re-trigger wedge #1 (shut-off VMs) → re-login iSCSI + `virsh start` the stragglers, then prep sequentially.

## State at relay boundary
- Build `83C1FB6A6E996A7ECDB68BF` (VERSION 0.5.7) = phantom-EX-waiter fix (VERIFIED earlier) + the P-IFLUSH-DIRTORN producer probe (see [[sess50-cwr-torn-dir444-extents-content-tear]]). Loaded on all 16 nodes but cluster NOT mounted (mkfs-busy).
- NEXT: get a clean mount (cluster_reset_n.sh 16 → if stragglers, iSCSI re-login + virsh start + sequential prep → reset4.sh 16 → binds), then run `POSIX_PHASE=cluster posix_phase_timing.sh --nodes 16` and grep nodes' `journalctl -k` for `P-IFLUSH-DIRTORN ino=444` + its stack to identify the flush path writing the torn LOCAL->EXTENTS dir dinode.
