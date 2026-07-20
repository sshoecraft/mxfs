---
name: MXFS Test Environment
description: VM cluster, physical nodes, credentials, storage config for MXFS testing
type: reference
---

## VM Environment (libvirt/KVM on clyde)
- 32 VMs: test1-test32, Ubuntu 24.04, 4 vCPU / 4GB each (EXCEPT test2 = 2 vCPU / 2GB — fix before scale tests), bridged to br0. **ALL 32 available to /src/mxfs — cluster is NOT partitioned (2026-06-14).**
- Host: clyde (192.168.1.166 / 192.168.120.1)
- Shared storage: **LIO fileio + tcm_loop, single shared LUN, NO iSCSI** (2026-06-14): `/home/steve/disk.img` (50G) → fileio backstore `mxfs` (write-through) → tcm_loop → host `/dev/sdX`, stable symlink `/dev/mxfs-shared`; device `/dev/sda` in VMs, vendor `LIO-ORG`, model `mxfs`. Built by `scripts/lio_tcm_setup.sh`, wired into VMs by `scripts/wire_vms.sh`. For TCP DLM (no CAW on this stack). AUTHORITATIVE: `.ccmemory/test-cluster-scst-stack.md`. (SCST iSCSI stack torn down 2026-06-14.)
- Credentials: root/<REDACTED-ROTATED>, password file: `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass`
- SSH: `tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "CMD"`
- NFS: 192.168.1.4:/src → /src on VMs (must remount after reboot)
- Deploy: build on dev → VMs mount NFS → insmod /src/mxfs/mxfs.ko
- After 32-node tests: VMs have auto-reconnecting iSCSI. Stop iscsid + delete nodes before single-node tests.

## Physical (Proxmox)
- pve1 (192.168.1.80): Xeon W3520 4-core, 12GB, Proxmox/Debian 13, kernel 6.17.2-1-pve
- pve2 (192.168.1.81): Xeon W3550 8-core, 12GB, same
- QNAP TS-453 Pro (192.168.1.4): 3x 20GB iSCSI LUNs, gigabit. DOES NOT support SCSI CAW — use TCP DLM.
- LUN serial 393a5a6e: pve1=/dev/sdb, pve2=/dev/sdb
- Password: /tmp/.proxmox_pass (<REDACTED-ROTATED>)

## Other Hosts
- z440/serv (192.168.1.5): dev machine (NOT .55)
- solardirector (192.168.1.168): RPi aarch64, kernel 6.1.21-v8+, no kernel headers
- clyde (192.168.1.166): primary dev machine, also has iSCSI to QNAP (/dev/sda)
