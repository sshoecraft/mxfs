---
name: test-environment
description: VM cluster, physical nodes, credentials (secrets store), storage config for MXFS testing
metadata:
  type: reference
---

## VM Environment (libvirt/KVM on clyde)
- 32 VMs: test1-test32, Ubuntu 24.04, 4 vCPU / 4GB each (EXCEPT test2 = 2 vCPU / 2GB — fix before scale tests), bridged to br0. **ALL 32 available to /src/mxfs — cluster is NOT partitioned (2026-06-14).**
- Host: clyde (192.168.1.166 / 192.168.120.1). ~94G RAM — 32×4G VMs will NOT all fit at once (batch heavy fleet ops ~8 at a time).
- Shared storage: **LIO fileio + tcm_loop, single shared LUN, NO iSCSI** (2026-06-14): `/home/steve/disk.img` (50G) → fileio backstore `mxfs` (write-through) → tcm_loop → host `/dev/sdX`, stable symlink `/dev/mxfs-shared`; device `/dev/sda` in VMs, vendor `LIO-ORG`, model `mxfs`. Built by `scripts/lio_tcm_setup.sh`, wired into VMs by `scripts/wire_vms.sh`. For TCP DLM (no CAW on this stack). AUTHORITATIVE: `.ccmemory/test-cluster-scst-stack.md`. (SCST iSCSI stack torn down 2026-06-14.)
- **Credentials (rotated 2026-07-21): SOURCE OF TRUTH = `~/.config/mxfslab/secrets`** (mode 600, NOT in the repo — plaintext pw lives ONLY there, never in repo/memory). `tools/mxfs_secrets.sh` resolves it → materializes the sshpass passfile `/tmp/.mxfs_pass`; `tools/mxfs_sshpass.sh` (SSH chokepoint all scripts use) re-resolves from the store if the passfile is missing. Node root pw rotated 2026-07-21 to an 8+ char value (Proxmox 9.x auto-install requires >=8) and kept in sync with osimager's `images/linux` secret so osimager-built nodes match. All 32 test VMs' root pw was updated to match.
- SSH: `tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "CMD"` (passfile auto-resolved from the secrets store)
- NFS: 192.168.1.4:/src → /src on VMs (must remount after reboot)
- Deploy: build on dev → VMs mount NFS → insmod /src/mxfs/mxfs.ko
- After 32-node tests: VMs have auto-reconnecting iSCSI. Stop iscsid + delete nodes before single-node tests.

## New multi-OS/kernel fleet (vms.md, 2026-07-21)
- `lab/vms.md` defines a matrix beyond the Ubuntu-24.04 test1-32 fleet: proxmox-ve-9.1 (pve9-{N}, 6.17), proxmox-ve-8.4 (pve8-{N}), rhel/alma/oel/sles/debian/fedora/ubuntu variants. Built via osimager `mkosimage qemu/lab/<spec> <name>`.
- osimager auto-install status (2026-07-21): Proxmox 9.1 WORKS after boot_command + answer.toml(9.x schema) + 8-char-pw fixes; Fedora 43 boot_command broken (isolinux `<tab>` vs GRUB2 — needs OEMDRV-autodetect fix); Debian 13.3 preseed stalls on dead httpredir mirror + CD apt-setup. Ubuntu 24.04 (subiquity) is the only historically-proven path.

## Physical (Proxmox)
- pve1 (192.168.1.80): Xeon W3520 4-core, 12GB, Proxmox/Debian 13, kernel 6.17.2-1-pve
- pve2 (192.168.1.81): Xeon W3550 8-core, 12GB, same
- QNAP TS-453 Pro (192.168.1.4): 3x 20GB iSCSI LUNs, gigabit. DOES NOT support SCSI CAW — use TCP DLM.
- LUN serial 393a5a6e: pve1=/dev/sdb, pve2=/dev/sdb
- Password: /tmp/.proxmox_pass (kept out of repo; physical pve host creds also in osimager `proxmox/pve*`)

## Other Hosts
- z440/serv (192.168.1.5): dev machine (NOT .55)
- solardirector (192.168.1.168): RPi aarch64, kernel 6.1.21-v8+, no kernel headers
- clyde (192.168.1.166): primary dev machine, also has iSCSI to QNAP (/dev/sda)
