---
name: reference-pve9-vms-use-static-ips-find-them-in-the-br0-neighbour-table
description: pve9-1/pve9-2 (PVE 9.1.1) have static IPs .120.194/.120.138; virsh domifaddr (arp/agent) returns nothing — read `ip neigh show dev br0` by MAC.
metadata:
  type: reference
---

The two Proxmox VE 9 VMs on clyde (libvirt `pve9-1`, `pve9-2`; 2 vCPU / 4 GB; PVE 9.1.1, kernel 6.17.2-1-pve at 2026-09-23) are configured with **static IPs** by the Proxmox installer, so they never take a dnsmasq lease and neither `getent hosts` nor `virsh domifaddr --source arp|agent` finds them (no guest agent; br0 is a host bridge, not a libvirt network). A 240 s boot-wait lap burned its whole budget on that lookup.

Find them from clyde's own neighbour table, matched by MAC:
- pve9-1 `52:54:00:cc:8e:c1` → 192.168.120.194
- pve9-2 `52:54:00:17:d1:9b` → 192.168.120.138

`ip neigh show dev br0 | grep -i <mac>`. Root ssh works through `tools/mxfs_sshpass.sh <ip>` with the same lab password as the test nodes.

**Shared disk:** their original XML attached `/dev/mxfs-shared` (the retired LIO/tcm_loop device), which no longer exists, so libvirt refused to start them. On 2026-09-23 that disk was detached from both definitions (`--config`; originals saved in `tests/evidence/pve9_release_0.89.77/*.before-detach.xml`); they now reach the shared LUN by in-guest iSCSI via `scripts/pve_iscsi_login.sh`, the same SCST target as test1/test2.
