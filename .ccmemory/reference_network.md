---
name: Network topology
description: Clyde has two IPs - 192.168.1.166 (main LAN) and 192.168.120.1 (lab/VM bridge with dnsmasq). Same machine, same iSCSI LUN.
type: reference
---

**clyde** (dev machine) has two network interfaces:
- **192.168.1.166** — main LAN (physical nodes reach iSCSI here)
- **192.168.120.1** — lab/VM bridge network with dnsmasq for DNS (test VMs reach iSCSI here)

Same machine, same `~/iscsi-lun.img`. The 192.168.120.x subnet has a rule on the router for internet access.

VMs use 192.168.120.1:3260 for iSCSI. Physical nodes (pve1, pve2, serv) use 192.168.1.166:3260.
