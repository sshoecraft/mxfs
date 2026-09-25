---
name: user-platform-priority-proxmox-rhel-ubuntu-debian
description: USER 2026-09-25: platform priority Proxmox, RHEL, Ubuntu, Debian. Plan: Debian next, then focus on CAW. SLES is the expensive port.
metadata:
  type: user
tags: [platforms, roadmap, priority]
---

The user ranked MXFS target platforms (2026-09-25), recorded in data/platforms.json priorities:

1. Proxmox VE — MXFS lets Proxmox compete almost directly with VMware; the product's reason to exist.
2. RHEL family (Alma/Rocky/Oracle) — largest enterprise Linux share (~43%).
3. Ubuntu LTS (~34%).
4. Debian (~16%) — cheap: same .deb/DKMS as Ubuntu/PVE, PVE 9 is Debian 13 userspace, stock kernel 6.12 sits between kernels already built.

THE PLAN (user, same day): once the 2/TCP stall defect on RHEL is settled, Debian is the next platform; after Debian, the focus moves to 2-node CAW.

Why: enterprise Linux server share plus the VMware exodus to shared-SAN KVM hosts.
SLES 16 was agreed to be the costlier port: KMP not DKMS, unsupported-module load refusal by default, SELinux switch, no free subscription (openSUSE Leap 16 as stand-in).
