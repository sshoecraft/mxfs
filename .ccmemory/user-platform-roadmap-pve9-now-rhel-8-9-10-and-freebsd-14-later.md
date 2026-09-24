---
name: user-platform-roadmap-pve9-now-rhel-8-9-10-and-freebsd-14-later
description: USER 2026-09-24: roadmap lives in data/platforms.json. macOS 26 = KERNEL EXTENSION. RHEL family runtime-tested on AlmaLinux VMs (no RHEL subscription…
metadata:
  type: user
tags: [platforms, roadmap, macos, rhel, alma, user-decision]
---

The platform roadmap is the registry itself: `tools/platforms.py` lists every platform with status and priority (ordered by installed base, with the user's adjustments). Read it rather than restating it here.

User decisions that the registry alone doesn't carry:
- **macOS 26 Tahoe is a kernel extension, not a user-space (FSKit) port.** The user is getting an Apple developer account and will do whatever it takes ("I don't care what we have to do, but we'll figure it out"). Don't propose FSKit or user space again.
- **RHEL family: runtime tests on AlmaLinux VMs (alma9-1, alma9-2, built by osimager spec qemu/lab/alma-9.7-x86_64 and dnf-updated to current), not RHEL.** The lab has no Red Hat subscription, so RHEL VMs from the local 9.2 DVD cannot update. AlmaLinux rebuilds the same kernel for each minor release. Build checks run in containers (scripts/rhel_kbuild_check.sh -i almalinux:9, rockylinux:9). The minor release, not the vendor, decides kernel APIs.
- **SLES:** only SLES 16 (6.12). SLES 15 is out.
- RHEL 9 is the target of the release after 0.89.80.
- RHEL 9 guests on QEMU need a CPU model with x86-64-v2. osimager's qemuargs have no -cpu, so builds get qemu64 and the RHEL 9 installer panics ("Attempted to kill init! exitcode=0x00007f00"). The user fixes that in their own osimager session; don't edit /src/osimager.
