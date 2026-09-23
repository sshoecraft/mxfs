---
name: feedback-proxmox-is-the-product-target-a-release-that-does-not-build-on-pve-is-not-a-release
description: USER 2026-09-23: Proxmox VE is the reason MXFS exists (a clustered FS lets PVE compete with VMware). A package that fails on the PVE kernel is not a…
metadata:
  type: feedback
---

User, 2026-09-23, after the 0.89.77 .deb failed its DKMS build on Proxmox VE 9 (kernel 6.17.2-1-pve, `d_hash_and_lookup` no longer public) and I proposed a "known issue" line in the release notes:

> "don't do that known issue line ... The whole reason for us doing this at all is for proxmox. It is the one thing in Proxmox that would allow it to almost directly compete with VMware. A clustered file system."

**How to apply:**
- Proxmox VE is the primary deployment target, not one OS among several. Any release must build, install and mount on the current Proxmox VE kernel before it is published. Never paper over a Proxmox failure with release-note caveats; fix it and ship a new version.
- The rig (test1..test32, clyde) runs Ubuntu's 6.8 kernel, so a clean rig gate proves nothing about the PVE kernel (6.17 on PVE 9.1). Kernel-API drift between the two is the expected failure, not a surprise: check the PVE headers for every kernel symbol a new code path uses.
- The two PVE 9 VMs on clyde (`pve9-1` 192.168.120.194, `pve9-2` 192.168.120.138) are the place to verify a release on Proxmox before publishing.
