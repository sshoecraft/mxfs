---
name: feedback-never-downloading-kernel-source-does-not-mean-never-installing-kernel-headers
description: USER 2026-09-23: the no-kernel-source rule is about source trees (/src/linux exists); installing header packages on targets or build containers is no…
metadata:
  type: feedback
---

I told the user their rules forbade downloading kernel header packages and proposed dropping the Proxmox container build check. They corrected it:

> "I never, ever said this. In fact, the only way to build a kernel module is you have to download the kernel headers ... Downloading the kernel source is a whole different story. Especially since we already have the kernel source. Downloading the kernel headers on a target system is totally different and I'm not sure why you would conflate the two."

**How to apply:**
- The rule "never download the Linux kernel source" means: no kernel source trees, tarballs or git clones for reading or reference — `/src/linux` is already here.
- Installing `proxmox-headers-*`, `linux-headers-*`, `kernel-devel` on a target VM or inside a throwaway build container (`scripts/pve_kbuild_check.sh`) is how DKMS modules are built and checked, and is fine.
- The .deb declares `proxmox-default-headers | linux-headers-generic | linux-headers-amd64 | linux-headers` so users get headers automatically (0.89.79).
- Read a rule for its purpose before stretching it to block normal engineering; when unsure, ask in one line rather than proposing a workaround.
