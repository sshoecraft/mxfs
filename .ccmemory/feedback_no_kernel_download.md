---
name: Never download Linux kernel source
description: Linux kernel source is already at ~/src/linux — never download it again
type: feedback
---

NEVER download the Linux kernel source (debs, tarballs, git clones) for any reason.

**Why:** The full kernel source tree is already available at ~/src/linux (6.19.0-rc0). A previous session downloaded a 357MB linux-source deb into the project directory, wasting space and cluttering the tree.

**How to apply:** If you need kernel headers, XFS source, or any kernel reference code, read it from ~/src/linux/. Never use apt, wget, curl, or any tool to download kernel source packages.
