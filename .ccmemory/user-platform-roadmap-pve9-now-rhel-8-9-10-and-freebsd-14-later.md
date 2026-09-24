---
name: user-platform-roadmap-pve9-now-rhel-8-9-10-and-freebsd-14-later
description: USER 2026-09-23: releases target Proxmox VE 9 now; RHEL 8/9/10 and FreeBSD 14 wanted in future builds. Platforms live in data/platforms.json.
metadata:
  type: user
---

User, 2026-09-23: "For this build, I'm just looking at Proxmox9. And that's what we're releasing for. ... for future builds, I definitely want to support ... Red Hat 8, 9 and 10 systems, as well as a FreeBSD system, FreeBSD 14."

**How to apply:**
- A release claims only the platforms marked `released` in `data/platforms.json` (today: `pve9`). README, release notes and package descriptions must not claim more than that.
- `tools/platforms.py check --version V` must pass before `scripts/release.sh --publish`; record each verification with `tools/platforms.py verify <platform> --version V --evidence <dir>`.
- Future work, in order of effort: RHEL 9 (5.14 with backports — shims must key on what the kernel provides, not LINUX_VERSION_CODE; alma-97 at 192.168.120.187 is the test VM), RHEL 10 (6.12), RHEL 8 (4.18, widest gap). FreeBSD 14 is a port, not a build target: a new VFS frontend over the pal/ abstraction — scope it as such, never as "shim work".
- The RPM is built by release.sh but not published until a RHEL platform is verified.
