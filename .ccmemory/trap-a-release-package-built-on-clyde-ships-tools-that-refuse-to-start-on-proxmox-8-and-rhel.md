---
name: trap-a-release-package-built-on-clyde-ships-tools-that-refuse-to-start-on-proxmox-8-and-rhel
description: TRAP (0.89.77): tools built on clyde (Ubuntu 24.04) need GLIBC_2.38; PVE 8 has 2.36, RHEL 9 2.34. Build release pkgs via scripts/release.sh (containe…
metadata:
  type: feedback
---

`make package` / `packaging/mkdeb.sh` run on clyde link `mkfs.mxfs` and `chk_mxfs` against glibc 2.39 and the binaries require **GLIBC_2.38** (`objdump -T | grep GLIBC_`). Proxmox 8 / Debian 12 ships 2.36 and RHEL 9 ships 2.34, so a .deb or .rpm built on the host installs fine and then its tools refuse to start on exactly the systems a release targets. The DKMS module is unaffected (compiled on the target); only the prebuilt userspace tools break.

**How to apply:** release packages come from `scripts/release.sh`, which builds each package in a container of the OLDEST distribution targeted: `debian:bookworm` for both .debs (tools then need 2.34), `almalinux:8` for the RPM (tools need 2.14; `mkfs.mxfs` verified running there). Never attach a host-built package to a release.

Two more traps found building it:
- **docker's bridge network on clyde has no outbound TCP** (image pulls work because the daemon does them; apt/dnf inside a bridged container time out). The build containers use `--network host`. Do not "fix" clyde's firewall for this — the rig depends on it.
- **EL8 rpmbuild fails the whole build** on an empty debugsource list when tools compile without `-g`; the spec needs `%global debug_package %{nil}`.
- `mkrpm.sh` had drifted from `mkdeb.sh` (no `mxfs_admin`, no udev rule, man pages listed by name). When a tool, page or config is added to one builder, add it to the other.
