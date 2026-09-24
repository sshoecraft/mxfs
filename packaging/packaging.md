# MXFS Packaging

## Overview

The packaging system builds distributable packages for MXFS. Each package contains:
- **DKMS kernel module source** — auto-compiles on install and on kernel updates
- **Userspace tools** — mkfs.mxfs, chk_mxfs, resize_mxfs, fsck.mxfs (symlink)
- **Boot config** — /etc/modules-load.d/mxfs.conf for auto-loading the module

## Quick Start

```bash
# On the target machine (with NFS-mounted source):
cd /src/mxfs
make package              # builds .deb or .rpm depending on OS
sudo dpkg -i mxfs_*.deb  # Debian/Ubuntu
sudo dnf install mxfs-*.rpm  # RHEL/Fedora
```

After install, no NFS source mount is needed — the package is self-contained.

## Release Builds

`make package` builds for the machine it runs on, and its tools link against
that machine's glibc. That is fine for a local install but wrong for a release:
tools built on a newer distribution refuse to start on an older one.

`scripts/release.sh` builds every release package into `dist/<version>/`, each
in a container of the OLDEST distribution it targets — Debian 12 for both
.debs (Debian 12+, Ubuntu 24.04+, Proxmox 8+), AlmaLinux 8 for the RPM.
`scripts/release.sh --publish` then creates the GitHub release with the .deb
packages, the RPM and `SHA256SUMS` attached. The RPM is built on EL8 so its
tools run on EL8's glibc and everything newer; its DKMS build compiles the
module against the host's own kernel headers, and the build-time API probes
(`pal/linux/kcompat_probe.sh`) adapt it to what that kernel carries.

The RPM also installs `/usr/share/selinux/packages/mxfs.cil` and loads it with
`semodule` in `%post`: an `fs_use_xattr` rule for `mxfs`, the rule XFS has, so
files carry real labels instead of `unlabeled_t`. As on XFS, a newly made
filesystem's root has no label until `restorecon` gives it one; new files
inherit from their directory.

## Package Formats

| OS Family | Package | Builder | Status |
|-----------|---------|---------|--------|
| Debian/Ubuntu/Proxmox | .deb | mkdeb.sh | Done |
| RHEL/AlmaLinux/Rocky 9 | .rpm | mkrpm.sh | Released (9.8 kernel, DKMS from EPEL) |
| Fedora, RHEL 8/10 | .rpm | mkrpm.sh | Not verified |
| SUSE/openSUSE | .rpm | mkrpm.sh | Untested |
| FreeBSD | .pkg | — | Needs porting |
| macOS | .pkg | — | Needs porting |

## Proxmox VE Storage Plugin

Separate package: `pve-storage-mxfs_X.Y.Z_all.deb`

Built by: `packaging/mkdeb_pve.sh`

Installs `PVE::Storage::Custom::MXFSPlugin` which adds MXFS as a storage type
in the Proxmox web UI. After install:

```bash
pvesm add mxfs mxfs-shared --blockdevice /dev/sdX --path /mnt/pve/mxfs-shared --shared 1 --content images,rootdir,iso,backup
```

Or via web UI: Datacenter -> Storage -> Add -> MXFS

The plugin handles modprobe, mount/unmount, and storage activation. It delegates
volume operations (disk images, ISOs, backups) to the directory plugin since MXFS
presents a POSIX filesystem.

## How It Works

`make package` calls `packaging/mkpackage.sh` which auto-detects the OS family
and dispatches to the platform-specific builder.

### DKMS Flow

On `dpkg -i` / `rpm -i`:
1. Source placed in `/usr/src/mxfs-VERSION/`
2. postinst (.deb) / `%post` (.rpm) runs `dkms add`, then `dkms build` +
   `dkms install` for every installed kernel whose headers are present — not
   only the running one, since the header dependency pulls in the newest
   kernel's headers
3. A build failure fails the script with the path of `make.log`. The .deb's
   configure step fails; RPM cannot undo an install from `%post`, so rpm and
   dnf report the scriptlet failure. The RPM's DKMS build runs last in `%post`,
   because a scriptlet's exit status is its last command's.
4. On kernel update, DKMS automatically rebuilds

### Auto-Mount at Boot

After installing the package, add an fstab entry:
```
/dev/sdX  /mnt/shared  mxfs  _netdev  0  0
```

The `_netdev` option tells systemd to wait for network (and iSCSI) before mounting.
Combined with `modules-load.d/mxfs.conf` and iSCSI auto-start, the filesystem
comes up automatically on reboot.

## Files

- `common.sh` — shared functions (version extraction, source staging, OS detection)
- `dkms.conf` — DKMS configuration template
- `mkpackage.sh` — auto-detecting entry point (called by `make package`)
- `mkdeb.sh` — Debian/Ubuntu .deb builder
- `mkdeb_pve.sh` — Proxmox VE storage plugin .deb builder
- `mkrpm.sh` — RPM builder (RHEL, Fedora, SUSE)
- `mxfs.cil` — the SELinux labeling rule the RPM loads

## Dependencies

### Build-time (on the machine running `make package`)
- gcc, make
- dpkg-deb (Debian) or rpmbuild (RPM)

### Install-time (on the target machine)
- dkms
- linux-headers for the running kernel
- open-iscsi (recommended, for iSCSI shared storage)

## Version

Version is read from the top-level `VERSION` file (`mxfs_version` in
`common.sh`). The `MXFS_VERSION_*` defines in `include/mxfs/mxfs_common.h` are
a legacy fallback only.

## History

- v0.8.2: Initial packaging with DKMS .deb builder
- v0.8.3: Added .rpm builder, PVE storage plugin, auto-detect OS, Bug 105 fix (TCP keepalive)
