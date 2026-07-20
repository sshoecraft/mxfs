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

## Package Formats

| OS Family | Package | Builder | Status |
|-----------|---------|---------|--------|
| Debian/Ubuntu/Proxmox | .deb | mkdeb.sh | Done |
| RHEL/AlmaLinux/Rocky/Fedora | .rpm | mkrpm.sh | Done |
| SUSE/openSUSE | .rpm | mkrpm.sh | Done |
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
2. postinst runs `dkms add` + `dkms build` + `dkms install`
3. Module available for the running kernel
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

## Dependencies

### Build-time (on the machine running `make package`)
- gcc, make
- dpkg-deb (Debian) or rpmbuild (RPM)

### Install-time (on the target machine)
- dkms
- linux-headers for the running kernel
- open-iscsi (recommended, for iSCSI shared storage)

## Version

Version is extracted from `include/mxfs/mxfs_common.h`:
```c
#define MXFS_VERSION_MAJOR  0
#define MXFS_VERSION_MINOR  8
#define MXFS_VERSION_PATCH  3
```

## History

- v0.8.2: Initial packaging with DKMS .deb builder
- v0.8.3: Added .rpm builder, PVE storage plugin, auto-detect OS, Bug 105 fix (TCP keepalive)
