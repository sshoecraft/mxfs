#!/bin/bash
#
# MXFS — Build RPM Package (RHEL, AlmaLinux, Rocky, Fedora, SUSE)
#
# Creates a single .rpm containing:
#   - DKMS source (kernel module auto-builds on install and kernel updates)
#   - Userspace tools: mkfs.mxfs, chk_mxfs, resize_mxfs, mxfs_admin
#   - /etc/modules-load.d/mxfs.conf (auto-load at boot)
#   - /etc/udev/rules.d/60-mxfs-blkid.rules (blkid/lsblk detect MXFS)
#   - fsck.mxfs symlink (for fstab fsck dispatch)
#   - an SELinux module giving mxfs the xattr labeling rule XFS has (RPM
#     only: the Debian family ships no SELinux policy by default)
#
# Contents must match mkdeb.sh: an RPM system gets the same package a
# Debian system does.
#
# Usage: ./packaging/mkrpm.sh [output_dir]
# Requires: rpm-build, rpmbuild
#

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTDIR/common.sh"

VERSION=$(mxfs_version)
VERSION_CFLAGS=$(mxfs_version_cflags)
OUTDIR="${1:-$SRCDIR}"

mxfs_banner "Building .rpm package"

# Check for rpmbuild
if ! command -v rpmbuild &>/dev/null; then
    echo "ERROR: rpmbuild not found. Install rpm-build:"
    echo "  dnf install rpm-build    # RHEL/Fedora"
    echo "  zypper install rpm-build # SUSE"
    exit 1
fi

# Set up rpmbuild tree in /tmp
RPMBUILD="/tmp/mxfs-rpmbuild-$$"
rm -rf "$RPMBUILD"
trap 'rm -rf "$RPMBUILD"' EXIT
mkdir -p "$RPMBUILD"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
echo "--- Creating source tarball ---"
TARDIR="/tmp/mxfs-${VERSION}"
rm -rf "$TARDIR"
mkdir -p "$TARDIR"

# Kernel module source
mxfs_stage_kmod_source "$TARDIR/src"
sed "s/__VERSION__/$VERSION/" "$SCRIPTDIR/dkms.conf" > "$TARDIR/src/dkms.conf"

# Tool source
mkdir -p "$TARDIR/tools"
cp "$SRCDIR/tools/mkfs_mxfs.c" "$TARDIR/tools/"
cp "$SRCDIR/tools/chk_mxfs.c" "$TARDIR/tools/"
cp "$SRCDIR/tools/resize_mxfs.c" "$TARDIR/tools/"
cp "$SRCDIR/tools/mxfs_admin.c" "$TARDIR/tools/"
cp "$SRCDIR/tools/mxfs_offline.h" "$TARDIR/tools/"
cp "$SRCDIR/tools/mxfs_lu_reset_witness.py" "$TARDIR/tools/"
cp -r "$SRCDIR/include" "$TARDIR/tools/"

# udev rule
mkdir -p "$TARDIR/udev"
cp "$SCRIPTDIR/60-mxfs-blkid.rules" "$TARDIR/udev/"

# SELinux labeling rule
mkdir -p "$TARDIR/selinux"
cp "$SCRIPTDIR/mxfs.cil" "$TARDIR/selinux/"

# modprobe config: TCP transport, the released configuration
mkdir -p "$TARDIR/modprobe"
cp "$SCRIPTDIR/mxfs-modprobe.conf" "$TARDIR/modprobe/mxfs.conf"

# Man pages
mkdir -p "$TARDIR/docs/man/man5" "$TARDIR/docs/man/man8"
cp "$SRCDIR"/docs/man/man8/*.8 "$TARDIR/docs/man/man8/"
cp "$SRCDIR"/docs/man/man5/*.5 "$TARDIR/docs/man/man5/"

tar czf "$RPMBUILD/SOURCES/mxfs-${VERSION}.tar.gz" -C /tmp "mxfs-${VERSION}"
rm -rf "$TARDIR"

# Generate spec file
echo "--- Generating spec file ---"
cat > "$RPMBUILD/SPECS/mxfs.spec" << SPECEOF
# The tools build without -g, so there is no debug source to package, and an
# EL8+ rpmbuild fails the whole build on the empty debugsource list.
%global debug_package %{nil}

Name:           mxfs
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        MXFS — Multinode XFS shared filesystem
License:        GPL-2.0-only
Source0:        mxfs-${VERSION}.tar.gz

BuildRequires:  gcc make
Requires:       dkms
Requires:       kernel-devel
Requires:       python3
Recommends:     iscsi-initiator-utils

%description
Shared/clustered filesystem for concurrent multi-node access to
XFS-formatted block devices. Features DLM-based coordination with
CAW (disk) or TCP (network) transport, per-inode lock caching,
on-disk journaling, and zero-config UDP multicast peer discovery.

%prep
%setup -q

%build
cd tools
gcc -Wall -Wextra -O2 -Iinclude ${VERSION_CFLAGS} -o mkfs.mxfs mkfs_mxfs.c
gcc -Wall -Wextra -O2 -Iinclude ${VERSION_CFLAGS} -o chk_mxfs chk_mxfs.c
gcc -Wall -Wextra -O2 -Iinclude ${VERSION_CFLAGS} -o resize_mxfs resize_mxfs.c
gcc -Wall -Wextra -O2 -Iinclude ${VERSION_CFLAGS} -o mxfs_admin mxfs_admin.c

%install
# DKMS source
mkdir -p %{buildroot}/usr/src/mxfs-%{version}
cp -a src/* %{buildroot}/usr/src/mxfs-%{version}/

# Tools
mkdir -p %{buildroot}/usr/sbin
install -m 755 tools/mkfs.mxfs %{buildroot}/usr/sbin/mkfs.mxfs
install -m 755 tools/chk_mxfs %{buildroot}/usr/sbin/chk_mxfs
install -m 755 tools/resize_mxfs %{buildroot}/usr/sbin/resize_mxfs
install -m 755 tools/mxfs_admin %{buildroot}/usr/sbin/mxfs_admin
ln -sf chk_mxfs %{buildroot}/usr/sbin/fsck.mxfs
# the witnessed LOGICAL UNIT RESET helper the module upcalls (see mkdeb.sh)
install -m 755 tools/mxfs_lu_reset_witness.py %{buildroot}/usr/sbin/mxfs_lu_reset_witness.py

# Man pages
mkdir -p %{buildroot}/usr/share/man/man5
mkdir -p %{buildroot}/usr/share/man/man8
for page in docs/man/man8/*.8; do
    gzip -9 -c "\$page" > %{buildroot}/usr/share/man/man8/\$(basename "\$page").gz
done
for page in docs/man/man5/*.5; do
    gzip -9 -c "\$page" > %{buildroot}/usr/share/man/man5/\$(basename "\$page").gz
done

# Module auto-load
mkdir -p %{buildroot}/etc/modules-load.d
echo "mxfs" > %{buildroot}/etc/modules-load.d/mxfs.conf

# udev rule: blkid/lsblk/mount (no -t) recognize MXFS by its on-disk magic
mkdir -p %{buildroot}/etc/udev/rules.d
install -m 644 udev/60-mxfs-blkid.rules %{buildroot}/etc/udev/rules.d/60-mxfs-blkid.rules

# Transport: TCP is the released configuration
mkdir -p %{buildroot}/etc/modprobe.d
install -m 644 modprobe/mxfs.conf %{buildroot}/etc/modprobe.d/mxfs.conf

# SELinux: loaded in %post where the host has SELinux tooling
mkdir -p %{buildroot}/usr/share/selinux/packages
install -m 644 selinux/mxfs.cil %{buildroot}/usr/share/selinux/packages/mxfs.cil

%post
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger --subsystem-match=block 2>/dev/null || true
# installed into the policy store even while SELinux is disabled, so a host
# that enables it later labels MXFS from its first boot enforcing
if command -v semodule >/dev/null 2>&1; then
    semodule -i /usr/share/selinux/packages/mxfs.cil ||
        echo "mxfs: the SELinux module did not load; files on MXFS stay unlabeled_t" >&2
fi
# The module build runs last and decides the scriptlet's exit status: a
# scriptlet's status is its last command's, so a build failure followed by
# anything else was reported as a successful install with no module.  RPM
# cannot undo an install from %post; a non-zero exit is what makes rpm and
# dnf report the failure.
dkms add -m mxfs -v %{version} 2>/dev/null || true
# Build for every installed kernel that has headers, not only the running
# one: Requires: kernel-devel installs the NEWEST kernel's headers, which is
# not the running kernel on a node that has not rebooted since an update.
built=0
for kdir in /lib/modules/*; do
    k=\${kdir##*/}
    [ -e "\$kdir/build/Makefile" ] || continue
    echo "Building MXFS %{version} for kernel \$k ..."
    if ! dkms build -m mxfs -v %{version} -k "\$k" || ! dkms install -m mxfs -v %{version} -k "\$k"; then
        echo "ERROR: MXFS %{version} did not build for kernel \$k; see /var/lib/dkms/mxfs/%{version}/build/make.log" >&2
        exit 1
    fi
    built=\$((built + 1))
done
if [ "\$built" = 0 ]; then
    echo "ERROR: no installed kernel has headers; install kernel-devel for your kernel" >&2
    exit 1
fi
if [ ! -e "/lib/modules/\$(uname -r)/build/Makefile" ]; then
    echo "NOTE: the running kernel \$(uname -r) has no headers, so MXFS was built for the"
    echo "      other installed kernels only. Reboot into one of them, or install"
    echo "      kernel-devel-\$(uname -r) and run: dkms install -m mxfs -v %{version}"
fi

%preun
dkms remove -m mxfs -v %{version} --all 2>/dev/null || true

%postun
udevadm control --reload-rules 2>/dev/null || true
# \$1 is 0 on erase, 1 on upgrade: an upgrade's %post has already loaded the
# new module, so only an erase removes it
if [ "\$1" = 0 ] && command -v semodule >/dev/null 2>&1 && semodule -l 2>/dev/null | grep -qx mxfs; then
    semodule -r mxfs
fi

%files
/usr/src/mxfs-%{version}/
/usr/sbin/mkfs.mxfs
/usr/sbin/chk_mxfs
/usr/sbin/resize_mxfs
/usr/sbin/mxfs_admin
/usr/sbin/fsck.mxfs
/usr/sbin/mxfs_lu_reset_witness.py
/usr/share/man/man5/*.5.gz
/usr/share/man/man8/*.8.gz
/etc/modules-load.d/mxfs.conf
/etc/udev/rules.d/60-mxfs-blkid.rules
%config(noreplace) /etc/modprobe.d/mxfs.conf
/usr/share/selinux/packages/mxfs.cil
SPECEOF

# Build RPM
echo "--- Building RPM ---"
rpmbuild --define "_topdir $RPMBUILD" -bb "$RPMBUILD/SPECS/mxfs.spec"

# Copy output
RPM_FILE=$(find "$RPMBUILD/RPMS" -name "mxfs-*.rpm" | head -1)
if [ -n "$RPM_FILE" ]; then
    cp "$RPM_FILE" "$OUTDIR/"
    echo ""
    echo "Package: $OUTDIR/$(basename "$RPM_FILE")"
    echo ""
    echo "Install with:"
    echo "  sudo dnf install ./$(basename "$RPM_FILE")   # RHEL/Fedora"
    echo "  sudo zypper install ./$(basename "$RPM_FILE") # SUSE"
else
    echo "ERROR: RPM build failed"
    exit 1
fi
