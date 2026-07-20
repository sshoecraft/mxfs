#!/bin/bash
#
# MXFS — Build RPM Package (RHEL, AlmaLinux, Rocky, Fedora, SUSE)
#
# Creates a single .rpm containing:
#   - DKMS source (kernel module auto-builds on install and kernel updates)
#   - Userspace tools: mkfs.mxfs, chk_mxfs, resize_mxfs
#   - /etc/modules-load.d/mxfs.conf (auto-load at boot)
#   - fsck.mxfs symlink (for fstab fsck dispatch)
#
# Usage: ./packaging/mkrpm.sh [output_dir]
# Requires: rpm-build, rpmbuild
#

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTDIR/common.sh"

VERSION=$(mxfs_version)
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
cp -r "$SRCDIR/include" "$TARDIR/tools/"

# Man pages
mkdir -p "$TARDIR/docs/man/man5" "$TARDIR/docs/man/man8"
cp "$SRCDIR"/docs/man/man8/*.8 "$TARDIR/docs/man/man8/"
cp "$SRCDIR"/docs/man/man5/*.5 "$TARDIR/docs/man/man5/"

tar czf "$RPMBUILD/SOURCES/mxfs-${VERSION}.tar.gz" -C /tmp "mxfs-${VERSION}"
rm -rf "$TARDIR"

# Generate spec file
echo "--- Generating spec file ---"
cat > "$RPMBUILD/SPECS/mxfs.spec" << SPECEOF
Name:           mxfs
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        MXFS — Multinode XFS shared filesystem
License:        GPL-2.0-only
Source0:        mxfs-${VERSION}.tar.gz

BuildRequires:  gcc make
Requires:       dkms
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
gcc -Wall -Wextra -O2 -Iinclude -o mkfs.mxfs mkfs_mxfs.c
gcc -Wall -Wextra -O2 -Iinclude -o chk_mxfs chk_mxfs.c
gcc -Wall -Wextra -O2 -Iinclude -o resize_mxfs resize_mxfs.c

%install
# DKMS source
mkdir -p %{buildroot}/usr/src/mxfs-%{version}
cp -a src/* %{buildroot}/usr/src/mxfs-%{version}/

# Tools
mkdir -p %{buildroot}/usr/sbin
install -m 755 tools/mkfs.mxfs %{buildroot}/usr/sbin/mkfs.mxfs
install -m 755 tools/chk_mxfs %{buildroot}/usr/sbin/chk_mxfs
install -m 755 tools/resize_mxfs %{buildroot}/usr/sbin/resize_mxfs
ln -sf chk_mxfs %{buildroot}/usr/sbin/fsck.mxfs

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

%post
dkms add -m mxfs -v %{version} 2>/dev/null || true
dkms build -m mxfs -v %{version}
dkms install -m mxfs -v %{version}

%preun
dkms remove -m mxfs -v %{version} --all 2>/dev/null || true

%files
/usr/src/mxfs-%{version}/
/usr/sbin/mkfs.mxfs
/usr/sbin/chk_mxfs
/usr/sbin/resize_mxfs
/usr/sbin/fsck.mxfs
/usr/share/man/man5/mxfs.5.gz
/usr/share/man/man8/mkfs.mxfs.8.gz
/usr/share/man/man8/chk_mxfs.8.gz
/usr/share/man/man8/resize_mxfs.8.gz
/etc/modules-load.d/mxfs.conf
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
