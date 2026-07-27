#!/bin/bash
#
# MXFS — Build Debian/Ubuntu .deb Package
#
# Creates a single .deb containing:
#   - DKMS source (kernel module auto-builds on install and kernel updates)
#   - Userspace tools: mkfs.mxfs, chk_mxfs, resize_mxfs
#   - /etc/modules-load.d/mxfs.conf (auto-load at boot)
#   - fsck.mxfs symlink (for fstab fsck dispatch)
#
# Usage: ./packaging/mkdeb.sh [output_dir]
# Output: mxfs_X.Y.Z_ARCH.deb
#

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTDIR/common.sh"

VERSION=$(mxfs_version)
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
OUTDIR="${1:-$SRCDIR}"
STAGING="/tmp/mxfs-deb-$$"

mxfs_banner "Building .deb package"

# Clean staging area
rm -rf "$STAGING"
trap 'rm -rf "$STAGING"' EXIT

# --- 1. DKMS source ---
echo "--- Staging DKMS source ---"
DKMS_DST="$STAGING/usr/src/mxfs-${VERSION}"
mxfs_stage_kmod_source "$DKMS_DST"

# Install dkms.conf with version substituted
sed "s/__VERSION__/$VERSION/" "$SCRIPTDIR/dkms.conf" > "$DKMS_DST/dkms.conf"

# --- 2. Userspace tools ---
echo "--- Building tools ---"
mxfs_build_tools "$STAGING/usr/sbin"

# fsck.mxfs symlink for fstab integration
ln -sf chk_mxfs "$STAGING/usr/sbin/fsck.mxfs"

# --- 3. Man pages ---
echo "--- Installing man pages ---"
mxfs_stage_manpages "$STAGING"

# --- 4. Module auto-load config ---
mkdir -p "$STAGING/etc/modules-load.d"
echo "mxfs" > "$STAGING/etc/modules-load.d/mxfs.conf"

# --- 4b. udev rule: teach blkid/lsblk/mount to auto-detect MXFS by its
# on-disk magic, so `blkid`/`lsblk -f`/`mount` (no -t) recognize the fstype
# without needing it explicitly specified.
mkdir -p "$STAGING/etc/udev/rules.d"
cp "$SCRIPTDIR/60-mxfs-blkid.rules" "$STAGING/etc/udev/rules.d/60-mxfs-blkid.rules"

# --- 5. DEBIAN control files ---
mkdir -p "$STAGING/DEBIAN"

cat > "$STAGING/DEBIAN/control" << EOF
Package: mxfs
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: MXFS Project
Depends: dkms
Recommends: open-iscsi
Section: kernel
Priority: optional
Description: MXFS — Multinode XFS shared filesystem
 Shared/clustered filesystem for concurrent multi-node access to
 XFS-formatted block devices. Features DLM-based coordination with
 CAW (disk) or TCP (network) transport, per-inode lock caching,
 on-disk journaling, and zero-config UDP multicast peer discovery.
EOF

# postinst: register and build DKMS module
cat > "$STAGING/DEBIAN/postinst" << POSTEOF
#!/bin/bash
set -e
echo "Registering MXFS ${VERSION} with DKMS ..."
dkms add -m mxfs -v ${VERSION} 2>/dev/null || true
dkms build -m mxfs -v ${VERSION}
dkms install -m mxfs -v ${VERSION}
udevadm control --reload-rules 2>/dev/null || true
udevadm trigger --subsystem-match=block 2>/dev/null || true
echo "MXFS ${VERSION} installed. Module will auto-load on boot."
echo ""
echo "To mount a filesystem:"
echo "  mount -t mxfs /dev/sdX /mnt/shared"
echo ""
echo "To auto-mount at boot, add to /etc/fstab:"
echo "  /dev/sdX  /mnt/shared  mxfs  _netdev  0  0"
POSTEOF
chmod 755 "$STAGING/DEBIAN/postinst"

# prerm: unregister DKMS module
cat > "$STAGING/DEBIAN/prerm" << PRERMEOF
#!/bin/bash
set -e
echo "Removing MXFS ${VERSION} from DKMS ..."
dkms remove -m mxfs -v ${VERSION} --all 2>/dev/null || true
rm -f /etc/udev/rules.d/60-mxfs-blkid.rules
udevadm control --reload-rules 2>/dev/null || true
PRERMEOF
chmod 755 "$STAGING/DEBIAN/prerm"

# --- 6. Fix ownership and build the .deb ---
echo "--- Building .deb ---"
DEB_FILE="${OUTDIR}/mxfs_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGING" "$DEB_FILE"

echo ""
echo "Package: $DEB_FILE"
echo ""
echo "Install with:"
echo "  sudo dpkg -i $(basename "$DEB_FILE")"
echo ""
echo "Then add to /etc/fstab for auto-mount:"
echo "  /dev/sdX  /mnt/shared  mxfs  _netdev  0  0"
