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

# --- 2-4. Tools, helpers, man pages, module config, udev rule ---
# The same list `make install` installs (packaging/common.sh).
mxfs_stage_node_files "$STAGING"

# --- 5. DEBIAN control files ---
mkdir -p "$STAGING/DEBIAN"

cat > "$STAGING/DEBIAN/control" << EOF
Package: mxfs
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: MXFS Project
Depends: dkms, python3, proxmox-default-headers | linux-headers-generic | linux-headers-amd64 | linux-headers
Recommends: open-iscsi
Section: kernel
Priority: optional
Description: MXFS — Multinode XFS shared filesystem
 Shared/clustered filesystem for concurrent multi-node access to
 XFS-formatted block devices. Features DLM-based coordination with
 CAW (disk) or TCP (network) transport, per-inode lock caching,
 on-disk journaling, and zero-config UDP multicast peer discovery.
EOF

# conffiles: dpkg-deb marks nothing on its own, and an unmarked file is
# overwritten on upgrade, discarding an operator's transport choice.
echo "/etc/modprobe.d/mxfs.conf" > "$STAGING/DEBIAN/conffiles"

# postinst: register and build DKMS module
cat > "$STAGING/DEBIAN/postinst" << POSTEOF
#!/bin/bash
set -e
echo "Registering MXFS ${VERSION} with DKMS ..."
dkms add -m mxfs -v ${VERSION} 2>/dev/null || true
# Build for every installed kernel that has headers, not only the running
# one: the header dependency installs the DEFAULT kernel's headers, which is
# not the running kernel on a node that has not rebooted since an update,
# and a fallback kernel with headers should keep a module too.
built=0
for kdir in /lib/modules/*; do
    k=\${kdir##*/}
    [ -e "\$kdir/build/Makefile" ] || continue
    echo "Building MXFS ${VERSION} for kernel \$k ..."
    if ! dkms build -m mxfs -v ${VERSION} -k "\$k" || ! dkms install -m mxfs -v ${VERSION} -k "\$k"; then
        echo "ERROR: MXFS ${VERSION} did not build for kernel \$k; see /var/lib/dkms/mxfs/${VERSION}/build/make.log" >&2
        exit 1
    fi
    built=\$((built + 1))
done
if [ "\$built" = 0 ]; then
    echo "ERROR: no installed kernel has headers; install the headers package for your kernel" >&2
    exit 1
fi
if [ ! -e "/lib/modules/\$(uname -r)/build/Makefile" ]; then
    echo "NOTE: the running kernel \$(uname -r) has no headers, so MXFS was built for the"
    echo "      other installed kernels only. Reboot into one of them, or install the"
    echo "      headers for \$(uname -r) and run: dkms install -m mxfs -v ${VERSION}"
fi
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
