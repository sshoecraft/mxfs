#!/bin/bash
#
# MXFS — Build Proxmox VE Storage Plugin .deb Package
#
# Creates pve-storage-mxfs_X.Y.Z.deb containing:
#   - PVE::Storage::Custom::MXFSPlugin.pm — Proxmox storage plugin (backend)
#   - mxfs-storage.js — Web UI panel for Add/Edit dialog
#
# After install, MXFS appears as a storage type in Datacenter → Storage → Add.
# Requires: mxfs package (kernel module + tools) already installed.
#
# Usage: ./packaging/mkdeb_pve.sh [output_dir]
#

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTDIR/common.sh"

VERSION=$(mxfs_version)
ARCH="all"
OUTDIR="${1:-$SRCDIR}"
STAGING="/tmp/mxfs-pve-deb-$$"

mxfs_banner "Building Proxmox VE storage plugin .deb"

# Clean staging area
rm -rf "$STAGING"
trap 'rm -rf "$STAGING"' EXIT

# --- 1. Plugin module (Custom/ directory for third-party plugins) ---
echo "--- Staging PVE plugin ---"
mkdir -p "$STAGING/usr/share/perl5/PVE/Storage/Custom"
cp "$SRCDIR/frontend/proxmox/MXFSPlugin.pm" \
   "$STAGING/usr/share/perl5/PVE/Storage/Custom/MXFSPlugin.pm"

# --- 2. Web UI JavaScript ---
echo "--- Staging web UI ---"
mkdir -p "$STAGING/usr/share/pve-manager/js"
cp "$SRCDIR/frontend/proxmox/mxfs-storage.js" \
   "$STAGING/usr/share/pve-manager/js/mxfs-storage.js"

# --- 3. DEBIAN control files ---
mkdir -p "$STAGING/DEBIAN"

cat > "$STAGING/DEBIAN/control" << EOF
Package: pve-storage-mxfs
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: MXFS Project
Depends: mxfs (>= ${VERSION}), proxmox-ve
Section: admin
Priority: optional
Description: MXFS storage plugin for Proxmox VE
 Adds MXFS as a storage type in the Proxmox VE web interface.
 Enables shared VM/container storage on MXFS-formatted block devices
 across all nodes in a PVE cluster. Supports VM disk images, ISOs,
 backups, templates, and snippets.
EOF

# postinst: inject JS into PVE web UI and restart services
cat > "$STAGING/DEBIAN/postinst" << 'POSTEOF'
#!/bin/bash
set -e

TMPL="/usr/share/pve-manager/index.html.tpl"
SCRIPT_TAG='<script type="text/javascript" src="/pve2/js/mxfs-storage.js"></script>'

# Inject script tag after pvemanagerlib.js (if not already present)
if [ -f "$TMPL" ] && ! grep -q 'mxfs-storage.js' "$TMPL"; then
    sed -i "/pvemanagerlib\.js/a\\    ${SCRIPT_TAG}" "$TMPL"
    echo "Injected MXFS web UI into PVE template."
fi

echo "Restarting PVE services to register MXFS plugin ..."
systemctl restart pvedaemon 2>/dev/null || true
systemctl restart pveproxy 2>/dev/null || true
echo ""
echo "MXFS storage plugin installed."
echo "  Web UI: Datacenter -> Storage -> Add -> MXFS"
echo "  CLI:    pvesm add mxfs <name> --blockdevice /dev/sdX --shared 1 --content images,rootdir"
POSTEOF
chmod 755 "$STAGING/DEBIAN/postinst"

# postrm: remove JS injection and restart services
cat > "$STAGING/DEBIAN/postrm" << 'POSTRMEOF'
#!/bin/bash
set -e

TMPL="/usr/share/pve-manager/index.html.tpl"

# Remove injected script tag
if [ -f "$TMPL" ]; then
    sed -i '/mxfs-storage\.js/d' "$TMPL"
fi

systemctl restart pvedaemon 2>/dev/null || true
systemctl restart pveproxy 2>/dev/null || true
POSTRMEOF
chmod 755 "$STAGING/DEBIAN/postrm"

# --- 4. Build the .deb ---
echo "--- Building .deb ---"
DEB_FILE="${OUTDIR}/pve-storage-mxfs_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group -Zxz --build "$STAGING" "$DEB_FILE"

echo ""
echo "Package: $DEB_FILE"
echo ""
echo "Install with:"
echo "  sudo dpkg -i $(basename "$DEB_FILE")"
echo ""
echo "Then add MXFS storage:"
echo "  pvesm add mxfs shared-storage --blockdevice /dev/sdX --path /mnt/pve/shared-storage --shared 1 --content images,rootdir"
