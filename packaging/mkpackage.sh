#!/bin/bash
#
# MXFS — Auto-Detecting Package Builder
#
# Detects the current OS and calls the appropriate platform-specific builder.
#
# Usage: ./packaging/mkpackage.sh [output_dir]
#
# Supported platforms:
#   - Debian/Ubuntu/Proxmox → .deb (DKMS + tools)
#   - RHEL/AlmaLinux/Rocky/Fedora/SUSE → .rpm (DKMS + tools)
#   - FreeBSD → .pkg (future)
#   - macOS → .pkg (future)
#

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTDIR/common.sh"

OS=$(mxfs_detect_os)
VERSION=$(mxfs_version)

echo "Detected OS family: $OS"
echo "MXFS version: $VERSION"
echo ""

case "$OS" in
    debian)
        exec "$SCRIPTDIR/mkdeb.sh" "$@"
        ;;
    redhat|suse)
        exec "$SCRIPTDIR/mkrpm.sh" "$@"
        ;;
    freebsd)
        echo "FreeBSD packaging not yet implemented."
        echo "Requires: pal/pal_freebsd_kern.c + frontend/freebsd/"
        exit 1
        ;;
    darwin)
        echo "macOS packaging not yet implemented."
        echo "Requires: pal/pal_macos_user.c + frontend/macos/ (macFUSE or FSKit)"
        exit 1
        ;;
    *)
        echo "ERROR: Unknown OS family '$OS'"
        echo "Cannot determine package format."
        echo ""
        echo "Supported: Debian/Ubuntu, RHEL/Fedora/AlmaLinux/Rocky, SUSE"
        echo "Planned:   FreeBSD, macOS"
        exit 1
        ;;
esac
