#!/bin/bash
#
# MXFS — the userspace half of `make install` from a source tree.
#
# A clone followed by `make && make install` must leave a node with
# everything the packages install, not just mxfs.ko: the module alone runs on
# compiled-in parameter defaults, has no mkfs.mxfs of its own version, and
# refuses every DRBD mount for want of the witness and fence handler.
#
# Usage (from the Makefile):
#   packaging/install_source.sh check    before the module is installed
#   packaging/install_source.sh files    after it is installed
#
# --overwrite (make install OVERWRITE=1) replaces an existing
# /etc/modprobe.d/mxfs.conf with the shipped one, saving the old one as
# mxfs.conf.backup; without it the existing file is kept.  Everything else is
# replaced on every install.
#
# DESTDIR, when set, installs into a staging root and skips the host checks.
#

set -e

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPTDIR/common.sh"

ROOT="${DESTDIR:-}"
VERSION=$(mxfs_version)

check_host() {
    if [ -n "$ROOT" ]; then
        return 0
    fi
    if [ "$(id -u)" != 0 ]; then
        echo "ERROR: make install writes /lib/modules, /usr/sbin and /etc; run it as root" >&2
        exit 1
    fi

    # A packaged MXFS on the same host owns /usr/sbin/mkfs.mxfs and a DKMS
    # module of its own version.  Installing a source build over it leaves two
    # versions answering to the same names: which mkfs.mxfs formats a volume
    # and which mxfs.ko a kernel loads then depends on PATH and depmod order,
    # not on what the operator just built.
    local found=""
    if command -v dpkg-query >/dev/null 2>&1 &&
       dpkg-query -W -f='${Status}' mxfs 2>/dev/null | grep -q 'install ok installed'; then
        found="the mxfs .deb ($(dpkg-query -W -f='${Version}' mxfs)) — remove it with: apt remove mxfs pve-storage-mxfs"
    elif command -v rpm >/dev/null 2>&1 && rpm -q mxfs >/dev/null 2>&1; then
        found="the mxfs rpm ($(rpm -q mxfs)) — remove it with: dnf remove mxfs"
    elif command -v dkms >/dev/null 2>&1 && [ -n "$(dkms status mxfs 2>/dev/null)" ]; then
        local reg
        reg=$(dkms status mxfs | head -1 | cut -d, -f1)
        found="a DKMS mxfs module ($(dkms status mxfs | head -1)) — remove it with: dkms remove ${reg} --all"
    fi
    if [ -n "$found" ]; then
        echo "ERROR: this host already has $found" >&2
        echo "       A source install of MXFS ${VERSION} beside it would leave two versions" >&2
        echo "       of the module and the tools installed under the same names." >&2
        exit 1
    fi
}

install_files() {
    mxfs_banner "Installing tools, helpers and configuration into ${ROOT:-/}"
    mxfs_stage_node_files "$ROOT"

    if [ -z "$ROOT" ]; then
        udevadm control --reload-rules 2>/dev/null || true
        udevadm trigger --subsystem-match=block 2>/dev/null || true
    fi

    # `modprobe mxfs` does nothing while a module is loaded, so after an
    # install the kernel keeps running the OLD build until it is unloaded.
    # Measured on two PVE hosts: a module loaded at boot from an earlier
    # install ran every mount of the afternoon after `make install && modprobe
    # mxfs` had installed a different one.
    local loaded installed
    if [ -z "$ROOT" ] && [ -r /sys/module/mxfs/srcversion ]; then
        loaded=$(cat /sys/module/mxfs/srcversion)
        installed=$(modinfo -F srcversion mxfs 2>/dev/null || true)
        if [ "$loaded" != "$installed" ]; then
            echo ""
            echo "WARNING: the mxfs module loaded now (srcversion $loaded) is NOT the one just"
            echo "         installed (srcversion $installed).  The kernel keeps running the old"
            echo "         build until it is unloaded: unmount every MXFS filesystem, then"
            echo "             rmmod mxfs && modprobe mxfs"
            echo "         and check that /sys/module/mxfs/srcversion reads $installed."
        fi
    fi

    echo ""
    echo "MXFS ${VERSION} installed: mxfs.ko, mkfs.mxfs, chk_mxfs (fsck.mxfs), resize_mxfs,"
    echo "mxfs_admin, the LU-reset and DRBD witness helpers, the DRBD fence-peer handler,"
    echo "man pages, /etc/modprobe.d/mxfs.conf and the udev rule.  The module auto-loads at boot."
    echo ""
    echo "Load it now:   modprobe mxfs"
    echo "Format:        mkfs.mxfs /dev/sdX          (one node only)"
    echo "Mount:         mount -t mxfs /dev/sdX /mnt/shared"
    echo "Every node of a cluster needs this same version installed."
}

if [ "$2" = "--overwrite" ]; then
    export MXFS_OVERWRITE_CONFIG=1
elif [ -n "$2" ]; then
    echo "usage: $0 check|files [--overwrite]" >&2
    exit 2
fi

case "$1" in
    check) check_host ;;
    files) install_files ;;
    *)
        echo "usage: $0 check|files [--overwrite]" >&2
        exit 2
        ;;
esac
