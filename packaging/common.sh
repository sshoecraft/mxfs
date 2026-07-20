#!/bin/bash
#
# MXFS Packaging — Common Functions
#
# Shared by all platform-specific package builders.
# Sources version info, gathers source files, detects platform.
#

set -e

SRCDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Resolve the package version.  The v5 source of truth is the top-level
# VERSION file (e.g. "0.4.2"); the build does not pass -DMXFS_VERSION_* so
# the mxfs_common.h defaults are 0.0.0 and must not be used as the version.
mxfs_version() {
    if [ -f "$SRCDIR/VERSION" ]; then
        local v
        v=$(tr -d ' \t\r\n' < "$SRCDIR/VERSION")
        if [ -n "$v" ]; then
            echo "$v"
            return
        fi
    fi
    # Fallback: mxfs_common.h defines (legacy layout).
    local hdr="$SRCDIR/include/mxfs/mxfs_common.h"
    local major minor patch
    major=$(grep '#define MXFS_VERSION_MAJOR' "$hdr" 2>/dev/null | awk '{print $3}')
    minor=$(grep '#define MXFS_VERSION_MINOR' "$hdr" 2>/dev/null | awk '{print $3}')
    patch=$(grep '#define MXFS_VERSION_PATCH' "$hdr" 2>/dev/null | awk '{print $3}')
    echo "${major:-0}.${minor:-0}.${patch:-0}"
}

# Detect what OS family we're running on
# Returns: debian, redhat, suse, freebsd, darwin, unknown
mxfs_detect_os() {
    if [ "$(uname)" = "Darwin" ]; then
        echo "darwin"
        return
    fi
    if [ "$(uname)" = "FreeBSD" ]; then
        echo "freebsd"
        return
    fi
    if [ -f /etc/os-release ]; then
        local id
        id=$(. /etc/os-release && echo "$ID")
        case "$id" in
            ubuntu|debian|linuxmint|pop|proxmox*|pve)
                echo "debian" ;;
            rhel|centos|almalinux|rocky|fedora|ol|amzn)
                echo "redhat" ;;
            sles|opensuse*)
                echo "suse" ;;
            *)
                # Check ID_LIKE for derivatives
                local like
                like=$(. /etc/os-release && echo "${ID_LIKE:-}")
                case "$like" in
                    *debian*|*ubuntu*) echo "debian" ;;
                    *rhel*|*fedora*|*centos*) echo "redhat" ;;
                    *suse*) echo "suse" ;;
                    *) echo "unknown" ;;
                esac
                ;;
        esac
    else
        echo "unknown"
    fi
}

# Copy kernel module source to a staging directory
# Usage: mxfs_stage_kmod_source <dest_dir>
mxfs_stage_kmod_source() {
    local dest="$1"
    mkdir -p "$dest"

    # v5 layout: mxfs.ko is built from the whole tree via the top-level
    # Kbuild.  Stage every source directory the Kbuild references (see its
    # -I include paths and the mxfs-y object lists): compat, include, the
    # XFS fork (xfs/ + xfs/libxfs/), the DLM subsystem, the platform layer,
    # and the MXFS coordination layer.  Source files only — build artifacts
    # are excluded so DKMS does a clean compile on the target kernel.
    local rsync_excl=(
        --exclude='*.o' --exclude='*.o.*' --exclude='.*.o.cmd'
        --exclude='.*.cmd' --exclude='*.ko' --exclude='*.mod'
        --exclude='*.mod.c' --exclude='*.mod.o' --exclude='modules.order'
        --exclude='Module.symvers' --exclude='*.symvers'
        --exclude='.tmp_versions/' --exclude='*.order'
    )
    local d
    for d in compat include xfs dlm pal mxfs_clayer; do
        [ -d "$SRCDIR/$d" ] || continue
        mkdir -p "$dest/$d"
        rsync -a "${rsync_excl[@]}" "$SRCDIR/$d/" "$dest/$d/"
    done

    # Build files
    cp "$SRCDIR/Kbuild" "$dest/"
    cp "$SRCDIR/Makefile" "$dest/"
    [ -f "$SRCDIR/VERSION" ] && cp "$SRCDIR/VERSION" "$dest/"
}

# Build userspace tools into a target directory
# Usage: mxfs_build_tools <dest_dir>
mxfs_build_tools() {
    local dest="$1"
    local cc="${CC:-gcc}"
    local cflags="-Wall -Wextra -O2 -I${SRCDIR}/include"

    mkdir -p "$dest"

    echo "  Building mkfs.mxfs ..."
    $cc $cflags -o "$dest/mkfs.mxfs" "$SRCDIR/tools/mkfs_mxfs.c"

    echo "  Building chk_mxfs ..."
    $cc $cflags -o "$dest/chk_mxfs" "$SRCDIR/tools/chk_mxfs.c"

    echo "  Building resize_mxfs ..."
    $cc $cflags -o "$dest/resize_mxfs" "$SRCDIR/tools/resize_mxfs.c"
}

# Install gzipped man pages into a staging directory
# Usage: mxfs_stage_manpages <dest_root>
# Creates dest_root/usr/share/man/man{5,8}/ with gzipped pages
mxfs_stage_manpages() {
    local dest="$1"

    echo "  Installing man pages ..."

    mkdir -p "$dest/usr/share/man/man5"
    mkdir -p "$dest/usr/share/man/man8"

    for page in "$SRCDIR"/docs/man/man8/*.8; do
        [ -f "$page" ] || continue
        gzip -9 -c "$page" > "$dest/usr/share/man/man8/$(basename "$page").gz"
    done

    for page in "$SRCDIR"/docs/man/man5/*.5; do
        [ -f "$page" ] || continue
        gzip -9 -c "$page" > "$dest/usr/share/man/man5/$(basename "$page").gz"
    done
}

# Print banner
mxfs_banner() {
    local version
    version=$(mxfs_version)
    echo "=== MXFS ${version} — $1 ==="
}
