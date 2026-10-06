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

# Compiler flags that stamp the package version into the tools.  Without
# them include/mxfs/mxfs_common.h falls back to a fixed version, and every
# tool reports that instead of the package it came from.
mxfs_version_cflags() {
    local major minor patch
    IFS=. read -r major minor patch <<< "$(mxfs_version)"
    echo "-DMXFS_VERSION_MAJOR=${major:-0} -DMXFS_VERSION_MINOR=${minor:-0} -DMXFS_VERSION_PATCH=${patch:-0}"
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
    local cflags="-Wall -Wextra -O2 -I${SRCDIR}/include $(mxfs_version_cflags)"

    mkdir -p "$dest"

    echo "  Building mkfs.mxfs ..."
    $cc $cflags -o "$dest/mkfs.mxfs" "$SRCDIR/tools/mkfs_mxfs.c"

    echo "  Building chk_mxfs ..."
    $cc $cflags -o "$dest/chk_mxfs" "$SRCDIR/tools/chk_mxfs.c"

    echo "  Building resize_mxfs ..."
    $cc $cflags -o "$dest/resize_mxfs" "$SRCDIR/tools/resize_mxfs.c"

    echo "  Building mxfs_admin ..."
    $cc $cflags -o "$dest/mxfs_admin" "$SRCDIR/tools/mxfs_admin.c"
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

# Install everything a node needs besides the kernel module into a root
# (a package staging directory, or / for `make install`).  The .deb and
# `make install` both call this, so a source install gets the same files a
# package does: the module alone mounts with the compiled-in parameter
# defaults, formats nothing, and refuses every DRBD mount for want of the
# witness.
# Usage: mxfs_stage_node_files <dest_root>
mxfs_stage_node_files() {
    local root="$1"
    local pkgdir="$SRCDIR/packaging"

    echo "--- Building tools ---"
    mxfs_build_tools "$root/usr/sbin"

    # fsck.mxfs symlink for fstab integration
    ln -sf chk_mxfs "$root/usr/sbin/fsck.mxfs"

    # The witnessed LOGICAL UNIT RESET helper the module upcalls when a dead
    # node's registration is already gone from the target (pal/linux/lureset.c's
    # default path).  Without it that fence is refused and the survivor stays
    # frozen, so it ships with the module, not with the test rig.
    install -m 755 "$SRCDIR/tools/mxfs_lu_reset_witness.py" "$root/usr/sbin/mxfs_lu_reset_witness.py"

    # The DRBD dual-primary attachment's two node-side pieces: the witness the
    # module upcalls at mount, at a peer's death and before each recovery step
    # (pal/linux/drbd.c), and DRBD's fence-peer handler, which the module requires
    # the resource to name at exactly /usr/sbin/mxfs-drbd-fence-peer.  Without
    # them every DRBD mount is refused.
    install -m 755 "$SRCDIR/tools/mxfs_drbd_witness.py" "$root/usr/sbin/mxfs_drbd_witness.py"
    install -m 755 "$SRCDIR/tools/mxfs_drbd_fence_peer.sh" "$root/usr/sbin/mxfs-drbd-fence-peer"
    # The pair's built-in fence authority (the default when no node fence is
    # configured), the guard that holds an excluded peer out across reboots,
    # and the per-resource unit that mounts MXFS on DRBD only when it is safe.
    install -m 755 "$SRCDIR/tools/mxfs_drbd_fence_self.py" "$root/usr/sbin/mxfs-drbd-fence-self"
    mkdir -p "$root/lib/systemd/system"
    install -m 644 "$pkgdir/mxfs-drbd-guard.service" "$root/lib/systemd/system/mxfs-drbd-guard.service"
    install -m 644 "$pkgdir/mxfs-drbd@.service" "$root/lib/systemd/system/mxfs-drbd@.service"
    mkdir -p "$root/usr/share/doc/mxfs"
    install -m 644 "$SRCDIR/docs/drbd-setup.md" "$root/usr/share/doc/mxfs/drbd-setup.md"

    echo "--- Installing man pages ---"
    mxfs_stage_manpages "$root"

    # Module auto-load at boot
    mkdir -p "$root/etc/modules-load.d"
    echo "mxfs" > "$root/etc/modules-load.d/mxfs.conf"

    # Module options.  This is the operator's file once installed: an existing
    # one is kept (the packages mark it a conffile for the same reason) unless
    # MXFS_OVERWRITE_CONFIG=1, which saves it as mxfs.conf.backup first —
    # modprobe reads only *.conf, so the backup is inert.
    mkdir -p "$root/etc/modprobe.d"
    if [ -e "$root/etc/modprobe.d/mxfs.conf" ] && [ "${MXFS_OVERWRITE_CONFIG:-0}" = 1 ]; then
        cp -p "$root/etc/modprobe.d/mxfs.conf" "$root/etc/modprobe.d/mxfs.conf.backup"
        install -m 644 "$pkgdir/mxfs-modprobe.conf" "$root/etc/modprobe.d/mxfs.conf"
        echo "  Replaced $root/etc/modprobe.d/mxfs.conf; the previous one is mxfs.conf.backup"
    elif [ -e "$root/etc/modprobe.d/mxfs.conf" ]; then
        echo "  Keeping existing $root/etc/modprobe.d/mxfs.conf (the shipped one is $pkgdir/mxfs-modprobe.conf;"
        echo "  make install OVERWRITE=1 replaces it)"
    else
        install -m 644 "$pkgdir/mxfs-modprobe.conf" "$root/etc/modprobe.d/mxfs.conf"
    fi

    # udev rule: teach blkid/lsblk/mount to auto-detect MXFS by its on-disk
    # magic, so `blkid`/`lsblk -f`/`mount` (no -t) recognize the fstype
    # without needing it explicitly specified.
    mkdir -p "$root/etc/udev/rules.d"
    install -m 644 "$pkgdir/60-mxfs-blkid.rules" "$root/etc/udev/rules.d/60-mxfs-blkid.rules"
}

# Print banner
mxfs_banner() {
    local version
    version=$(mxfs_version)
    echo "=== MXFS ${version} — $1 ==="
}
