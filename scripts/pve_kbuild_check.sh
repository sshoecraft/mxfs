#!/bin/bash
#
# pve_kbuild_check.sh — compile mxfs.ko against Proxmox VE kernel headers
#
# Usage: scripts/pve_kbuild_check.sh [KREL ...]
#
# With no arguments, builds against the headers of Proxmox VE 9's current
# default kernel (proxmox-default-headers).  Each KREL given (e.g.
# 6.17.2-1-pve) is built against that exact kernel's headers as well.
#
# Proxmox VE is the product's primary target, and the development rig runs
# Ubuntu's 6.8 kernel, so a module that builds and passes on the rig proves
# nothing about the PVE kernel.  0.89.77 shipped a .deb whose DKMS build
# failed on every PVE 9 node (d_hash_and_lookup is VFS-internal from 6.16).
# release.sh runs this before it builds any package.
#
# The build runs in a Debian 13 (trixie) container with the pve-no-subscription
# repository, from the source staged exactly as the .deb stages it.  The host
# network is used because docker's bridge network on the rig host has no
# outbound TCP.
#
# Prints PVE_KBUILD_OK <krel> or PVE_KBUILD_FAIL <krel> per kernel, followed by
# the compiler's error lines for a failure.  Exits non-zero if any build failed.
#

set -e

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="debian:trixie"
KEYRING_URL="https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg"

docker run --rm --network host -v "$SRCDIR:/src/mxfs:ro" \
    -e KRELS="$*" -e KEYRING_URL="$KEYRING_URL" "$IMAGE" bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# The headers ship prebuilt objtool (libelf) and gendwarfksyms (libdw).
apt-get install -y -qq ca-certificates curl gcc make rsync kmod \
    libelf1t64 libdw1t64 >/dev/null
curl -fsSL "$KEYRING_URL" -o /usr/share/keyrings/proxmox-archive-keyring.gpg
cat > /etc/apt/sources.list.d/pve.sources <<EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
apt-get update -qq

pkgs="proxmox-default-headers"
for k in $KRELS; do pkgs="$pkgs proxmox-headers-$k"; done
apt-get install -y -qq $pkgs >/dev/null

# Stage the source the way the .deb does (packaging/common.sh).
source /src/mxfs/packaging/common.sh
mxfs_stage_kmod_source /build >/dev/null

rc=0
for hdr in /usr/src/linux-headers-*-pve; do
    krel=${hdr#/usr/src/linux-headers-}
    # -k: keep compiling past a failed object, so one run lists every file
    # that does not build rather than only the first few make reached.
    if make -k -s -j"$(nproc)" -C "$hdr" M=/build modules >/tmp/kbuild.log 2>&1; then
        echo "PVE_KBUILD_OK $krel $(modinfo -F srcversion /build/mxfs.ko) libiscsi_fp=$(grep -o -E "[0-9a-f]{64}|absent:[^\"]*" /build/pal/linux/mxfs_libiscsi_fp.h)"
    else
        echo "PVE_KBUILD_FAIL $krel"
        # Compiler errors, and the tool failures (a missing command or
        # shared library exits 127) that would otherwise read as "Error 127".
        grep -E "error:|not found|error while loading|No such file|Error [0-9]" \
            /tmp/kbuild.log | sort | uniq -c | sort -rn | head -200
        rc=1
    fi
    make -s -C "$hdr" M=/build clean >/dev/null 2>&1 || true
done
exit $rc
'
