#!/bin/bash
#
# debian_kbuild_check.sh — compile mxfs.ko against Debian kernel headers
#
# Usage: scripts/debian_kbuild_check.sh [-i IMAGE] [KREL ...]
#        scripts/debian_kbuild_check.sh -i IMAGE --drop
#
# Builds against the headers of the newest kernel the image's repositories
# carry (linux-headers-amd64), and against each KREL given (e.g.
# 6.12.43+deb13-amd64). IMAGE defaults to debian:13; debian:12 and debian:11
# are the other Debian releases on the roadmap.
#
# Debian's stock kernel is not Proxmox's: Proxmox VE 9 is Debian 13 userspace
# on its own 6.17/7.0 kernels, so a Proxmox verification says nothing about
# the 6.12 kernel a plain Debian 13 node runs. Only a build against its own
# headers does.
#
# The container is kept between runs (named mxfs-kbuild-<image>), so an
# iteration costs one compile, not an apt install; --drop removes it. The
# source is staged the way the packages stage it (packaging/common.sh), on
# every run. The host network is used because docker's bridge network on the
# rig host has no outbound TCP.
#
# Prints DEBIAN_KBUILD_OK <krel> or DEBIAN_KBUILD_FAIL <krel> per kernel,
# followed by the compiler's error lines for a failure. Exits non-zero if any
# build failed.
#

set -e

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="debian:13"
if [ "${1:-}" = "-i" ]; then
    IMAGE="$2"
    shift 2
fi
NAME="mxfs-kbuild-$(echo "$IMAGE" | tr ':/' '--')"

if [ "${1:-}" = "--drop" ]; then
    docker rm -f "$NAME" >/dev/null
    echo "dropped $NAME"
    exit 0
fi

if docker inspect "$NAME" >/dev/null 2>&1; then
    # A build whose docker exec client died (a timeout, a killed shell) keeps
    # running inside the container, a -j$(nproc) make competing with the next
    # one; restarting ends everything in it and keeps the installed packages.
    docker restart -t 0 "$NAME" >/dev/null
else
    docker run -d --name "$NAME" --network host -v "$SRCDIR:/src/mxfs:ro" \
        "$IMAGE" sleep infinity >/dev/null
    docker exec "$NAME" bash -c '
        set -e
        export DEBIAN_FRONTEND=noninteractive
        apt-get -q update >/dev/null
        apt-get -q -y install gcc make rsync kmod libelf-dev linux-headers-amd64 >/dev/null
    '
fi

docker exec -e KRELS="$*" "$NAME" bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
for k in $KRELS; do
    [ -d /usr/src/linux-headers-$k ] || apt-get -q -y install linux-headers-$k >/dev/null
done

# Stage the source the way the packages do (packaging/common.sh).
rm -rf /build
source /src/mxfs/packaging/common.sh
mxfs_stage_kmod_source /build >/dev/null

rc=0
for hdr in /usr/src/linux-headers-*; do
    krel=${hdr#/usr/src/linux-headers-}
    # the -common trees hold the shared sources a flavour tree points into;
    # only a flavour tree (with its own .config) is a kernel to build against
    [ -f "$hdr/.config" ] || continue
    # -k: keep compiling past a failed object, so one run lists every file
    # that does not build rather than only the first few make reached.
    if make -k -s -j"$(nproc)" -C "$hdr" M=/build modules >/tmp/kbuild.log 2>&1; then
        echo "DEBIAN_KBUILD_OK $krel $(modinfo -F srcversion /build/mxfs.ko)"
        # which kernel APIs the probes found: the build a release ships differs per kernel
        echo "  kcompat $krel: $(sed -n "s/^#define MXFS_HAVE_\([A-Z0-9_]*\) 1$/\1/p" /build/pal/linux/mxfs_kcompat.h | paste -sd " ")"
    else
        echo "DEBIAN_KBUILD_FAIL $krel"
        # Compiler errors, and the tool failures (a missing command or
        # shared library exits 127) that would otherwise read as "Error 127".
        grep -E "error:|ERROR:|undefined!|not found|error while loading|No such file|Error [0-9]" \
            /tmp/kbuild.log | sort | uniq -c | sort -rn | head -300
        rc=1
    fi
done
exit $rc
'
