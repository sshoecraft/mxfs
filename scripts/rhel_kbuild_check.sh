#!/bin/bash
#
# rhel_kbuild_check.sh — compile mxfs.ko against RHEL-family kernel headers
#
# Usage: scripts/rhel_kbuild_check.sh [-i IMAGE] [KREL ...]
#        scripts/rhel_kbuild_check.sh -i IMAGE --drop
#
# Builds against the kernel-devel of the newest kernel the image's
# repositories carry, and against each KREL given (e.g. 5.14.0-611.5.1.el9_7).
# IMAGE defaults to almalinux:9; almalinux:8 and almalinux:10 are the other
# RHEL majors on the roadmap.
#
# A RHEL kernel's LINUX_VERSION_CODE names the base it forked from (5.14 for
# every RHEL 9) while Red Hat backports newer block, super and VFS APIs into
# it, so no version number says what a RHEL kernel provides. Only a build
# against its own headers does.
#
# The container is kept between runs (named mxfs-kbuild-<image>), so an
# iteration costs one compile, not a dnf install; --drop removes it. The source
# is staged the way the packages stage it (packaging/common.sh), on every run.
# The host network is used because docker's bridge network on the rig host has
# no outbound TCP.
#
# Prints RHEL_KBUILD_OK <krel> or RHEL_KBUILD_FAIL <krel> per kernel, followed
# by the compiler's error lines for a failure. Exits non-zero if any build
# failed.
#

set -e

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="almalinux:9"
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

if ! docker inspect "$NAME" >/dev/null 2>&1; then
    docker run -d --name "$NAME" --network host -v "$SRCDIR:/src/mxfs:ro" \
        "$IMAGE" sleep infinity >/dev/null
    docker exec "$NAME" bash -c '
        set -e
        dnf -q -y install gcc make rsync kmod elfutils-libelf-devel \
            kernel-devel >/dev/null
    '
fi

docker exec -e KRELS="$*" "$NAME" bash -c '
set -e
for k in $KRELS; do
    [ -d /usr/src/kernels/$k ] || dnf -q -y install kernel-devel-$k >/dev/null
done

# Stage the source the way the packages do (packaging/common.sh).
rm -rf /build
source /src/mxfs/packaging/common.sh
mxfs_stage_kmod_source /build >/dev/null

rc=0
for hdr in /usr/src/kernels/*; do
    krel=${hdr#/usr/src/kernels/}
    # -k: keep compiling past a failed object, so one run lists every file
    # that does not build rather than only the first few make reached.
    if make -k -s -j"$(nproc)" -C "$hdr" M=/build modules >/tmp/kbuild.log 2>&1; then
        echo "RHEL_KBUILD_OK $krel $(modinfo -F srcversion /build/mxfs.ko)"
    else
        echo "RHEL_KBUILD_FAIL $krel"
        # Compiler errors, and the tool failures (a missing command or
        # shared library exits 127) that would otherwise read as "Error 127".
        grep -E "error:|not found|error while loading|No such file|Error [0-9]" \
            /tmp/kbuild.log | sort | uniq -c | sort -rn | head -300
        rc=1
    fi
done
exit $rc
'
