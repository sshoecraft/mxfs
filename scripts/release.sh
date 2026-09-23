#!/bin/bash
#
# MXFS — build every release package, and optionally publish a GitHub release
#
# Usage: scripts/release.sh [--publish] [--notes-file FILE]
#
# Builds into dist/<version>/:
#   mxfs_<v>_amd64.deb              Debian / Ubuntu / Proxmox (DKMS + tools)
#   pve-storage-mxfs_<v>_all.deb    Proxmox VE storage plugin
#   mxfs-<v>-1.el8.x86_64.rpm       RHEL / Alma / Rocky / Fedora / SUSE
#   SHA256SUMS
#
# Each package is built in a container running the OLDEST distribution it
# targets, never on the host.  The userspace tools are linked against the
# build system's glibc and refuse to start on an older one: built on the
# Ubuntu 24.04 host, mkfs.mxfs and chk_mxfs require GLIBC_2.38, which
# Proxmox 8 / Debian 12 (2.36) and RHEL 9 (2.34) do not have.  Debian 12
# covers Debian 12+, Ubuntu 24.04+ and Proxmox 8+; EL8 covers RHEL 8+.
#
# The containers use the host network: on clyde, docker's bridge network has
# no outbound TCP, so apt/dnf inside a bridged container cannot reach a mirror.
#
# --publish creates GitHub release v<version> on sshoecraft/mxfs with the
# packages attached.  Release notes are this version's CHANGELOG.md section
# unless --notes-file is given.  Commit and push first: the tag is created
# on the remote's main.
#

set -e

SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
source "$SRCDIR/packaging/common.sh"

DEB_IMAGE="debian:bookworm"
RPM_IMAGE="almalinux:8"
REPO="sshoecraft/mxfs"

publish=0
notes=""
while [ $# -gt 0 ]; do
    case "$1" in
        --publish) publish=1 ;;
        --notes-file) notes="$2"; shift ;;
        *) echo "usage: $0 [--publish] [--notes-file FILE]" >&2; exit 2 ;;
    esac
    shift
done

VERSION=$(mxfs_version)
OUT="$SRCDIR/dist/$VERSION"

if [ -d "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
    echo "ERROR: $OUT already holds files; remove it to rebuild $VERSION" >&2
    exit 1
fi
mkdir -p "$OUT"

owner="$(id -u):$(id -g)"

echo "=== MXFS $VERSION — .deb packages in $DEB_IMAGE ==="
docker run --rm --network host -v "$SRCDIR:/src/mxfs:ro" -v "$OUT:/out" "$DEB_IMAGE" bash -ec "
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc make rsync dpkg-dev >/dev/null
    /src/mxfs/packaging/mkdeb.sh /out
    /src/mxfs/packaging/mkdeb_pve.sh /out
    chown $owner /out/*.deb
"

echo "=== MXFS $VERSION — .rpm package in $RPM_IMAGE ==="
docker run --rm --network host -v "$SRCDIR:/src/mxfs:ro" -v "$OUT:/out" "$RPM_IMAGE" bash -ec "
    dnf install -y -q gcc make rsync rpm-build tar gzip >/dev/null
    /src/mxfs/packaging/mkrpm.sh /out
    chown $owner /out/*.rpm
"

(cd "$OUT" && sha256sum *.deb *.rpm > SHA256SUMS)

echo ""
echo "=== Built in $OUT ==="
ls -l "$OUT"

[ "$publish" = 1 ] || exit 0

if [ -z "$notes" ]; then
    notes="$OUT/RELEASE_NOTES.md"
    awk -v v="$VERSION" '
        /^## / { if (found) exit; if (index($0, "— " v " —")) found = 1 }
        found' "$SRCDIR/CHANGELOG.md" > "$notes"
    if [ ! -s "$notes" ]; then
        echo "ERROR: no CHANGELOG.md section for $VERSION; pass --notes-file" >&2
        exit 1
    fi
fi

gh release create "v$VERSION" -R "$REPO" --target main \
    --title "MXFS $VERSION" --notes-file "$notes" \
    "$OUT"/*.deb "$OUT"/*.rpm "$OUT/SHA256SUMS"
