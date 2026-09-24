#!/bin/bash
#
# pve_libiscsi_crosscheck.sh — compare a Proxmox kernel's iSCSI initiator
# headers with the tree the LU-reset witness was audited on
#
# Usage: scripts/pve_libiscsi_crosscheck.sh KREL [KREL ...]
#   e.g. scripts/pve_libiscsi_crosscheck.sh 6.17.2-1-pve 7.0.14-19-pve
#
# The witnessed-LU-reset fence (dlm/scsipr.c) runs only on a kernel release in
# its audited-kernel pin, because the witness's meaning rests on libiscsi
# allowing one task-management function per session at a time.  The reference
# is the tree under /src/linux, whose libiscsi bodies were read.  A release
# whose bodies are not available here can still be compared structurally —
# the declarations that state machine is built from — which is how
# 6.8.0-101-generic was admitted, and which the pin records as a structural
# cross-check and never as a body-level audit.
#
# For each KREL this installs proxmox-headers-KREL in a Debian 13 container
# (the same one scripts/pve_kbuild_check.sh builds in) and diffs
# include/scsi/{libiscsi.h,scsi_transport_iscsi.h,iscsi_proto.h} against
# /src/linux, printing the diff, the MXFS_LIBISCSI_FP of both sides
# (pal/linux/libiscsi_fingerprint.sh — what the module admits by), then for
# libiscsi.h the TMF-relevant identifiers with their line numbers on both sides.
#
set -e

[ $# -ge 1 ] || { echo "usage: $0 KREL [KREL ...]" >&2; exit 2; }
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"
REF=/src/linux
IMAGE="debian:trixie"
KEYRING_URL="https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg"
echo "reference: $REF ($(sed -n 's/^VERSION = //p;s/^PATCHLEVEL = //p;s/^SUBLEVEL = //p;s/^EXTRAVERSION = //p' $REF/Makefile | tr '\n' '.' | sed 's/\.$//'))"

docker run --rm --network host -v "$REF/include/scsi:/ref:ro" -v "$SRCDIR/pal/linux:/fp:ro" \
    -e KRELS="$*" -e KEYRING_URL="$KEYRING_URL" "$IMAGE" bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl diffutils >/dev/null
curl -fsSL "$KEYRING_URL" -o /usr/share/keyrings/proxmox-archive-keyring.gpg
cat > /etc/apt/sources.list.d/pve.sources <<EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
apt-get update -qq
pkgs=""
for k in $KRELS; do pkgs="$pkgs proxmox-headers-$k"; done
apt-get install -y -qq --no-install-recommends $pkgs >/dev/null
ids="TMF_INITIAL|TMF_QUEUED|TMF_SUCCESS|TMF_FAILED|TMF_TIMEDOUT|TMF_NOT_FOUND|eh_mutex|ehwait|tmhdr|tmf_timer|tmf_state|lu_reset_timeout|frwd_lock|back_lock"
for k in $KRELS; do
    d=/usr/src/linux-headers-$k/include/scsi
    echo "=== $k"
    [ -d "$d" ] || { echo "CROSSCHECK_FAIL $k: no headers at $d"; continue; }
    for f in libiscsi.h scsi_transport_iscsi.h iscsi_proto.h; do
        if diff -q /ref/$f $d/$f >/dev/null; then
            echo "IDENTICAL $f"
        else
            echo "DIFFERS $f ($(diff /ref/$f $d/$f | grep -c "^[<>]") changed lines)"
            diff -u /ref/$f $d/$f | head -80
        fi
    done
    echo "FINGERPRINT ref=$(sh /fp/libiscsi_fingerprint.sh /ref/libiscsi.h | sed -n "s/.*FP \"\(.*\)\"/\1/p") $k=$(sh /fp/libiscsi_fingerprint.sh $d/libiscsi.h | sed -n "s/.*FP \"\(.*\)\"/\1/p")"
    echo "--- TMF identifiers in libiscsi.h (ref line : $k line)"
    for id in $(echo $ids | tr "|" " "); do
        a=$(grep -n -w "$id" /ref/libiscsi.h | cut -d: -f1 | tr "\n" ",")
        b=$(grep -n -w "$id" $d/libiscsi.h | cut -d: -f1 | tr "\n" ",")
        [ "$a" = "$b" ] && s=same || s=MOVED
        printf "  %-18s %-14s %-14s %s\n" "$id" "${a%,}" "${b%,}" "$s"
    done
done
'
