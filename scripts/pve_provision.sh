#!/bin/bash
#
# pve_provision.sh — provision a FRESH Proxmox VE 9 (Debian 13/trixie) node so it
# can build + run the MXFS DKMS module.  osimager-built pve9-* nodes boot bare:
# no /src, no apt repo that resolves (only the subscription-gated enterprise
# repo), no kernel headers, no dkms, no build toolchain.  This brings all of
# that up, idempotently, so scripts/pve_dkms_rebuild.sh can then build mxfs.ko.
#
# Run ON the node.  Invoke from the dev host as ONE simple command so the
# sshpass wrapper's arg-flattening can't mangle it:
#   tools/mxfs_sshpass.sh <node> <passfile> "bash /src/mxfs/scripts/pve_provision.sh"
#
# Prints PVE_PROVISION_OK <kernel> <headerpkg> on success,
# PVE_PROVISION_FAIL: <reason> otherwise.  Re-runnable.
set -u

NFS_SERVER="${NFS_SERVER:-192.168.1.4:/src}"
KREL="$(uname -r)"
KEYR=/usr/share/keyrings/proxmox-archive-keyring.gpg
APTLOG=/tmp/pve_provision_apt.log

fail() { echo "PVE_PROVISION_FAIL: $*" >&2; exit 1; }

# 1. /src over NFS (the MXFS source tree + this script live here).
mountpoint -q /src || {
    mkdir -p /src
    mount -t nfs "$NFS_SERVER" /src -o rw,vers=4.1,hard,timeo=600,retrans=2,tcp 2>/dev/null \
        || fail "NFS mount $NFS_SERVER -> /src failed"
}
[ -f /src/mxfs/VERSION ] || fail "/src/mxfs not visible (VERSION missing)"

# 2. apt sources: add the pve no-subscription repo (deb822) and DISABLE the
#    enterprise + ceph-enterprise repos, which 401 without a subscription and
#    would abort `apt update`.  The Debian base repo (debian.sources) is left
#    alone — dkms/build-essential come from there.
[ -f "$KEYR" ] || fail "proxmox keyring $KEYR missing"
cat > /etc/apt/sources.list.d/pve-no-subscription.sources <<EOF
Types: deb
URIs: http://download.proxmox.com/debian/pve
Suites: trixie
Components: pve-no-subscription
Signed-By: $KEYR
EOF
# apt only reads files matching *.sources, so renaming these aside disables the
# subscription-gated repos cleanly (a stray in-stanza key would malform them).
for f in pve-enterprise ceph; do
    s="/etc/apt/sources.list.d/$f.sources"
    [ -f "$s" ] && mv -f "$s" "$s.backup"
done

# 3. update + install headers (matching THIS kernel) + dkms + toolchain.
export DEBIAN_FRONTEND=noninteractive
apt-get update >"$APTLOG" 2>&1 || fail "apt-get update failed (see $APTLOG on node)"
# PVE 9 header package is proxmox-headers-<krel>; keep pve-headers-<krel> as a
# fallback for older naming.
HDR="proxmox-headers-$KREL"
apt-cache show "$HDR" >/dev/null 2>&1 || HDR="pve-headers-$KREL"
# sg3-utils supplies sg_persist — REQUIRED so tests/setup/prep_fs.sh can clear a
# stale SCSI Persistent Reservation left on the shared LUN by a prior CAW cluster
# (its PR-clear is guarded by `command -v sg_persist`; without it mkfs fails with
# EBADE "Invalid exchange" against the still-fenced LUN).
apt-get install -y "$HDR" dkms build-essential sg3-utils >>"$APTLOG" 2>&1 \
    || fail "apt-get install $HDR dkms build-essential sg3-utils failed (see $APTLOG on node)"

# 4. verify the build prerequisites are actually present.
[ -d "/lib/modules/$KREL/build" ] || [ -d "/usr/src/linux-headers-$KREL" ] \
    || fail "kernel build tree for $KREL not present after install"
command -v dkms >/dev/null 2>&1 || fail "dkms missing after install"
command -v make >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1 \
    || fail "make/gcc missing after install"

echo "PVE_PROVISION_OK $KREL $HDR"
