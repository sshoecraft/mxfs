#!/bin/bash
#
# pve_to_qnap_tcp.sh — switch THIS pve9 node from clyde's SCST CAW LUN to the
# QNAP iSCSI LUN, i.e. the EXACT config the physical pve1/pve2 servers run and
# where the coherency defects were observed: iSCSI-from-QNAP + TCP DLM (no CAW).
#
# Tears down any mounted mxfs, then logs out the current iSCSI target and logs
# into the QNAP target (via pve_iscsi_login.sh).  force_transport=1 (TCP) is
# applied later by prep_node.sh's `tcp` path, not here.  Idempotent.  Run ON the
# node.  Prints PVE_QNAP_OK <bypath> or PVE_QNAP_FAIL: <reason>.
set -u

MNT="${MXFS_MOUNT:-/mnt/shared}"
# QNAP target (the physical rig's LUN); overridable for a different portal/LUN.
export MXFS_ISCSI_PORTAL="${MXFS_ISCSI_PORTAL:-192.168.1.4:3260}"
export MXFS_ISCSI_TGT="${MXFS_ISCSI_TGT:-iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772}"

fail() { echo "PVE_QNAP_FAIL: $*" >&2; exit 1; }

# 1. Tear down mxfs so the SCST LUN is free to log out (a live mount would EIO on
#    logout).  A shut-down/withdrawn FS returns EIO to plain umount; force then
#    lazy.  Then rmmod (may be briefly busy right after umount).
if mountpoint -q "$MNT"; then
    fuser -km "$MNT" 2>/dev/null; sleep 1
    umount "$MNT" 2>/dev/null || timeout 25 umount -f "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
fi
if lsmod | grep -q '^mxfs'; then
    for i in 1 2 3 4 5 6 7 8; do rmmod mxfs 2>/dev/null && break; sleep 2; done
    lsmod | grep -q '^mxfs' && fail "mxfs loaded and won't rmmod (wedged?)"
fi

# 2. Switch the iSCSI session: pve_iscsi_login.sh logs out + purges all node
#    records first, then discovers+logs into the QNAP target above.
bash /src/mxfs/scripts/pve_iscsi_login.sh || fail "QNAP iSCSI login failed"

BYPATH="/dev/disk/by-path/ip-${MXFS_ISCSI_PORTAL}-iscsi-${MXFS_ISCSI_TGT}-lun-0"
[ -e "$BYPATH" ] || fail "QNAP LUN $BYPATH did not appear"
echo "PVE_QNAP_OK $BYPATH -> $(readlink -f "$BYPATH")"
