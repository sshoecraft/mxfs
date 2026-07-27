#!/bin/bash
#
# pve_iscsi_login.sh — log THIS node into clyde's SCST CAW iSCSI target over a
# single portal (the `cawd` condition: direct in-guest iSCSI, own I_T nexus / PR
# registrant, real SCSI COMPARE-AND-WRITE).  Idempotent: logs out + purges stale
# node records first so a re-run never leaves a second path for multipathd to
# swallow.  Run ON the node.
#
# Prints PVE_ISCSI_OK <bypath> -> <sdX> on success, PVE_ISCSI_FAIL: <reason>.
set -u

PORTAL="${MXFS_ISCSI_PORTAL:-192.168.120.1:3260}"
TGT="${MXFS_ISCSI_TGT:-iqn.2026-05.local.mxfs:shared}"
BYPATH="/dev/disk/by-path/ip-${PORTAL}-iscsi-${TGT}-lun-0"

fail() { echo "PVE_ISCSI_FAIL: $*" >&2; exit 1; }

systemctl start iscsid 2>/dev/null || service iscsid start 2>/dev/null || true
sleep 1

# Clean slate: drop any existing session + stale discovery records for this
# portal so exactly ONE session (one path) comes up.
iscsiadm -m node -u >/dev/null 2>&1
iscsiadm -m node -o delete >/dev/null 2>&1

iscsiadm -m discovery -t st -p "$PORTAL" >/dev/null 2>&1 || fail "discovery against $PORTAL failed"
iscsiadm -m node -T "$TGT" -p "$PORTAL" --login >/dev/null 2>&1 || fail "login to $TGT @ $PORTAL failed"

# The by-path symlink appears asynchronously after the SCSI scan.
for i in $(seq 1 20); do
    [ -e "$BYPATH" ] && break
    iscsiadm -m session --rescan >/dev/null 2>&1
    sleep 1
done
[ -e "$BYPATH" ] || fail "LUN device $BYPATH did not appear after login"

echo "PVE_ISCSI_OK $BYPATH -> $(readlink -f "$BYPATH")"
