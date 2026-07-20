#!/bin/bash
# MXFS SCST shared-LUN setup — HOST side (clyde).  CAW-capable iSCSI target.
#
# Stands up a SCST iSCSI target that exports ONE shared backing file as a
# CAW-capable LUN.  Unlike the LIO/tcm_loop stack (lio_tcm_setup.sh), SCST's
# vdisk_fileio handler implements SCSI COMPARE AND WRITE (0x89) and Persistent
# Reservations natively — which is what MXFS's default CAW transport needs.
#
#   /home/steve/disk.img  ->  SCST vdisk_fileio device "mxfs" (o_direct)
#                         ->  iSCSI target iqn.2026-05.local.mxfs:shared, LUN 0
#                         ->  reachable on br0 192.168.120.1:3260
#
# A vdisk_fileio device does NOT create a local /dev/sdX on clyde (contrast
# tcm_loop) — the LUN only materialises inside an initiator that logs in.  So
# this single target serves BOTH CAW conditions:
#   * direct  (cond 3): each VM runs its own iscsiadm login (tools/prep_node.sh)
#                       -> its own I_T nexus / PR registrant.  Nothing on clyde.
#   * passthrough (cond 2): clyde logs in N times via distinct ifaces
#                       (scst_wire_passthrough.sh) -> N host /dev/sdX -> one
#                       passed through to each VM.  Simulates an FC fabric.
#
# The end-to-end bring-up (host + every VM) is scripts/caw_cluster_up.sh; this
# script is only the host target half.
#
# Usage:
#   scripts/scst_setup.sh setup      # load SCST, create device + target, enable
#   scripts/scst_setup.sh status     # show device, target, LUN, sessions
#   scripts/scst_setup.sh teardown   # remove target + device (leaves disk.img)
#
# Idempotent: re-running setup reuses existing objects.

set -u

IMG="${MXFS_SCST_IMG:-/home/steve/disk.img}"
DEV="${MXFS_SCST_DEV:-mxfs}"                       # vdisk_fileio device name
TGT="${MXFS_SCST_TGT:-iqn.2026-05.local.mxfs:shared}"
# Cluster network (br0).  clyde has many bridge IPs (libvirt 192.168.122.1,
# docker 172.x, etc.); without restriction SCST advertises the target on ALL of
# them, so a guest's `iscsiadm --login` opens one session PER portal (9 seen) ->
# 9 sd devices -> multipathd assembles mpatha -> /dev/sda busy and the
# direct-mode mount fails.  allowed_portal pins discovery to one portal = one
# session = clean /dev/sda.
PORTAL_IP="${MXFS_SCST_PORTAL_IP:-192.168.120.1}"
# vdisk_fileio device parameters.  o_direct=1 is the sess26 perf fix: a buffered
# pwrite to one backing file serialises ALL initiators on the file inode's
# i_rwsem (~930 MB/s aggregate ceiling); o_direct bypasses the page cache and
# lifts it to NVMe-bound (~2.8 GB/s).  o_direct is a CREATE-TIME attribute — it
# can only be set on add_device, never toggled later.  Durability: O_DIRECT
# writes bypass the host cache, and mkfs/mxfs FUA + SYNCHRONIZE CACHE flush the
# device, so writes are stable without fileio write_through.
# NOTE: o_direct requires async=1 (SCST vdisk_attach rejects o_direct alone with
# "using o_direct without setting async is not supported", -EINVAL) — matches the
# sess26 proven combo (async=1; o_direct=1).
DEVPARAMS="${MXFS_SCST_DEVPARAMS:-filename=$IMG; blocksize=512; async=1; o_direct=1}"

SCST_ROOT=/sys/kernel/scst_tgt
H="$SCST_ROOT/handlers/vdisk_fileio"
TROOT="$SCST_ROOT/targets/iscsi"
ISCSI_SCSTD="${ISCSI_SCSTD:-/usr/local/sbin/iscsi-scstd}"

say()  { echo "$@"; }
fail() { echo "SCST_SETUP_FAIL: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] && SUDO="" || SUDO="sudo"; }

# LIO's tcm_loop and SCST cannot both export the same backing file — a double
# export corrupts the LUN.  If the LIO stack is currently holding disk.img,
# tear it down first (this is the intended "switch transport on the shared LUN"
# path — the current TCP-on-LIO rig is being replaced by CAW-on-SCST).
release_lio() {
    local liosetup="$(dirname "$0")/lio_tcm_setup.sh"
    if [ -L /dev/mxfs-shared ] || lsmod | grep -q '^tcm_loop '; then
        say "NOTE: LIO/tcm_loop is active on the shared LUN — tearing it down"
        say "      (CAW-on-SCST and TCP-on-LIO are mutually exclusive on $IMG)"
        [ -x "$liosetup" ] && $SUDO "$liosetup" teardown || \
            say "WARN: could not run lio_tcm_setup.sh teardown — check /dev/mxfs-shared manually"
    fi
}

load_modules() {
    for m in scst scst_vdisk iscsi_scst; do
        $SUDO modprobe "$m" 2>/dev/null && continue
        # Fall back to the built module files if modprobe has no dep info.
        case "$m" in
            scst)        ko="/lib/modules/$(uname -r)/extra/scst.ko" ;;
            scst_vdisk)  ko="/lib/modules/$(uname -r)/extra/dev_handlers/scst_vdisk.ko" ;;
            iscsi_scst)  ko="/lib/modules/$(uname -r)/extra/iscsi-scst.ko" ;;
        esac
        [ -f "$ko" ] && $SUDO insmod "$ko" 2>/dev/null
    done
    [ -d "$SCST_ROOT" ] || fail "SCST core not loaded ($SCST_ROOT missing) — is scst.ko installed?"
    [ -d "$H" ]         || fail "vdisk_fileio handler missing ($H) — scst_vdisk not loaded"
    [ -d "$TROOT" ]     || fail "iSCSI target driver missing ($TROOT) — iscsi_scst not loaded"
}

# The iSCSI target driver needs the userspace iscsi-scstd daemon running to
# negotiate logins; loading the module alone is not enough.
start_daemon() {
    pgrep -x iscsi-scstd >/dev/null 2>&1 && return 0
    [ -x "$ISCSI_SCSTD" ] || fail "iscsi-scstd not found at $ISCSI_SCSTD"
    $SUDO "$ISCSI_SCSTD" || fail "iscsi-scstd failed to start"
    sleep 1
    pgrep -x iscsi-scstd >/dev/null 2>&1 || fail "iscsi-scstd did not stay up"
}

setup() {
    [ -f "$IMG" ] || fail "backing file $IMG does not exist (create it first)"
    need_root
    release_lio
    load_modules
    start_daemon

    # 1. vdisk_fileio device over the shared image.
    if [ -d "$H/../../devices/$DEV" ]; then
        say "device already present: vdisk_fileio/$DEV"
    else
        echo "add_device $DEV $DEVPARAMS" | $SUDO tee "$H/mgmt" >/dev/null \
            || fail "add_device $DEV failed"
        [ -d "$H/../../devices/$DEV" ] || fail "device $DEV did not appear after add_device"
        say "device created: vdisk_fileio/$DEV ($DEVPARAMS)"
    fi

    # 2. iSCSI target + LUN 0 mapping.
    if [ -d "$TROOT/$TGT" ]; then
        say "target already present: $TGT"
    else
        echo "add_target $TGT" | $SUDO tee "$TROOT/mgmt" >/dev/null \
            || fail "add_target $TGT failed"
        say "target created: $TGT"
    fi
    if [ ! -d "$TROOT/$TGT/luns/0" ]; then
        echo "add $DEV 0" | $SUDO tee "$TROOT/$TGT/luns/mgmt" >/dev/null \
            || fail "LUN 0 mapping failed"
        say "LUN 0 -> $DEV"
    fi

    # 3. restrict discovery/logins to exactly the listed portal(s).  PORTAL_IP is
    #    a space-separated list: one IP for the single-path conditions, two for
    #    the multipath condition.  Reset cleanly each setup so switching modes
    #    never leaves a stale portal allowed.
    echo 0 | $SUDO tee "$TROOT/$TGT/enabled" >/dev/null 2>&1
    # SCST exposes a multi-value attribute as allowed_portal, allowed_portal1,
    # allowed_portal2, ... — sweep EVERY numbered file, not just the first,
    # or a dual-portal (multipath) -> single-portal switch leaves the second
    # portal advertised: node discovery then plants records for BOTH portals
    # and every VM reboot auto-logs into two sessions (test25 boot 2026-07-18
    # 13:47Z — sda+sdb on the "single-path" direct rig).  Skip the trailing
    # "[key]" marker line sysfs appends.
    for pf in "$TROOT/$TGT"/allowed_portal*; do
        [ -f "$pf" ] || continue
        for cur in $($SUDO cat "$pf" 2>/dev/null | grep -v '^\[' | tr -d ' '); do
            [ -n "$cur" ] && echo "del_target_attribute $TGT allowed_portal $cur" \
                | $SUDO tee "$TROOT/mgmt" >/dev/null 2>&1
        done
    done
    for ip in $PORTAL_IP; do
        echo "add_target_attribute $TGT allowed_portal $ip" | $SUDO tee "$TROOT/mgmt" >/dev/null 2>&1
    done
    say "target restricted to portal(s): $PORTAL_IP"

    # 4. enable the target and the driver (both required to accept logins).
    echo 1 | $SUDO tee "$TROOT/$TGT/enabled" >/dev/null || fail "could not enable target"
    echo 1 | $SUDO tee "$TROOT/enabled"      >/dev/null || fail "could not enable iscsi driver"

    say "SCST_SETUP_OK target=$TGT lun0=$DEV img=$IMG portal(s)=$PORTAL_IP"
    say "  next: scripts/rig.sh direct N | scripts/rig.sh pass N | scripts/mpath_up.sh up N"
}

status() {
    need_root
    [ -d "$SCST_ROOT" ] || { say "SCST not loaded"; return 0; }
    say "=== devices ==="
    $SUDO ls "$H/../../devices" 2>/dev/null | sed 's/^/  /'
    say "=== target $TGT ==="
    if [ -d "$TROOT/$TGT" ]; then
        say "  enabled: $($SUDO cat "$TROOT/$TGT/enabled" 2>/dev/null)"
        say "  luns:    $($SUDO ls "$TROOT/$TGT/luns" 2>/dev/null | grep -v mgmt | tr '\n' ' ')"
        say "  sessions:"
        $SUDO ls "$TROOT/$TGT/sessions" 2>/dev/null | grep -v mgmt | sed 's/^/    /' \
            || say "    (none)"
    else
        say "  (target not present)"
    fi
    say "=== iscsi-scstd ==="
    pgrep -x iscsi-scstd >/dev/null 2>&1 && say "  running" || say "  NOT running"
}

teardown() {
    need_root
    if [ -d "$TROOT/$TGT" ]; then
        echo 0 | $SUDO tee "$TROOT/$TGT/enabled" >/dev/null 2>&1
        [ -d "$TROOT/$TGT/luns/0" ] && echo "del 0" | $SUDO tee "$TROOT/$TGT/luns/mgmt" >/dev/null 2>&1
        echo "del_target $TGT" | $SUDO tee "$TROOT/mgmt" >/dev/null 2>&1
        say "removed target $TGT"
    fi
    if [ -d "$H/../../devices/$DEV" ]; then
        echo "del_device $DEV" | $SUDO tee "$H/mgmt" >/dev/null 2>&1
        say "removed device $DEV"
    fi
    say "SCST_TEARDOWN_OK (disk.img left intact: $IMG)"
}

case "${1:-}" in
    setup)    setup ;;
    status)   status ;;
    teardown) teardown ;;
    *) echo "usage: $0 {setup|status|teardown}" >&2; exit 2 ;;
esac
