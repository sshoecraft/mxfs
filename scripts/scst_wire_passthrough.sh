#!/bin/bash
# MXFS SCST passthrough wiring — HOST side (clyde).  Condition 2 (FC-fabric sim).
#
# Simulates a Fibre-Channel fabric where each physical host has its own HBA path
# to a shared LUN, using VMs behind clyde.  clyde is the iSCSI INITIATOR: it logs
# into the shared SCST device N times (one distinct per-node target each) and
# passes each resulting /dev/disk/by-path device into the matching test VM via
# QEMU `device='lun'` SCSI passthrough.  The guest sees a raw CAW-capable SCSI
# LUN with no iSCSI stack of its own — exactly what an FC HBA presents.
#
# WHY N TARGETS (not N ifaces to one target): PR fencing is per I_T nexus, so
# each VM needs a distinct nexus (sess26 — a shared host session made PR fencing
# "theater").  N sessions to ONE target+portal also collide on a single
# /dev/disk/by-path symlink, so there is no stable per-node device.  N distinct
# targets (iqn...:node1..:nodeN, all LUN 0 -> the same shared device "mxfs")
# give each node a stable, distinct by-path device AND a real distinct nexus.
#
# Prereq: scripts/scst_setup.sh setup   (creates the shared vdisk device "mxfs").
# The end-to-end bring-up is scripts/caw_cluster_up.sh passthrough N.
#
# NOTE: this is the clyde-loopback-initiator path that SCST_PROBLEM.md documents
# as wedge-prone under heavy concurrent CAW.  The 180s guest SCSI timeout
# (tools/prep_tcm_node_scst.sh) is the mitigation; keep it in place.
#
# Usage:
#   scripts/scst_wire_passthrough.sh attach 4        # wire test1..test4
#   scripts/scst_wire_passthrough.sh attach 1 5 9    # those specific nodes
#   scripts/scst_wire_passthrough.sh detach 4        # unwire + logout + del targets
#   scripts/scst_wire_passthrough.sh status [N|list]

set -u

DEV="${MXFS_SCST_DEV:-mxfs}"                     # shared vdisk device (from scst_setup.sh)
TGT_BASE="${MXFS_SCST_TGT_BASE:-iqn.2026-05.local.mxfs:node}"
PORTAL="${MXFS_SCST_PORTAL:-127.0.0.1:3260}"     # clyde logs into itself (loopback)
GUEST_TGT="${MXFS_GUEST_TGT:-sda}"               # device name inside the guest
VIRSH="virsh -c qemu:///system"
SCST_ROOT=/sys/kernel/scst_tgt
H="$SCST_ROOT/handlers/vdisk_fileio"
TROOT="$SCST_ROOT/targets/iscsi"
MAXNODE=32
TMP=$(mktemp -d /tmp/scst_wire.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

say()  { echo "$@"; }
fail() { echo "WIRE_FAIL: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] && SUDO="" || SUDO="sudo"; }

parse_nodes() {
    if [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
        local n="$1" i
        [ "$n" -ge 1 ] && [ "$n" -le "$MAXNODE" ] || fail "count $n out of range 1..$MAXNODE"
        for i in $(seq 1 "$n"); do echo "$i"; done
    else
        local a num
        for a in "$@"; do
            if [[ "$a" =~ ^[0-9]+$ ]]; then num="$a"; else num="${a#test}"; fi
            [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$MAXNODE" ] \
                || fail "bad node '$a' (expect 1..$MAXNODE or testN)"
            echo "$num"
        done
    fi
}

has_scsi_ctrl() { $VIRSH dumpxml "$1" --inactive 2>/dev/null | grep -q "model='virtio-scsi'"; }

# by-path device that open-iscsi creates for a given target on $PORTAL, LUN 0.
bypath_for() { echo "/dev/disk/by-path/ip-${PORTAL}-iscsi-$1-lun-0"; }

ensure_target() {                                # $1 = target IQN
    local tgt="$1"
    [ -d "$H/../../devices/$DEV" ] || fail "shared device '$DEV' missing — run scst_setup.sh setup first"
    [ -d "$TROOT/$tgt" ] || echo "add_target $tgt" | $SUDO tee "$TROOT/mgmt" >/dev/null \
        || fail "add_target $tgt failed"
    [ -d "$TROOT/$tgt/luns/0" ] || echo "add $DEV 0" | $SUDO tee "$TROOT/$tgt/luns/mgmt" >/dev/null \
        || fail "LUN map on $tgt failed"
    echo 1 | $SUDO tee "$TROOT/$tgt/enabled" >/dev/null
}

host_login() {                                   # $1 = target IQN -> stable by-path dev on stdout
    local tgt="$1" dev i
    $SUDO iscsiadm -m discovery -t st -p "$PORTAL" >/dev/null 2>&1
    $SUDO iscsiadm -m node -T "$tgt" -p "$PORTAL" --login >/dev/null 2>&1
    dev=$(bypath_for "$tgt")
    for i in $(seq 1 10); do [ -e "$dev" ] && break; sleep 1; done
    [ -e "$dev" ] || return 1
    echo "$dev"
}

host_logout() {                                  # $1 = target IQN
    local tgt="$1"
    $SUDO iscsiadm -m node -T "$tgt" -p "$PORTAL" --logout >/dev/null 2>&1
    $SUDO iscsiadm -m node -T "$tgt" -p "$PORTAL" -o delete >/dev/null 2>&1
}

del_target() {                                   # $1 = target IQN
    local tgt="$1"
    [ -d "$TROOT/$tgt" ] || return 0
    echo 0 | $SUDO tee "$TROOT/$tgt/enabled" >/dev/null 2>&1
    [ -d "$TROOT/$tgt/luns/0" ] && echo "del 0" | $SUDO tee "$TROOT/$tgt/luns/mgmt" >/dev/null 2>&1
    echo "del_target $tgt" | $SUDO tee "$TROOT/mgmt" >/dev/null 2>&1
}

attach_one() {                                   # $1 = node number
    local k="$1" vm="test$k" tgt="${TGT_BASE}${k}" dev state note=""
    $VIRSH dominfo "$vm" >/dev/null 2>&1 || { say "$vm: NOT DEFINED — skipped"; return 1; }

    ensure_target "$tgt"
    dev=$(host_login "$tgt") || { say "$vm: FAILED host iSCSI login to $tgt"; return 1; }

    state=$($VIRSH domstate "$vm" 2>/dev/null)
    if ! has_scsi_ctrl "$vm"; then
        echo "<controller type='scsi' model='virtio-scsi'/>" > "$TMP/ctrl.xml"
        $VIRSH attach-device "$vm" "$TMP/ctrl.xml" --config >/dev/null 2>&1 \
            || { say "$vm: FAILED to add virtio-scsi controller"; return 1; }
    fi
    $VIRSH detach-disk "$vm" "$GUEST_TGT" --config >/dev/null 2>&1 || true

    cat > "$TMP/lun.xml" <<EOF
<disk type='block' device='lun'>
  <driver name='qemu' type='raw' cache='none'/>
  <source dev='$dev'/>
  <target dev='$GUEST_TGT' bus='scsi'/>
  <shareable/>
</disk>
EOF
    $VIRSH attach-device "$vm" "$TMP/lun.xml" --config >/dev/null 2>&1 \
        || { say "$vm: FAILED to attach LUN"; return 1; }

    [ "$state" = "running" ] && note="  (RUNNING — restart to apply)"
    say "$vm: nexus=$tgt  host-dev=$dev  ->  guest $GUEST_TGT$note"
}

detach_one() {                                   # $1 = node number
    local k="$1" vm="test$k" tgt="${TGT_BASE}${k}"
    $VIRSH dominfo "$vm" >/dev/null 2>&1 && \
        $VIRSH detach-disk "$vm" "$GUEST_TGT" --config >/dev/null 2>&1 && say "$vm: detached $GUEST_TGT"
    host_logout "$tgt"
    del_target "$tgt"
    say "$vm: logged out + removed target $tgt"
}

status_one() {                                   # $1 = node number
    local k="$1" vm="test$k" tgt="${TGT_BASE}${k}" src en="-"
    $VIRSH dominfo "$vm" >/dev/null 2>&1 || return 0
    src=$($VIRSH dumpxml "$vm" --inactive 2>/dev/null | grep -A4 "device='lun'" | grep -oP "source dev='\K[^']+")
    [ -d "$TROOT/$tgt" ] && en=$($SUDO cat "$TROOT/$tgt/enabled" 2>/dev/null)
    printf "%-8s %-10s tgt=%s(en=%s) %s\n" "$vm" "$($VIRSH domstate "$vm" 2>/dev/null)" "$tgt" "$en" "${src:-<no shared LUN>}"
}

action="${1:-}"; shift || true
need_root

case "$action" in
    attach)
        [ "$#" -ge 1 ] || fail "attach needs a count or node list"
        rc=0
        for k in $(parse_nodes "$@"); do attach_one "$k" || rc=1; done
        say "NOTE: running VMs must be restarted (virsh destroy+start) to see the new LUN."
        exit $rc ;;
    detach)
        [ "$#" -ge 1 ] || fail "detach needs a count or node list"
        for k in $(parse_nodes "$@"); do detach_one "$k"; done ;;
    status)
        printf "%-8s %-10s %s\n" VM STATE "NEXUS / SHARED-LUN-SOURCE"
        if [ "$#" -ge 1 ]; then
            for k in $(parse_nodes "$@"); do status_one "$k"; done
        else
            for vm in $($VIRSH list --all --name 2>/dev/null | grep -E '^test[0-9]+$' | sort -V); do
                status_one "${vm#test}"
            done
        fi ;;
    *) echo "usage: $0 {attach|detach|status} [N | node-list]" >&2; exit 2 ;;
esac
