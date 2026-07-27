#!/bin/bash
# MXFS VM wiring — attach the shared LIO/tcm_loop LUN into test VMs.
#
# Presents /dev/mxfs-shared (the stable symlink created by lio_tcm_setup.sh,
# currently -> the tcm_loop /dev/sdX) into each VM as a shareable SCSI LUN
# passthrough on a virtio-scsi controller.  Inside the guest it appears as
# /dev/sda.  No iSCSI.  Edits the PERSISTENT domain config (--config); a
# running VM must be restarted for the change to take effect (the bring-up
# step does that).
#
# Any of test1..test32 may be wired — the cluster is NOT partitioned.
#
# Usage:
#   scripts/wire_vms.sh attach 4            # wire test1..test4
#   scripts/wire_vms.sh attach 1 5 9 17     # wire those specific nodes
#   scripts/wire_vms.sh detach 4            # remove the shared LUN from test1..4
#   scripts/wire_vms.sh status [N|list]     # show wiring (default: all defined testN)
#
# A single integer arg = count (test1..testN).  Multiple args = explicit node
# list (bare numbers or testN names).

set -u

SHARED="${MXFS_SHARED_DEV:-/dev/mxfs-shared}"
GUEST_TGT="${MXFS_GUEST_TGT:-sda}"          # device name inside the guest
VIRSH="virsh -c qemu:///system"
MAXNODE=32
TMP=$(mktemp -d /tmp/wire_vms.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

say()  { echo "$@"; }
fail() { echo "WIRE_FAIL: $*" >&2; exit 1; }

# Expand args into a list of VM names.
parse_nodes() {
    if [ "$#" -eq 1 ] && [[ "$1" =~ ^[0-9]+$ ]]; then
        local n="$1" i
        [ "$n" -ge 1 ] && [ "$n" -le "$MAXNODE" ] || fail "count $n out of range 1..$MAXNODE"
        for i in $(seq 1 "$n"); do echo "test$i"; done
    else
        local a num
        for a in "$@"; do
            if [[ "$a" =~ ^[0-9]+$ ]]; then num="$a"; else num="${a#test}"; fi
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$MAXNODE" ]; then
                echo "test$num"
            elif $VIRSH dominfo "$a" >/dev/null 2>&1; then
                # sess5 (ccloop-4dd7): any DEFINED libvirt domain may be wired
                # (pve9-1/pve9-2 Proxmox VMs etc.), not just the testN fleet.
                echo "$a"
            else
                fail "bad node '$a' (expect 1..$MAXNODE, testN, or a defined VM name)"
            fi
        done
    fi
}

has_scsi_ctrl() { $VIRSH dumpxml "$1" --inactive 2>/dev/null | grep -q "model='virtio-scsi'"; }

attach_one() {
    local vm="$1" state note=""
    $VIRSH dominfo "$vm" >/dev/null 2>&1 || { say "$vm: NOT DEFINED — skipped"; return 1; }
    state=$($VIRSH domstate "$vm" 2>/dev/null)

    # 1. ensure a virtio-scsi controller exists in the persistent config.
    if ! has_scsi_ctrl "$vm"; then
        echo "<controller type='scsi' model='virtio-scsi'/>" > "$TMP/ctrl.xml"
        $VIRSH attach-device "$vm" "$TMP/ctrl.xml" --config >/dev/null 2>&1 \
            || { say "$vm: FAILED to add virtio-scsi controller"; return 1; }
    fi

    # 2. drop any existing shared LUN at this target (idempotent re-wire).
    $VIRSH detach-disk "$vm" "$GUEST_TGT" --config >/dev/null 2>&1 || true

    # 3. attach the shared LUN passthrough.
    cat > "$TMP/lun.xml" <<EOF
<disk type='block' device='lun'>
  <driver name='qemu' type='raw' cache='none'/>
  <source dev='$SHARED'/>
  <target dev='$GUEST_TGT' bus='scsi'/>
  <shareable/>
</disk>
EOF
    $VIRSH attach-device "$vm" "$TMP/lun.xml" --config >/dev/null 2>&1 \
        || { say "$vm: FAILED to attach LUN"; return 1; }

    [ "$state" = "running" ] && note="  (RUNNING — restart to apply)"
    say "$vm: wired $GUEST_TGT -> $SHARED$note"
}

detach_one() {
    local vm="$1"
    $VIRSH dominfo "$vm" >/dev/null 2>&1 || { say "$vm: NOT DEFINED — skipped"; return 1; }
    if $VIRSH detach-disk "$vm" "$GUEST_TGT" --config >/dev/null 2>&1; then
        say "$vm: detached $GUEST_TGT"
    else
        say "$vm: no $GUEST_TGT to detach"
    fi
}

status_one() {
    local vm="$1" src
    $VIRSH dominfo "$vm" >/dev/null 2>&1 || return 0
    src=$($VIRSH dumpxml "$vm" --inactive 2>/dev/null \
          | grep -A4 "device='lun'" | grep -oP "source dev='\K[^']+")
    printf "%-8s %-10s %s\n" "$vm" "$($VIRSH domstate "$vm" 2>/dev/null)" "${src:-<no shared LUN>}"
}

action="${1:-}"; shift || true

case "$action" in
    attach)
        [ "$#" -ge 1 ] || fail "attach needs a count or node list"
        [ -e "$SHARED" ] || fail "$SHARED does not exist — run lio_tcm_setup.sh setup first"
        rc=0
        for vm in $(parse_nodes "$@"); do attach_one "$vm" || rc=1; done
        exit $rc ;;
    detach)
        [ "$#" -ge 1 ] || fail "detach needs a count or node list"
        for vm in $(parse_nodes "$@"); do detach_one "$vm"; done ;;
    status)
        printf "%-8s %-10s %s\n" VM STATE "SHARED-LUN-SOURCE"
        if [ "$#" -ge 1 ]; then
            for vm in $(parse_nodes "$@"); do status_one "$vm"; done
        else
            for vm in $($VIRSH list --all --name 2>/dev/null | grep -E '^test[0-9]+$' | sort -V); do
                status_one "$vm"
            done
        fi ;;
    *) echo "usage: $0 {attach|detach|status} [N | node-list]" >&2; exit 2 ;;
esac
