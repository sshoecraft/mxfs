#!/bin/bash
# pve_lvm_drbd_baseline.sh — the storage a two-host Proxmox pair runs without a
# cluster filesystem, set up beside MXFS on the same hosts so the two can be
# measured on the same hardware: a dual-primary DRBD resource on a spare disk
# of each host, LVM on top of it, added to Proxmox as shared LVM storage (each
# guest disk a logical volume on the replicated device).  This is the layout
# Proxmox's DRBD guides describe; MXFS's own resource (mxfs, /dev/drbd0) is
# not touched.
#
# Usage: scripts/pve_lvm_drbd_baseline.sh up|down|status
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81"); the first
#              host creates the volume group
#   DISK       the spare disk on each host (default /dev/sdb).  `up` refuses a
#              disk that holds the root filesystem, is mounted, or carries any
#              signature: wipe it first.
#   MODEL      a substring the disk's model must contain (default empty = any)
#   RES/MINOR/PORT  DRBD resource, minor and port (default lvmdrbd, 2, 7792)
#   VG/STORE   the volume group and the Proxmox storage name (default
#              drbdvg, drbdlvm)
#
# The replication settings are mxfs.res's own (protocol C, two primaries,
# split-brain policies disconnect, the same resync tuning), so the two stacks
# differ only above DRBD.  No fence handler: this volume is for measurement,
# and MXFS's handler is for the mxfs resource.
#
# LVM must never see the spare disk's PV directly, or it may use the raw disk
# and bypass replication: `up` adds "r|^<DISK>.*|" to lvm.conf's global_filter
# and `down` removes it.  Both disks start blank, so the initial sync is
# skipped (new-current-uuid --clear-bitmap).
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
DISK=${DISK:-/dev/sdb}; MODEL=${MODEL:-}
RES=${RES:-lvmdrbd}; MINOR=${MINOR:-2}; PORT=${PORT:-7792}
VG=${VG:-drbdvg}; STORE=${STORE:-drbdlvm}
FILTER="r|^$DISK.*|"

on() {  # <host> <cmd> [timeout]
    timeout "${3:-120}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'
    return "${PIPESTATUS[0]}"
}
die() { echo "pve_lvm_drbd_baseline: $*"; exit 1; }

res_file() {
    local h n s=""
    for h in "${PAIR[@]}"; do
        n=$(on "$h" hostname 20) || die "$h does not answer"
        s+="    on $n {
        device    /dev/drbd$MINOR minor $MINOR;
        disk      $DISK;
        address   $h:$PORT;
        meta-disk internal;
    }
"
    done
    cat <<EOF
resource $RES {
    net {
        protocol C;
        allow-two-primaries yes;
        after-sb-0pri disconnect;
        after-sb-1pri disconnect;
        after-sb-2pri disconnect;
        ping-int 3;
    }
    disk {
        c-fill-target 4M;
        c-max-rate    110M;
        c-min-rate    20M;
    }
$s}
EOF
}

up() {
    local h rf
    rf=$(res_file) || exit 1
    for h in "${PAIR[@]}"; do
        on "$h" "set -u
            [ -b $DISK ] || { echo 'REFUSE: no $DISK'; exit 1; }
            m=\$(cat /sys/block/$(basename "$DISK")/device/model 2>/dev/null)
            case \"\$m\" in *$MODEL*) ;; *) echo \"REFUSE: $DISK model is \$m\"; exit 1 ;; esac
            rd=\$(lsblk -nrso NAME,TYPE \$(findmnt -n -o SOURCE /) | awk '\$2==\"disk\" {print \$1}')
            [ \"/dev/\$rd\" != $DISK ] || { echo 'REFUSE: $DISK holds the root filesystem'; exit 1; }
            lsblk -nro MOUNTPOINT $DISK | grep -q . && { echo 'REFUSE: something on $DISK is mounted'; exit 1; }
            [ -z \"\$(wipefs -n $DISK 2>/dev/null)\" ] || [ -f /etc/drbd.d/$RES.res ] || { echo 'REFUSE: $DISK carries signatures; wipe it first'; exit 1; }
            grep -q '$FILTER' /etc/lvm/lvm.conf || sed -i 's#^\(\s*global_filter=\[.*\)\]#\1,\"$FILTER\"]#' /etc/lvm/lvm.conf
            grep -q '$FILTER' /etc/lvm/lvm.conf || { echo 'REFUSE: could not add the LVM filter'; exit 1; }
            cat > /etc/drbd.d/$RES.res <<'RESEOF'
$rf
RESEOF
            drbdadm dump $RES >/dev/null || { echo 'REFUSE: resource file does not parse'; exit 1; }
            drbdadm cstate $RES >/dev/null 2>&1 || { yes yes | drbdadm create-md --force $RES >/dev/null 2>&1; drbdadm up $RES; }
            echo UP_OK" 120 | tail -3
    done
    on "${PAIR[0]}" "for i in \$(seq 1 30); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && break; sleep 1; done
        drbdadm cstate $RES
        [ \"\$(drbdadm dstate $RES)\" = UpToDate/UpToDate ] || drbdadm -- --clear-bitmap new-current-uuid $RES
        drbdadm dstate $RES" 60
    for h in "${PAIR[@]}"; do on "$h" "drbdadm primary $RES && echo \"\$(hostname) \$(drbdadm role $RES)\"" 30; done
    on "${PAIR[0]}" "vgs $VG >/dev/null 2>&1 || { pvcreate -q /dev/drbd$MINOR && vgcreate -q $VG /dev/drbd$MINOR; }; vgs $VG" 60
    on "${PAIR[1]}" "pvscan --cache >/dev/null 2>&1; vgs $VG" 60
    on "${PAIR[0]}" "pvesm status --storage $STORE >/dev/null 2>&1 || pvesm add lvm $STORE --vgname $VG --shared 1 --content images; pvesm status --storage $STORE" 60
}

down() {
    local h
    on "${PAIR[0]}" "pvesm status --storage $STORE >/dev/null 2>&1 && pvesm remove $STORE; echo storage removed" 60
    for h in "${PAIR[@]}"; do
        on "$h" "vgchange -an $VG >/dev/null 2>&1; drbdadm secondary $RES 2>/dev/null; drbdadm down $RES 2>/dev/null
            rm -f /etc/drbd.d/$RES.res
            sed -i 's#,\"$FILTER\"##' /etc/lvm/lvm.conf
            echo \"\$(hostname): down, filter \$(grep -c '$FILTER' /etc/lvm/lvm.conf)\"" 60
    done
}

status() {
    local h
    for h in "${PAIR[@]}"; do
        on "$h" "echo \"\$(hostname) cs=\$(drbdadm cstate $RES 2>&1) ro=\$(drbdadm role $RES 2>&1) ds=\$(drbdadm dstate $RES 2>&1) vg=\$(vgs --noheadings -o vg_name,vg_size,vg_free $VG 2>&1 | tr -s ' ')\"" 30
    done
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *) echo "usage: scripts/pve_lvm_drbd_baseline.sh up|down|status"; exit 2 ;;
esac
