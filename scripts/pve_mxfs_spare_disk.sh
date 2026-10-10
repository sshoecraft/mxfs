#!/bin/bash
# pve_mxfs_spare_disk.sh — put MXFS on the physical pair's spare disks, set up
# exactly as docs/drbd-setup.md tells a user to (the same resource options,
# fence handler and mxfs-drbd@ unit), so the same VM builds can be timed on
# MXFS and on LVM-on-DRBD (scripts/pve_lvm_drbd_baseline.sh) over the same
# disks.  Only one MXFS mount runs on the pair at a time: `up` stops the
# pair's own mxfs-drbd@mxfs (its /mnt/shared) first, and `down` starts it
# again.  `up` refuses while a VM on either host has a disk on the storage
# that mount carries.
#
# Usage: scripts/pve_mxfs_spare_disk.sh up|down|off|status
#   off: as down, but the pair's own mount is left stopped (between runs that
#   put the spare disks to other uses)
# Env:
#   PVE_PAIR   "<addr> <addr>" (default "192.168.1.80 192.168.1.81"): host A
#              (participant 0, the lower DRBD address, which formats) then B
#   DISK       the spare disk on each host (default /dev/sdb).  `up` refuses
#              a disk that holds the root filesystem or is mounted, or whose
#              model does not contain MODEL.  Whatever is on it is lost.
#   MODEL      a substring the disk's model must contain (default empty = any)
#   RES/MINOR/PORT  DRBD resource, minor and port (default mxfssdb, 2, 7792)
#   MNT/STORE  mount point and Proxmox storage name (default /mnt/mxfssdb,
#              mxfssdb)
#   LIVE       the pair's own MXFS resource, stopped while this runs and
#              started again by `down` (default mxfs; its storage `shared`)
#
# Both disks start as whatever the last user left, so the initial sync is
# skipped (new-current-uuid --clear-bitmap) as for the LVM baseline: blocks
# MXFS never wrote may differ between the two disks, and MXFS never reads a
# block it did not write.  This volume is for measurement only.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
DISK=${DISK:-/dev/sdb}; MODEL=${MODEL:-}
RES=${RES:-mxfssdb}; MINOR=${MINOR:-2}; PORT=${PORT:-7792}
MNT=${MNT:-/mnt/mxfssdb}; STORE=${STORE:-mxfssdb}
LIVE=${LIVE:-mxfs}; LIVE_STORE=${LIVE_STORE:-shared}

on() {  # <host> <cmd> [timeout]
    timeout "${3:-120}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'
    return "${PIPESTATUS[0]}"
}
die() { echo "pve_mxfs_spare_disk: $*"; exit 1; }

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
        fencing resource-and-stonith;
        c-fill-target 4M;
        c-max-rate    110M;
        c-min-rate    20M;
    }
    handlers {
        fence-peer "/usr/sbin/mxfs-drbd-fence-peer";
    }
$s}
EOF
}

up() {
    local h rf out
    rf=$(res_file) || exit 1
    # no VM may have a disk on the live mount's storage: stopping it would
    # take the disk from under the guest
    for h in "${PAIR[@]}"; do
        out=$(on "$h" "for id in \$(qm list 2>/dev/null | awk 'NR > 1 {print \$1}'); do qm config \$id 2>/dev/null | grep -E '^(virtio|scsi|sata|ide|efidisk|tpmstate)[0-9]+: $LIVE_STORE:' | sed \"s/^/VM \$id /\"; done" 60)
        [ -z "$out" ] || die "$h has guest disks on $LIVE_STORE: $out"
    done
    for h in "${PAIR[@]}"; do
        on "$h" "set -u
            [ -b $DISK ] || { echo 'REFUSE: no $DISK'; exit 1; }
            m=\$(cat /sys/block/$(basename "$DISK")/device/model 2>/dev/null)
            case \"\$m\" in *$MODEL*) ;; *) echo \"REFUSE: $DISK model is \$m\"; exit 1 ;; esac
            rd=\$(lsblk -nrso NAME,TYPE \$(findmnt -n -o SOURCE /) | awk '\$2==\"disk\" {print \$1}')
            [ \"/dev/\$rd\" != $DISK ] || { echo 'REFUSE: $DISK holds the root filesystem'; exit 1; }
            lsblk -nro MOUNTPOINT $DISK | grep -q . && { echo 'REFUSE: something on $DISK is mounted'; exit 1; }
            drbdsetup show 2>/dev/null | grep -q \"disk.*\\\"$DISK\\\"\" && ! [ -f /etc/drbd.d/$RES.res ] && { echo 'REFUSE: another DRBD resource uses $DISK'; exit 1; }
            cat > /etc/drbd.d/$RES.res <<'RESEOF'
$rf
RESEOF
            drbdadm dump $RES >/dev/null || { echo 'REFUSE: resource file does not parse'; exit 1; }
            echo MOUNTPOINT=$MNT > /etc/mxfs/drbd-$RES.conf
            mkdir -p $MNT
            echo PREP_OK" 60 | tail -3 | sed "s/^/$h: /"
        [ "${PIPESTATUS[0]}" = 0 ] || exit 1
    done
    # the live mount down, B then A, through its own unit
    for h in "${PAIR[@]:1}" "${PAIR[0]}"; do
        on "$h" "systemctl stop mxfs-drbd@$LIVE; echo \"\$(hostname): $LIVE unit=\$(systemctl is-active mxfs-drbd@$LIVE) mounts=\$(grep -c ' mxfs ' /proc/mounts)\"" 300
    done
    for h in "${PAIR[@]}"; do
        on "$h" "grep -q ' mxfs ' /proc/mounts && { echo 'REFUSE: an mxfs mount is still up'; exit 1; }
            drbdadm cstate $RES >/dev/null 2>&1 || { yes yes | drbdadm create-md --force $RES >/dev/null 2>&1; drbdadm up $RES; }
            echo \"\$(hostname): $RES up\"" 120 || exit 1
    done
    on "${PAIR[0]}" "for i in \$(seq 1 30); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && break; sleep 1; done
        echo \"cstate \$(drbdadm cstate $RES)\"
        [ \"\$(drbdadm dstate $RES)\" = UpToDate/UpToDate ] || drbdadm -- --clear-bitmap new-current-uuid $RES
        echo \"dstate \$(drbdadm dstate $RES)\"
        drbdadm primary $RES && wipefs -a -q /dev/drbd$MINOR && mkfs.mxfs -f /dev/drbd$MINOR 2>&1 | tail -3
        drbdadm secondary $RES; echo \"mkfs rc=\${PIPESTATUS[0]}\"" 300
    # the unit brings the resource up, promotes and mounts.  Both at once: a
    # host A that starts alone gives B 30 s, then isolates it and mounts
    # without it (docs/drbd-setup.md section 7)
    start_units "$RES" || exit 1
    on "${PAIR[0]}" "pvesm status --storage $STORE >/dev/null 2>&1 || pvesm add dir $STORE --path $MNT --shared 1 --is_mountpoint yes --content images; pvesm status --storage $STORE" 60
}

off() {      # this resource gone; the live mount left as it is
    local h
    on "${PAIR[0]}" "pvesm status --storage $STORE >/dev/null 2>&1 && pvesm remove $STORE; echo storage removed" 60
    for h in "${PAIR[@]:1}" "${PAIR[0]}"; do
        on "$h" "systemctl stop mxfs-drbd@$RES; timeout 30 drbdadm down $RES
            rm -f /etc/drbd.d/$RES.res /etc/mxfs/drbd-$RES.conf
            echo \"\$(hostname): $RES unit=\$(systemctl is-active mxfs-drbd@$RES) mounts=\$(grep -c ' mxfs ' /proc/mounts)\"" 300
    done
}

down() {
    off
    start_units "$LIVE"
}

start_units() {  # <resource>: start its unit on both hosts at once
    local h i rc=0 d
    d=$(mktemp -d) || return 1
    i=0
    for h in "${PAIR[@]}"; do
        on "$h" "systemctl start mxfs-drbd@$1; echo \"\$(hostname): $1 unit=\$(systemctl is-active mxfs-drbd@$1) role=\$(drbdadm role $1) ds=\$(drbdadm dstate $1) mnt=\$(findmnt -n -o TARGET,FSTYPE /dev/drbd\$(drbdadm sh-minor $1) | tr -s ' ')\"" 420 > "$d/$i" 2>&1 &
        i=$(( i + 1 ))
    done
    wait
    cat "$d"/[0-9]*
    grep -q 'unit=active' "$d/0" && grep -q 'unit=active' "$d/1" || rc=1
    return "$rc"
}

status() {
    local h
    for h in "${PAIR[@]}"; do
        on "$h" "echo \"\$(hostname) $RES: unit=\$(systemctl is-active mxfs-drbd@$RES) cs=\$(drbdadm cstate $RES 2>&1) ro=\$(drbdadm role $RES 2>&1) ds=\$(drbdadm dstate $RES 2>&1) mnt=\$(findmnt -n -o FSTYPE $MNT); $LIVE: unit=\$(systemctl is-active mxfs-drbd@$LIVE)\"" 30
    done
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    off) off ;;
    status) status ;;
    *) echo "usage: scripts/pve_mxfs_spare_disk.sh up|down|off|status"; exit 2 ;;
esac
