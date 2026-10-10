#!/bin/bash
# pve_vmio_fs_matrix.sh — the installing-guest write pattern
# (tests/pve_vmio_census.sh) on the spare-disk DRBD resource of the physical
# pair, each filesystem freshly made, sparse and prefilled file each:
#
#   xfs-1pri   XFS mounted on host A, host B Secondary (a single-primary pair)
#   xfs-2pri   the same XFS, host B Primary too but not mounting it (DRBD's
#              dual-primary mode, as under MXFS, without MXFS)
#   mxfs       MXFS on the same device, mounted on both by the mxfs-drbd@ unit
#              (scripts/pve_mxfs_spare_disk.sh)
#
# so what MXFS costs a guest is read against XFS on the same disks, with the
# cost of DRBD's dual-primary mode separated out.  Nothing else may run on
# the pair meanwhile: a build harness tearing its VMs down on the same mount
# made one MXFS reading five times worse than a clean one.
#
# Usage: tests/pve_vmio_fs_matrix.sh <outdir> [config ...]   (default: all three)
# Env:   PVE_PAIR ("192.168.1.80 192.168.1.81")  RES (mxfssdb)  MINOR (2)
#        DISK (sdb)  MODEL (SVP100S: passed to pve_mxfs_spare_disk.sh up)
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
OUT=${1:?outdir}; shift
CONFIGS=${*:-xfs-1pri xfs-2pri mxfs}
read -r -a PAIR <<<"${PVE_PAIR:-192.168.1.80 192.168.1.81}"
RES=${RES:-mxfssdb}; MINOR=${MINOR:-2}; DISK=${DISK:-sdb}
XMNT=/mnt/xfs$RES
mkdir -p "$OUT" || exit 1
say() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/matrix.log"; }
on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^$'; return "${PIPESTATUS[0]}"; }

mxfs_down() {   # the MXFS units stopped (B then A), the resource left up, Secondary
    local h
    for h in "${PAIR[1]}" "${PAIR[0]}"; do
        on "$h" "systemctl stop mxfs-drbd@$RES; drbdadm cstate $RES >/dev/null 2>&1 || drbdadm up $RES; echo \"\$(hostname): unit=\$(systemctl is-active mxfs-drbd@$RES) mxfs mounts=\$(grep -c ' mxfs ' /proc/mounts)\"" 300 | tee -a "$OUT/matrix.log"
    done
    on "${PAIR[0]}" "for i in \$(seq 1 30); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && break; sleep 1; done; echo \"cs=\$(drbdadm cstate $RES) ro=\$(drbdadm role $RES) ds=\$(drbdadm dstate $RES)\"" 60 | tee -a "$OUT/matrix.log"
}
xfs_up() {      # <2pri>: fresh XFS on A; B Primary too when 1
    on "${PAIR[0]}" "drbdadm primary $RES && mkfs.xfs -f -q /dev/drbd$MINOR && mkdir -p $XMNT && mount /dev/drbd$MINOR $XMNT && echo \"A: \$(findmnt -n -o SOURCE,FSTYPE $XMNT) ro=\$(drbdadm role $RES)\"" 120 | tee -a "$OUT/matrix.log"
    [ "$1" = 1 ] && on "${PAIR[1]}" "drbdadm primary $RES; echo \"B: ro=\$(drbdadm role $RES)\"" 60 | tee -a "$OUT/matrix.log"
    on "${PAIR[0]}" "findmnt -n $XMNT >/dev/null"
}
xfs_down() {
    on "${PAIR[0]}" "timeout 60 umount $XMNT; rmdir $XMNT; drbdadm secondary $RES; echo \"A: mounted=\$(grep -c drbd$MINOR /proc/mounts) ro=\$(drbdadm role $RES)\"" 90 | tee -a "$OUT/matrix.log"
    on "${PAIR[1]}" "drbdadm secondary $RES; echo \"B: ro=\$(drbdadm role $RES)\"" 60 | tee -a "$OUT/matrix.log"
}
pair() {        # <config> <mountpoint>: sparse then prefill
    local m
    for m in sparse prefill; do
        say "$1 $m"
        timeout 420 "$REPO/tests/pve_vmio_census.sh" "$2" "$m" "$OUT/$1-$m" > "$OUT/$1-$m.log" 2>&1
        say "  $1 $m rc=$? $(cat "$OUT/$1-$m/fio.summary" 2>/dev/null)"
    done
}

say "matrix: $CONFIGS on $RES (/dev/drbd$MINOR on $DISK)"
for c in $CONFIGS; do
    case "$c" in
        xfs-1pri|xfs-2pri)
            mxfs_down
            if xfs_up "$([ "$c" = xfs-2pri ] && echo 1 || echo 0)"; then pair "$c" "$XMNT"; else say "$c: XFS did not come up"; fi
            xfs_down ;;
        mxfs)
            MODEL=${MODEL:-SVP100S} timeout 480 "$REPO/scripts/pve_mxfs_spare_disk.sh" up > "$OUT/mxfs-up.log" 2>&1
            say "mxfs up rc=$? $(grep -c 'unit=active' "$OUT/mxfs-up.log") unit(s) active"
            pair mxfs /mnt/$RES ;;
        *) say "unknown config $c" ;;
    esac
done
say "matrix done"
grep -E '  .* rc=' "$OUT/matrix.log"
