#!/bin/bash
# pve_drbd_xfs_storage.sh — put a plain XFS on a scratch DRBD resource of the
# physical pair and offer it to Proxmox as a storage on one host, so the same
# VM builds can run on XFS over the same DRBD that carries MXFS.
#
# What MXFS costs a guest's disk on the pair is whatever it adds over XFS on
# the same replicated device; what DRBD protocol C costs on these disks is the
# hardware's.  scripts/drbd_write_latency_probe.sh measures that with fio; this
# script lets scripts/pve_pair_builds.sh measure it with the real builds
# (STORAGE=drbdxfs COUNTS="3 0").
#
# up:   a thick LV <RES> of SIZE on each host's VG, a DRBD resource on it
#       (minor MINOR, port PORT, protocol C, both hosts Primary as the MXFS
#       resource is, no initial resync: both sides start from a new current
#       UUID with a cleared bitmap), XFS made and mounted on host A at
#       /mnt/<RES>, and a Proxmox dir storage <RES> for images on host A's node
#       only.
# down: the storage removed, XFS unmounted, the resource down, the LVs and the
#       resource file removed.  Refuses while any VM disk is still on it.
# status: the storage, the mount, the resource's state and the LVs.
#
# Usage: scripts/pve_drbd_xfs_storage.sh up|down|status
# Env:   HOSTS ("192.168.1.80 192.168.1.81": host A, which mounts, then B)
#        RES (drbdxfs)  SIZE (14G)  VG (pve)  MINOR (1)  PORT (7790)
#        THIN_POOL      a thin pool in VG (e.g. data): the LV is a thin volume
#                       in it, as the MXFS resource's backing is, instead of a
#                       thick LV
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSHP="$REPO/tools/mxfs_sshpass.sh"
read -r -a HS <<<"${HOSTS:-192.168.1.80 192.168.1.81}"
[ "${#HS[@]}" = 2 ] || { echo "HOSTS must name two hosts"; exit 2; }
HA=${HS[0]}; HB=${HS[1]}
RES=${RES:-drbdxfs}; SIZE=${SIZE:-14G}; VG=${VG:-pve}; MINOR=${MINOR:-1}; PORT=${PORT:-7790}
if [ -n "${THIN_POOL:-}" ]; then LVSPEC="-V $SIZE -T $VG/$THIN_POOL -n $RES"; else LVSPEC="-W y -L $SIZE -n $RES $VG"; fi
DEV=/dev/drbd$MINOR; MNTP=/mnt/$RES
on() { timeout "${3:-60}" "$SSHP" "$1" "$2" </dev/null 2>/dev/null | grep -avE '^Warning:|^Unauthorized|^If you'; }
log() { echo "[$(date +%T)] $*"; }

NA=$(on "$HA" 'uname -n'); NB=$(on "$HB" 'uname -n')
[ -n "$NA" ] && [ -n "$NB" ] || { log "cannot reach $HA or $HB"; exit 1; }

status() {
    on "$HA" "pvesm status 2>/dev/null | awk '\$1 == \"$RES\"'; findmnt -n $MNTP"
    for h in "$HA" "$HB"; do
        on "$h" "echo \"\$(uname -n): role \$(drbdadm role $RES 2>&1) cstate \$(drbdadm cstate $RES 2>&1) dstate \$(drbdadm dstate $RES 2>&1)\"; lvs --noheadings -o lv_name,lv_size $VG/$RES 2>&1"
    done
}

case "${1:-}" in
up)
    for h in "$HA" "$HB"; do
        st=$(on "$h" "[ -e /etc/drbd.d/$RES.res ] && echo HAVE_RES; grep -q '^ *$MINOR:' /proc/drbd && echo MINOR_USED; lvs $VG/$RES >/dev/null 2>&1 && echo HAVE_LV")
        [ -z "$st" ] || { log "$h already has: $(echo $st); run down first"; exit 1; }
    done
    CONF="resource $RES {
    net { protocol C; allow-two-primaries yes; }
    disk { c-fill-target 4M; c-max-rate 110M; c-min-rate 20M; }
    on $NA { device $DEV minor $MINOR; disk /dev/$VG/$RES; address $HA:$PORT; meta-disk internal; }
    on $NB { device $DEV minor $MINOR; disk /dev/$VG/$RES; address $HB:$PORT; meta-disk internal; }
}"
    for h in "$HA" "$HB"; do
        r=$(on "$h" "lvcreate -y $LVSPEC >/dev/null 2>&1 || { echo LV_FAIL; exit; }
            cat > /etc/drbd.d/$RES.res <<'EOF'
$CONF
EOF
            drbdadm -- --force create-md $RES >/dev/null 2>&1 || { echo MD_FAIL; exit; }
            drbdadm up $RES >/dev/null 2>&1 || { echo UP_FAIL; exit; }
            echo UP" 120)
        log "$h: $r"
        [ "$r" = UP ] || exit 1
    done
    r=$(on "$HA" "for i in \$(seq 1 30); do [ \"\$(drbdadm cstate $RES)\" = Connected ] && break; sleep 1; done
        drbdadm -- --clear-bitmap new-current-uuid $RES >/dev/null 2>&1; sleep 1
        drbdadm primary $RES 2>&1 | tail -1; echo \"\$(drbdadm cstate $RES) \$(drbdadm dstate $RES)\"" 60)
    log "$NA: $r"
    r=$(on "$HB" "drbdadm primary $RES 2>&1 | tail -1; drbdadm role $RES" 30)
    log "$NB: $r"
    case "$r" in *Primary/Primary*) ;; *) log "both hosts are not Primary"; exit 1 ;; esac
    r=$(on "$HA" "mkfs.xfs -f -q -K $DEV && mkdir -p $MNTP && mount $DEV $MNTP || { echo XFS_FAIL; exit; }
        pvesm add dir $RES --path $MNTP --content images --nodes $NA --is_mountpoint yes >/dev/null 2>&1 || { echo PVESM_FAIL; exit; }
        echo READY" 120)
    log "$NA: $r"
    [ "$r" = READY ] || exit 1
    status
    ;;
down)
    n=$(on "$HA" "grep -l '$RES:' /etc/pve/nodes/*/qemu-server/*.conf 2>/dev/null | wc -l")
    [ "${n:-1}" = 0 ] || { log "VM configs still name storage $RES ($n); remove those VMs first"; exit 1; }
    on "$HA" "pvesm remove $RES >/dev/null 2>&1; if findmnt -n $MNTP >/dev/null; then timeout 60 umount $MNTP; fi; rmdir $MNTP 2>/dev/null; echo \"\$(uname -n): storage and mount gone\"" 90
    for h in "$HA" "$HB"; do
        on "$h" "timeout 20 drbdadm secondary $RES >/dev/null 2>&1; timeout 30 drbdadm down $RES >/dev/null 2>&1
            rm -f /etc/drbd.d/$RES.res; lvremove -y $VG/$RES >/dev/null 2>&1
            echo \"\$(uname -n): minor $MINOR \$(grep -c '^ *$MINOR:' /proc/drbd) left, lv \$(lvs $VG/$RES >/dev/null 2>&1 && echo LEFT || echo gone)\"" 90
    done
    ;;
status) status ;;
*) echo "usage: $0 up|down|status"; exit 2 ;;
esac
