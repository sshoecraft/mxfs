#!/bin/bash
# scst_platform_targets.sh — give every platform verification pair its OWN
# SCST iSCSI LUN on clyde, visible to that pair's two initiators and nobody
# else.
#
# WHY.  The pairs used to share one LUN with each other and with the 2-node rig
# (test1/test2), so a platform round and a rig lap could not run at the same
# time, and neither could two platforms' rounds: each formats the LUN it is
# given.  A LUN per pair lets the four platforms verify in parallel with each
# other and with the rig.
#
# ISOLATION IS THE POINT, NOT A NICETY.  run.sh's iSCSI restore on the rig runs
# a SendTargets discovery and then a bare `iscsiadm -m node --login`, which
# logs a rig node into every target the portal offers.  So each target's LUN 0
# lives only in an ini_group named `pair` that holds the pair's two initiator
# names, and the target has no default LUN: any other initiator that logs in
# sees no disk.  (This SCST build has no allowed_initiator attribute;
# add_target_attribute refuses it with EINVAL.)  Each pair node also gets a
# node record for its own target only, so the harness login never needs a
# discovery — which would record every target, and RHEL logs into discovered
# targets at boot.
#
# For each `pair <platform>=<A>,<B>` in the lab file:
#   ~/disk-plat-<platform>.img  (sparse, PLAT_SIZE, created if absent)
#     -> vdisk_fileio device mxfs<platform>
#     -> target iqn.2026-05.local.mxfs:plat-<platform>, LUN 0 in ini_group pair
#   ~/.config/mxfslab/lab.<platform>: the lab file with only that pair and its
#     own storage line.  Run a round against it with
#       MXFS_LAB=~/.config/mxfslab/lab.<platform> tests/packaged_round.sh <platform>
#     (the format step checks that every node on the LUN is unmounted, and
#     that set must be the pair alone).
#
# SCST objects are runtime-only: after a clyde reboot run scst_setup.sh setup
# for the rig and then this script again.  Idempotent.
#
# Usage: scripts/scst_platform_targets.sh setup|status
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
PLAT_SIZE="${PLAT_SIZE:-64G}"
PORTAL=$(lab_need storage portal) || exit 2
PORTAL=${PORTAL%%:*}
IMGDIR=$(dirname "$(lab_need paths image)") || exit 2
T=/sys/kernel/scst_tgt/targets/iscsi
LABDIR=$(dirname "$MXFS_LAB")

platforms() {
    awk '$1=="pair" { for (i = 2; i <= NF; i++) { n = index($i, "="); if (n) print substr($i, 1, n-1) } }' "$MXFS_LAB"
}

initiator_of() {  # <node> -> its InitiatorName, or nothing
    timeout 30 "$SSH" "$(lab_addr "$1")" \
        'sed -n "s/^InitiatorName=//p" /etc/iscsi/initiatorname.iscsi' </dev/null 2>/dev/null \
        | grep -a '^iqn\.' | tail -1
}

setup_one() {
    local p=$1 a b tgt dev img g i ini
    read -r a b <<< "$(lab_pair "$p")" || return 1
    tgt=iqn.2026-05.local.mxfs:plat-$p
    dev=mxfs$(echo "$p" | tr -cd 'a-z0-9')
    img=$IMGDIR/disk-plat-$p.img
    [ -e "$img" ] || truncate -s "$PLAT_SIZE" "$img" || return 1
    MXFS_SCST_IMG=$img MXFS_SCST_DEV=$dev MXFS_SCST_TGT=$tgt \
        timeout 60 "$HERE/scripts/scst_setup.sh" setup | grep -E 'SCST_SETUP|FAIL' || return 1
    g=$T/$tgt/ini_groups
    [ -d "$g/pair" ] || echo "create pair" | sudo tee "$g/mgmt" >/dev/null || return 1
    [ -d "$g/pair/luns/0" ] || echo "add $dev 0" | sudo tee "$g/pair/luns/mgmt" >/dev/null || return 1
    for i in $a $b; do
        ini=$(initiator_of "$i")
        [ -n "$ini" ] || { echo "$p: no initiator name from $i" >&2; return 1; }
        [ -e "$g/pair/initiators/$ini" ] || echo "add $ini" | sudo tee "$g/pair/initiators/mgmt" >/dev/null || return 1
        timeout 30 "$SSH" "$(lab_addr "$i")" \
            "iscsiadm -m node -T $tgt -p $PORTAL:3260 >/dev/null 2>&1 || iscsiadm -m node -o new -T $tgt -p $PORTAL:3260 >/dev/null" \
            </dev/null >/dev/null 2>&1 || { echo "$p: node record on $i failed" >&2; return 1; }
    done
    [ -d "$T/$tgt/luns/0" ] && { echo "del 0" | sudo tee "$T/$tgt/luns/mgmt" >/dev/null || return 1; }
    { grep -E '^#|^addr|^qemu|^paths' "$MXFS_LAB"
      echo "storage portal=$PORTAL target=$tgt lun=/dev/disk/by-path/ip-$PORTAL:3260-iscsi-$tgt-lun-0"
      echo "pair $p=$a,$b"; } > "$LABDIR/lab.$p"
    echo "$p: $tgt lun0=$dev in group pair [$(ls "$g/pair/initiators" | grep -v mgmt | tr '\n' ' ')] lab=$LABDIR/lab.$p"
}

status() {
    local p tgt
    for p in $(platforms); do
        tgt=iqn.2026-05.local.mxfs:plat-$p
        if [ -d "$T/$tgt" ]; then
            echo "$p: $tgt default_luns=[$(ls "$T/$tgt/luns" | grep -v mgmt | tr '\n' ' ')] pair_luns=[$(ls "$T/$tgt/ini_groups/pair/luns" 2>/dev/null | grep -v mgmt | tr '\n' ' ')] initiators=[$(ls "$T/$tgt/ini_groups/pair/initiators" 2>/dev/null | grep -v mgmt | tr '\n' ' ')] sessions=[$(sudo ls "$T/$tgt/sessions" 2>/dev/null | grep -v mgmt | tr '\n' ' ')]"
        else
            echo "$p: $tgt not present"
        fi
    done
}

case "${1:-}" in
    setup)  rc=0; for p in $(platforms); do setup_one "$p" || { echo "PLATFORM_TARGET_FAIL $p" >&2; rc=1; }; done; exit $rc ;;
    status) status ;;
    *) echo "usage: $0 setup|status" >&2; exit 2 ;;
esac
