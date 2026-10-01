#!/bin/bash
# rig_groups.sh — give every rig group its own SCST LUN and log the group's
# nodes into it, so several configurations can run on the rig at once.
#
# WHY.  The rig's nodes all attach to one LUN (:shared), so one run.sh at a
# time is all the rig can hold: every run formats the LUN it is given.  A rig
# group is a disjoint slice of test1..test32 named by a `group` line in the lab
# file (tools/mxfs_lab.sh); with a LUN of its own it runs a whole board with
# `run.sh <configuration> --group <name>` beside the other groups.
#
# ISOLATION.  Same shape as scripts/scst_platform_targets.sh: the group's
# LUN 0 lives only in an ini_group holding the group's initiator names, and the
# target has no default LUN, so a node of another group that logs in (run.sh's
# power-cycle restore runs a discovery and a bare login) sees no disk.  Each
# node is logged out of everything and into its own group's target only, and
# gets no discovery record.  tests/lib/rig.sh refuses a device whose WWID is not
# the declared one, and run.sh declares the group's.
#
# For each group <g>:
#   <image dir>/disk-grp-<g>.img  (sparse, created if absent, GROUP_SIZE,
#                                  default the rig image's size: a sparse
#                                  file costs only the blocks written)
#     -> vdisk_fileio device mxfsgrp<g>
#     -> target iqn.2026-05.local.mxfs:grp-<g>, LUN 0 in ini_group grp
#   guest device: /dev/disk/by-path/ip-<portal>:3260-iscsi-<target>-lun-0
#
# Only the `direct` attachment is built.  A multipath group needs the second
# portal on its target and the guests' multipathd map, which mpath_up.sh builds
# for :shared only.
#
# Refuses while any run holds the rig or one of the group's nodes
# (tests/lib/runlock.sh): logging a node out under a live run is how a
# rig change turns into a fabricated filesystem failure.
#
# SCST objects are runtime-only: after a clyde reboot run setup again.
# Idempotent.
#
# Usage: scripts/rig_groups.sh setup [<group> ...]   # every group when none named
#        scripts/rig_groups.sh status
#        scripts/rig_groups.sh dev <group>           # print the group's guest device
#        scripts/rig_groups.sh image <group>         # print the group's host-side image
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
. "$HERE/tests/lib/runlock.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
PORTAL=$(lab_need storage portal) || exit 2
PORTAL=${PORTAL%%:*}
RIG_IMG=$(lab_need paths image) || exit 2
IMGDIR=$(dirname "$RIG_IMG")
# A group's LUN is the size of the rig's own, so mkfs gives it the geometry
# the release boards were graded on.  Group LUNs of 20G were built first:
# 9 AGs against the rig LUN's 63, so 8 nodes shared 9 AGs, the allocator
# contention was not the release's, and alloc_witness's fill could not carve
# a chunk on one node.  Sparse, so the size costs only the blocks written.
GROUP_SIZE="${GROUP_SIZE:-$(stat -c %s "$RIG_IMG" 2>/dev/null)}"
[ -n "$GROUP_SIZE" ] || { echo "rig_groups: cannot size a group LUN: $RIG_IMG is unreadable" >&2; exit 2; }
T=/sys/kernel/scst_tgt/targets/iscsi

tgt_of() { echo "iqn.2026-05.local.mxfs:grp-$1"; }
dev_of() { echo "/dev/disk/by-path/ip-$PORTAL:3260-iscsi-$(tgt_of "$1")-lun-0"; }
ssh_n() { timeout "${3:-30}" "$SSH" "$(lab_addr "$1")" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you'; }

disjoint() {  # every node in at most one group, and in no platform set
    local dup plat
    dup=$(for g in $(lab_groups); do lab_group "$g" | tr ' ' '\n'; done | sort | uniq -d | tr '\n' ' ')
    [ -z "$dup" ] || { echo "rig_groups: nodes in more than one group: $dup" >&2; return 1; }
    plat=$(for g in $(lab_groups); do lab_group "$g" | tr ' ' '\n'; done | grep -Fxf <(lab_lun_nodes) | tr '\n' ' ')
    [ -z "$plat" ] || { echo "rig_groups: group nodes also in a platform set: $plat" >&2; return 1; }
}

# The node side: the cleanout scripts/rig.sh runs (unmount, unload, drop every
# session and record, flush maps), then a login to this group's target alone.
# The mountpoint gate before fuser -km is load-bearing: on a directory that is
# not a mountpoint it resolves to the root fs and kills sshd.
NODE_LOGIN='
    for t in 1 2 3 4 5; do
        mountpoint -q /mnt/shared || break
        fuser -km /mnt/shared 2>/dev/null; sleep 1
        umount /mnt/shared 2>/dev/null && break
        timeout 20 umount -f /mnt/shared 2>/dev/null && break
        sleep 1
    done
    mountpoint -q /mnt/shared && { echo LOGIN_FAIL still mounted; exit 0; }
    for t in 1 2 3 4 5; do lsmod | grep -q "^mxfs " || break; rmmod mxfs 2>/dev/null && break; sleep 2; done
    lsmod | grep -q "^mxfs " && { echo LOGIN_FAIL mxfs still loaded; exit 0; }
    mkdir -p /etc/multipath/conf.d
    printf "defaults {\n    find_multipaths strict\n}\n" > /etc/multipath/conf.d/mxfs.conf
    multipath -F >/dev/null 2>&1
    > /etc/multipath/wwids 2>/dev/null
    > /etc/multipath/bindings 2>/dev/null
    systemctl restart multipathd >/dev/null 2>&1
    for try in 1 2 3; do
        iscsiadm -m node -u >/dev/null 2>&1
        iscsiadm -m node -o delete >/dev/null 2>&1
        iscsiadm -m node -o new -T TGT -p PORTAL:3260 >/dev/null 2>&1
        iscsiadm -m node -T TGT -p PORTAL:3260 --op update -n node.startup -v automatic >/dev/null 2>&1
        iscsiadm -m node -T TGT -p PORTAL:3260 --login >/dev/null 2>&1
        iscsiadm -m session --rescan >/dev/null 2>&1
        sleep 2
        d=$(readlink -f DEVPATH 2>/dev/null)
        if [ -b "$d" ]; then
            echo "LOGIN_OK sessions=$(iscsiadm -m session 2>/dev/null | grep -c iqn) wwid=$(cat /sys/block/$(basename $d)/device/wwid 2>/dev/null | tr -d " ")"
            exit 0
        fi
        sleep 3
    done
    echo LOGIN_FAIL no device'

initiator_of() {  # <node> -> its InitiatorName, or nothing
    ssh_n "$1" 'sed -n "s/^InitiatorName=//p" /etc/iscsi/initiatorname.iscsi' | grep -a '^iqn\.' | tail -1
}

setup_one() {
    local g=$1 set tgt dev img grp n ini want="" td bad="" wwid="" line
    set=$(lab_group "$g") || return 1
    runlock_nodes "rig_groups.sh setup $g" $set || return 1
    tgt=$(tgt_of "$g")
    dev=mxfsgrp$(echo "$g" | tr -cd 'a-z0-9')
    img=$IMGDIR/disk-grp-$g.img
    [ -e "$img" ] || truncate -s "$GROUP_SIZE" "$img" || return 1
    MXFS_SCST_IMG=$img MXFS_SCST_DEV=$dev MXFS_SCST_TGT=$tgt MXFS_SCST_PORTAL_IP=$PORTAL \
        timeout 60 "$HERE/scripts/scst_setup.sh" setup | grep -E 'SCST_SETUP|FAIL' || return 1
    grp=$T/$tgt/ini_groups
    [ -d "$grp/grp" ] || echo "create grp" | sudo tee "$grp/mgmt" >/dev/null || return 1
    [ -d "$grp/grp/luns/0" ] || echo "add $dev 0" | sudo tee "$grp/grp/luns/mgmt" >/dev/null || return 1
    for n in $set; do
        ini=$(initiator_of "$n")
        [ -n "$ini" ] || { echo "$g: no initiator name from $n" >&2; return 1; }
        want="$want $ini"
        [ -e "$grp/grp/initiators/$ini" ] || echo "add $ini" | sudo tee "$grp/grp/initiators/mgmt" >/dev/null || return 1
    done
    for ini in $(ls "$grp/grp/initiators" | grep -v mgmt); do
        case " $want " in *" $ini "*) ;; *)
            echo "del $ini" | sudo tee "$grp/grp/initiators/mgmt" >/dev/null || return 1
            echo "$g: removed initiator $ini (no longer in the group)" ;;
        esac
    done
    [ -d "$T/$tgt/luns/0" ] && { echo "del 0" | sudo tee "$T/$tgt/luns/mgmt" >/dev/null || return 1; }

    local snippet=${NODE_LOGIN//TGT/$tgt}
    snippet=${snippet//PORTAL/$PORTAL}
    snippet=${snippet//DEVPATH/$(dev_of "$g")}
    td=$(mktemp -d)
    for n in $set; do
        ( ssh_n "$n" "$snippet" 120 > "$td/$n" ) &
    done
    wait
    for n in $set; do
        line=$(grep -a -E '^LOGIN_(OK|FAIL)' "$td/$n" | tail -1)
        case "$line" in
            LOGIN_OK*)
                w=$(sed -n 's/.* wwid=\([^ ]*\).*/\1/p' <<<"$line")
                [ -z "$wwid" ] && wwid=$w
                [ "$w" = "$wwid" ] || bad="$bad $n(wwid=$w!=$wwid)" ;;
            *) bad="$bad $n(${line:-unreachable})" ;;
        esac
    done
    [ -z "$bad" ] || { echo "$g: login FAIL:$bad"; return 1; }
    echo "GROUP_OK $g nodes=[$set] target=$tgt lun0=$dev img=$img wwid=$wwid dev=$(dev_of "$g")"
}

status() {
    local g tgt
    for g in $(lab_groups); do
        tgt=$(tgt_of "$g")
        if [ -d "$T/$tgt" ]; then
            echo "$g: nodes=[$(lab_group "$g")] $tgt default_luns=[$(ls "$T/$tgt/luns" | grep -v mgmt | tr '\n' ' ')] grp_luns=[$(ls "$T/$tgt/ini_groups/grp/luns" 2>/dev/null | grep -v mgmt | tr '\n' ' ')] initiators=$(ls "$T/$tgt/ini_groups/grp/initiators" 2>/dev/null | grep -vc mgmt) sessions=$(sudo ls "$T/$tgt/sessions" 2>/dev/null | grep -vc mgmt)"
        else
            echo "$g: nodes=[$(lab_group "$g")] $tgt not present"
        fi
    done
}

case "${1:-}" in
    setup)
        shift
        disjoint || exit 2
        runlock_take "$RUNLOCK" shared "rig_groups.sh setup ${*:-all}" \
            || { echo "rig_groups: a whole-rig run holds $RUNLOCK: $(runlock_holder "$RUNLOCK")"; exit 3; }
        rc=0
        for g in ${*:-$(lab_groups)}; do setup_one "$g" || { echo "GROUP_FAIL $g" >&2; rc=1; }; done
        exit $rc ;;
    status) status ;;
    dev)    lab_group "${2:?group}" >/dev/null && dev_of "$2" ;;
    image)  lab_group "${2:?group}" >/dev/null && echo "$IMGDIR/disk-grp-$2.img" ;;
    *) echo "usage: $0 setup [<group> ...] | status | dev <group> | image <group>" >&2; exit 2 ;;
esac
