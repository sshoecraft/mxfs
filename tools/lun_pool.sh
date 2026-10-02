#!/bin/bash
# lun_pool.sh — a pool of fixed-size test LUNs on clyde's SCST target, handed
# out to a set of nodes for the length of one run and taken back after it.
#
# WHY.  Every test configuration used to get a LUN of its own, made for it and
# kept forever: the rig's :shared image, one per rig group, one per platform
# set, plus snapshots of the ones that went corrupt.  They were sparse, sized
# for the largest geometry anything had ever been graded on (128 GiB, 64 GiB),
# and a sparse file grows into whatever a test writes, on the one filesystem
# that also holds every guest image and the host journal.  A run needs A LUN,
# not ITS LUN: so the LUNs are generic, and a run borrows one.
#
# THE LUNS.  <pool dir>/lunNN.img, each a FIXED size allocated in full at
# create (fallocate), so it cannot grow and the pool's footprint is known the
# day it is made.  Each is an SCST vdisk_fileio device mxfspoolNN exported as
# its own target iqn.2026-05.local.mxfs:pool-NN.  The target has NO default
# LUN: LUN 0 lives only in the ini_group `alloc`, which holds the initiator
# names of the nodes the LUN is allocated to and nobody else's.  A free LUN's
# group is empty, so a node that logs in to it (a SendTargets discovery
# followed by a bare login does exactly that) sees no disk.
#
# ALLOCATION.  `alloc` records an owner — a pid and its start time — in
# <pool dir>/lunNN.owner.  While that process lives nobody else gets the LUN
# or any of its nodes: alloc refuses a node a live allocation holds, and an
# owner that asks again is handed the LUN it already holds (a run.sh started
# inside run.sh).  When the owner exits the allocation is KEPT, still bound:
# the cluster formed on it is intact, so the next run on exactly that node set
# adopts it without rebinding, and a filtered rerun finds its cluster still
# mounted.  A kept allocation is released when a new one names any of its
# nodes, or, oldest first, when no LUN is free; `free` releases one at once.
# A run that is killed therefore holds nothing anyone else needs.
#
# Binding a node logs it out of every target, deletes every node record,
# unmounts any mxfs on it and unloads the module, then logs it in to this
# LUN's target alone, with node.startup=automatic so a reboot logs it back in
# (the platform rounds reboot their nodes).  Every node must then read the
# same WWID through the device, or the allocation is undone.
#
# Nothing here formats a LUN.  The run that holds it formats it, and a stale
# filesystem left by the previous holder is what that format replaces.  A
# harness that wants a corrupt platter kept copies the image before its run
# ends: the next holder formats it.
#
# SCST objects are runtime-only: after a clyde reboot run `up`, which
# re-registers every image already in the pool.  Idempotent.
#
# Usage:
#   tools/lun_pool.sh create <count> [<size>]   add <count> LUNs (default 20G)
#   tools/lun_pool.sh up                        register every pool image with SCST
#   tools/lun_pool.sh alloc [--owner <pid>] [--what <text>] [--size <min>] [--paths 1|2] <node>...
#       --paths 2 logs every node in through both portals (storage portal= and
#       portal2= in the lab file) and hands out the multipath map, mpatha
#       prints: POOL_LUN id=NN size=<bytes> target=<iqn> dev=<guest path>
#                        wwid=<id> img=<host path> nodes=<a,b,..> owner=<pid>
#   tools/lun_pool.sh lookup --owner <pid>      the POOL_LUN line <pid> holds, if any
#   tools/lun_pool.sh lookup --nodes <a,b,..>   the line of the allocation (live or
#                                               kept) bound to exactly that node set
#   tools/lun_pool.sh free <id> | --owner <pid> [--force]
#   tools/lun_pool.sh status
#   tools/lun_pool.sh snapshot <id> <label>     copy a LUN's platter out of the pool
#   tools/lun_pool.sh destroy <id>              remove a free LUN and its image
#
# --owner defaults to the caller (the parent of this script).  free refuses a
# LUN whose live owner is not the one named unless --force.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
. "$HERE/tools/mxfs_lab.sh"
SSH="$HERE/tools/mxfs_sshpass.sh"
PORTAL=$(lab_need storage portal) || exit 2
PORTAL=${PORTAL%%:*}
# the second portal a multipath allocation logs in through (optional): every
# target is exported on both, and a single-path login names PORTAL itself
PORTAL2=$(lab_get storage portal2 2>/dev/null); PORTAL2=${PORTAL2%%:*}
POOL=$(lab_need paths pool) || exit 2
DEFAULT_SIZE=20G
T=/sys/kernel/scst_tgt/targets/iscsi
H=/sys/kernel/scst_tgt/handlers/vdisk_fileio
LOCKFILE=$POOL/.lock

tgt_of() { echo "iqn.2026-05.local.mxfs:pool-$1"; }
scstdev_of() { echo "mxfspool$1"; }
img_of() { echo "$POOL/lun$1.img"; }
owner_of() { echo "$POOL/lun$1.owner"; }
paths_of() { cat "$POOL/lun$1.paths" 2>/dev/null || echo 1; }
dev_of() {  # the guest device of an allocation: the by-path node, or the multipath map
    if [ "$(paths_of "$1")" = 2 ]; then echo /dev/mapper/mpatha
    else echo "/dev/disk/by-path/ip-$PORTAL:3260-iscsi-$(tgt_of "$1")-lun-0"; fi
}
ids() { local f; for f in "$POOL"/lun[0-9][0-9].img; do [ -e "$f" ] || continue; f=${f##*/lun}; echo "${f%.img}"; done; }
ssh_n() { timeout "${3:-30}" "$SSH" "$(lab_addr "$1")" "$2" </dev/null 2>&1 | grep -avE '^Warning:|^Unauthorized|^If you'; }
die() { echo "lun_pool: $*" >&2; exit 1; }

pool_lock() {  # serialise every decision about who holds what
    mkdir -p "$POOL" || die "cannot create $POOL"
    exec {LOCKFD}>>"$LOCKFILE" || die "cannot open $LOCKFILE"
    flock -w 60 "$LOCKFD" || die "pool lock not taken in 60 s: $LOCKFILE"
}
pool_unlock() { exec {LOCKFD}>&-; }

starttime_of() {  # <pid> -> field 22 of /proc/<pid>/stat, or nothing
    local s
    s=$(cat "/proc/$1/stat" 2>/dev/null) || return 0
    s=${s##*) }
    set -- $s
    echo "${20}"
}

# An owner file is one line:  <pid> <starttime> <nodes,comma> <iso time> <what...>
owner_field() {  # <id> <n> -> the n-th field (1-based) of the owner line
    awk -v n="$2" 'NR == 1 { print $n }' "$(owner_of "$1")" 2>/dev/null
}
owner_live() {  # <id> -> 0 iff the LUN has an owner and that process still runs
    local f pid st
    f=$(owner_of "$1")
    [ -s "$f" ] || return 1
    pid=$(owner_field "$1" 1); st=$(owner_field "$1" 2)
    [ -n "$pid" ] && [ "$(starttime_of "$pid")" = "$st" ]
}

lun_size() { stat -c %s "$(img_of "$1")" 2>/dev/null; }

register() {  # <id>: the SCST device and target exist, target has no default LUN
    local id=$1 tgt dev img g
    tgt=$(tgt_of "$id"); dev=$(scstdev_of "$id"); img=$(img_of "$id")
    if [ -n "$PORTAL2" ] && ! ip -4 addr show br0 | grep -q "inet $PORTAL2/"; then
        sudo ip addr add "$PORTAL2/24" dev br0 || { echo "lun_pool: cannot add portal $PORTAL2 to br0" >&2; return 1; }
    fi
    MXFS_SCST_IMG=$img MXFS_SCST_DEV=$dev MXFS_SCST_TGT=$tgt MXFS_SCST_PORTAL_IP="$PORTAL${PORTAL2:+ $PORTAL2}" \
        timeout 60 "$HERE/scripts/scst_setup.sh" setup | grep -E 'SCST_SETUP|FAIL' >/dev/null || return 1
    # scst_setup.sh reuses a device of the same name whatever file it holds.
    g=$(sudo cat "/sys/kernel/scst_tgt/devices/$dev/filename" 2>/dev/null | head -1)
    [ "$g" = "$img" ] || { echo "lun_pool: SCST device $dev holds '$g', not $img" >&2; return 1; }
    g=$T/$tgt/ini_groups
    [ -d "$g/alloc" ] || echo "create alloc" | sudo tee "$g/mgmt" >/dev/null || return 1
    [ -d "$g/alloc/luns/0" ] || echo "add $dev 0" | sudo tee "$g/alloc/luns/mgmt" >/dev/null || return 1
    if [ -d "$T/$tgt/luns/0" ]; then
        echo "del 0" | sudo tee "$T/$tgt/luns/mgmt" >/dev/null || return 1
    fi
    return 0
}

set_initiators() {  # <id> <iqn>...: the alloc group holds exactly these
    local id=$1 g ini; shift
    g=$T/$(tgt_of "$id")/ini_groups/alloc/initiators
    [ -d "$g" ] || return 1
    for ini in "$@"; do
        [ -e "$g/$ini" ] || echo "add $ini" | sudo tee "$g/mgmt" >/dev/null || return 1
    done
    for ini in $(ls "$g" | grep -v '^mgmt$'); do
        case " $* " in *" $ini "*) ;; *) echo "del $ini" | sudo tee "$g/mgmt" >/dev/null || return 1 ;; esac
    done
}

initiator_of() {  # <node> -> its InitiatorName, or nothing
    # Three tries 5 s apart: a set is allocated right after it is powered up,
    # and 0.90.39's debian13-1 missed the one ssh it got on a host deep in
    # swap, which cost that platform its whole round.  A name that stays
    # unreadable for three tries still fails the allocation.
    local i ini
    for i in 1 2 3; do
        ini=$(ssh_n "$1" 'sed -n "s/^InitiatorName=//p" /etc/iscsi/initiatorname.iscsi' | grep -a '^iqn\.' | tail -1)
        [ -n "$ini" ] && { echo "$ini"; return 0; }
        [ $i -lt 3 ] && sleep 5
    done
}

# Unmount every mxfs on the node.  The mountpoint gate before fuser -km is
# load-bearing: on a directory that is not a mountpoint fuser resolves to the
# root filesystem and kills sshd.  Each umount is bounded: an unbounded one
# that hangs in the kernel is a task nothing can kill.
NODE_UNMOUNT='
    for m in $(awk "\$3 == \"mxfs\" {print \$2}" /proc/mounts); do
        for t in 1 2 3 4 5; do
            mountpoint -q "$m" || break
            fuser -km "$m" 2>/dev/null; sleep 1
            timeout 30 umount "$m" 2>/dev/null && break
            sleep 1
        done
    done
    if grep -q " mxfs " /proc/mounts; then echo UNMOUNT_FAIL; exit 0; fi'

NODE_LOGIN=$NODE_UNMOUNT'
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

# Two paths: a node record per portal, both logged in at boot, and multipathd
# assembling them as mpatha.  The wwids and bindings files are cleared so this
# LUN's map is the one named mpatha.  The WWID reported is the SCSI one of a
# path under the map, the same identifier a single-path node reads.
NODE_LOGIN_MP=$NODE_UNMOUNT'
    for t in 1 2 3 4 5; do lsmod | grep -q "^mxfs " || break; rmmod mxfs 2>/dev/null && break; sleep 2; done
    lsmod | grep -q "^mxfs " && { echo LOGIN_FAIL mxfs still loaded; exit 0; }
    iscsiadm -m node -u >/dev/null 2>&1
    iscsiadm -m node -o delete >/dev/null 2>&1
    multipath -F >/dev/null 2>&1
    mkdir -p /etc/multipath/conf.d
    printf "defaults {\n    find_multipaths yes\n}\n" > /etc/multipath/conf.d/mxfs.conf
    > /etc/multipath/wwids 2>/dev/null
    rm -f /etc/multipath/bindings 2>/dev/null
    systemctl enable iscsid multipathd >/dev/null 2>&1
    systemctl restart multipathd >/dev/null 2>&1
    for p in PORTAL PORTAL2; do
        iscsiadm -m node -o new -T TGT -p $p:3260 >/dev/null 2>&1
        iscsiadm -m node -T TGT -p $p:3260 --op update -n node.startup -v automatic >/dev/null 2>&1
        iscsiadm -m node -T TGT -p $p:3260 --login >/dev/null 2>&1
    done
    iscsiadm -m session --rescan >/dev/null 2>&1
    for t in $(seq 1 15); do
        multipath >/dev/null 2>&1
        n=$(multipath -ll mpatha 2>/dev/null | grep -cE "[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ ")
        if [ -b /dev/mapper/mpatha ] && [ "${n:-0}" -ge 2 ]; then
            sd=$(ls /sys/block/$(basename $(readlink -f /dev/mapper/mpatha))/slaves | head -1)
            echo "LOGIN_OK paths=$n wwid=$(cat /sys/block/$sd/device/wwid 2>/dev/null | tr -d " ")"
            exit 0
        fi
        sleep 2
    done
    echo "LOGIN_FAIL paths=${n:-0} map=$([ -b /dev/mapper/mpatha ] && echo yes || echo no)"'

NODE_LOGOUT=$NODE_UNMOUNT'
    multipath -F >/dev/null 2>&1
    for p in PORTAL PORTAL2; do
        iscsiadm -m node -T TGT -p $p:3260 -u >/dev/null 2>&1
        iscsiadm -m node -T TGT -p $p:3260 -o delete >/dev/null 2>&1
    done
    echo LOGOUT_OK'

subst() {  # <snippet> <id>
    local s=${1//TGT/$(tgt_of "$2")}
    s=${s//PORTAL2/${PORTAL2:-$PORTAL}}
    s=${s//PORTAL/$PORTAL}
    echo "${s//DEVPATH/$(dev_of "$2")}"
}

release() {  # <id>: log the owner's nodes out, empty the group, drop the owner file
    local id=$1 nodes n td snippet bad=""
    nodes=$(owner_field "$id" 3 | tr ',' ' ')
    if [ -n "$nodes" ]; then
        snippet=$(subst "$NODE_LOGOUT" "$id")
        td=$(mktemp -d)
        for n in $nodes; do ( ssh_n "$n" "$snippet" 150 > "$td/$n" ) & done
        wait
        for n in $nodes; do grep -aq '^LOGOUT_OK' "$td/$n" || bad="$bad $n"; done
        rm -rf "$td"
        [ -z "$bad" ] || echo "lun_pool: lun$id: no clean logout from:$bad (its group is emptied anyway; the node sees no disk)" >&2
    fi
    if [ -d "$T/$(tgt_of "$id")" ]; then
        set_initiators "$id" || { echo "lun_pool: lun$id: could not empty its initiator group" >&2; return 1; }
    fi
    : > "$(owner_of "$id")"
    unlink "$POOL/lun$id.paths" 2>/dev/null
    return 0
}

reclaim_stale() {  # under the pool lock: release every allocation whose owner is gone
    local id
    for id in $(ids); do
        [ -s "$(owner_of "$id")" ] || continue
        owner_live "$id" && continue
        echo "lun_pool: lun$id: owner $(owner_field "$id" 1) ($(cut -d' ' -f5- "$(owner_of "$id")")) is gone; reclaiming" >&2
        release "$id"
    done
}

pool_line() {  # <id> -> the POOL_LUN line for a held LUN
    echo "POOL_LUN id=$1 size=$(lun_size "$1") target=$(tgt_of "$1") dev=$(dev_of "$1") wwid=$(cat "$POOL/lun$1.wwid" 2>/dev/null) img=$(img_of "$1") nodes=$(owner_field "$1" 3) owner=$(owner_field "$1" 1)"
}

cmd_create() {
    local count=${1:?usage: create <count> [<size>]} size=${2:-$DEFAULT_SIZE} bytes id next img
    [[ "$count" =~ ^[0-9]+$ ]] && [ "$count" -ge 1 ] || die "count must be a positive integer"
    bytes=$(numfmt --from=iec "$size" 2>/dev/null) || die "bad size $size"
    [ "$bytes" -ge $((1 << 30)) ] || die "size $size is under 1G"
    pool_lock
    next=1
    for id in $(ids); do [ "$((10#$id))" -ge "$next" ] && next=$((10#$id + 1)); done
    while [ "$count" -gt 0 ]; do
        id=$(printf %02d "$next")
        [ "$next" -le 99 ] || die "the pool holds at most 99 LUNs"
        img=$(img_of "$id")
        fallocate -l "$bytes" "$img" || die "fallocate $size $img failed"
        [ "$(( $(stat -c %b "$img") * $(stat -c %B "$img") ))" -ge "$bytes" ] \
            || die "$img is not fully allocated after fallocate"
        : > "$(owner_of "$id")"
        register "$id" || die "lun$id: SCST registration failed"
        echo "created lun$id $size $(tgt_of "$id") $img"
        next=$((next + 1)); count=$((count - 1))
    done
    pool_unlock
}

cmd_up() {
    local id rc=0 ini n
    pool_lock
    for id in $(ids); do
        register "$id" || { echo "lun_pool: lun$id: SCST registration failed" >&2; rc=1; continue; }
        if owner_live "$id"; then
            # a live allocation survives an SCST rebuild with its nodes bound
            local inis=()
            for n in $(owner_field "$id" 3 | tr ',' ' '); do
                ini=$(initiator_of "$n"); [ -n "$ini" ] && inis+=("$ini")
            done
            set_initiators "$id" "${inis[@]}" || rc=1
        else
            set_initiators "$id" || rc=1
            : > "$(owner_of "$id")"
        fi
        echo "up lun$id $(tgt_of "$id")"
    done
    pool_unlock
    return $rc
}

cmd_alloc() {
    local owner=$PPID what="" min=0 paths=1 nodes=() id n held best="" bestsize=0 sz
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --owner) owner=${2:?}; shift 2 ;;
            --what) what=${2:?}; shift 2 ;;
            --size) min=$(numfmt --from=iec "${2:?}") || die "bad size $2"; shift 2 ;;
            --paths) paths=${2:?}; shift 2 ;;
            -*) die "unknown option $1" ;;
            *) nodes+=("$1"); shift ;;
        esac
    done
    [ "${#nodes[@]}" -ge 1 ] || die "alloc needs at least one node"
    case "$paths" in 1) ;; 2) [ -n "$PORTAL2" ] || die "--paths 2 needs a second portal: storage portal2= in $MXFS_LAB" ;;
        *) die "--paths is 1 or 2" ;; esac
    local st; st=$(starttime_of "$owner")
    [ -n "$st" ] || die "owner pid $owner is not running"
    local want; want=$(IFS=,; echo "${nodes[*]}")
    local claim="$owner $st $want $(date -u +%FT%TZ) ${what:-$(cat "/proc/$owner/comm" 2>/dev/null)}"
    pool_lock
    for id in $(ids); do
        owner_live "$id" || continue
        if [ "$(owner_field "$id" 1)" = "$owner" ]; then
            [ "$(owner_field "$id" 3)" = "$want" ] && [ "$(paths_of "$id")" = "$paths" ] \
                || die "owner $owner already holds lun$id for [$(owner_field "$id" 3)] on $(paths_of "$id") path(s), not [$want] on $paths"
            pool_unlock
            pool_line "$id"
            return 0
        fi
        held=",$(owner_field "$id" 3),"
        for n in "${nodes[@]}"; do
            case "$held" in *",$n,"*) die "$n is held by lun$id's allocation: $(cat "$(owner_of "$id")")" ;; esac
        done
    done
    # A finished run's LUN stays bound to its nodes: the cluster it formed is
    # still there, and a later run on the same node set re-uses it rather than
    # rebinding (which unmounts and unloads every node).  It is adopted when
    # it is still bound — its target registered with exactly those nodes'
    # initiators in its group — and released when the node sets only overlap.
    for id in $(ids); do
        [ -s "$(owner_of "$id")" ] && ! owner_live "$id" || continue
        if [ "$(owner_field "$id" 3)" = "$want" ] && [ "$(lun_size "$id")" -ge "$min" ] \
           && [ "$(paths_of "$id")" = "$paths" ] \
           && [ "$(ls "$T/$(tgt_of "$id")/ini_groups/alloc/initiators" 2>/dev/null | grep -vc '^mgmt$')" = "${#nodes[@]}" ] \
           && [ -s "$POOL/lun$id.wwid" ]; then
            echo "$claim" > "$(owner_of "$id")"
            pool_unlock
            pool_line "$id"
            return 0
        fi
        held=",$(owner_field "$id" 3),"
        for n in "${nodes[@]}"; do
            case "$held" in *",$n,"*)
                echo "lun_pool: lun$id: its finished allocation holds $n; releasing it" >&2
                release "$id"; break ;;
            esac
        done
    done
    pick_free() {
        local i s
        best=""; bestsize=0
        for i in $(ids); do
            [ -s "$(owner_of "$i")" ] && continue
            s=$(lun_size "$i")
            [ "$s" -ge "$min" ] || continue
            if [ -z "$best" ] || [ "$s" -lt "$bestsize" ]; then best=$i; bestsize=$s; fi
        done
    }
    pick_free
    if [ -z "$best" ]; then
        # No free LUN: take back finished allocations, oldest first.
        for id in $(for i in $(ids); do [ -s "$(owner_of "$i")" ] && ! owner_live "$i" && echo "$(owner_field "$i" 4) $i"; done | sort | awk '{print $2}'); do
            [ "$(lun_size "$id")" -ge "$min" ] || continue
            echo "lun_pool: lun$id: no free LUN; releasing the finished allocation $(cut -d' ' -f3- "$(owner_of "$id")")" >&2
            release "$id"
            break
        done
        pick_free
    fi
    [ -n "$best" ] || die "no LUN of at least $(numfmt --to=iec "$min") is free (tools/lun_pool.sh status; tools/lun_pool.sh create 1 <size> adds one)"
    id=$best
    echo "$claim" > "$(owner_of "$id")"
    echo "$paths" > "$POOL/lun$id.paths"
    pool_unlock

    # Bind outside the lock: the owner file already claims the LUN and the nodes.
    local inis=() ini td snippet line w wwid="" bad=""
    register "$id" || { pool_lock; release "$id"; pool_unlock; die "lun$id: SCST registration failed"; }
    for n in "${nodes[@]}"; do
        ini=$(initiator_of "$n")
        [ -n "$ini" ] || { pool_lock; release "$id"; pool_unlock; die "no initiator name from $n"; }
        inis+=("$ini")
    done
    set_initiators "$id" "${inis[@]}" || { pool_lock; release "$id"; pool_unlock; die "lun$id: could not set its initiator group"; }
    if [ "$paths" = 2 ]; then snippet=$(subst "$NODE_LOGIN_MP" "$id")
    else snippet=$(subst "$NODE_LOGIN" "$id"); fi
    td=$(mktemp -d)
    for n in "${nodes[@]}"; do ( ssh_n "$n" "$snippet" 180 > "$td/$n" ) & done
    wait
    for n in "${nodes[@]}"; do
        line=$(grep -a -E '^(LOGIN_(OK|FAIL)|UNMOUNT_FAIL)' "$td/$n" | tail -1)
        case "$line" in
            LOGIN_OK*)
                w=$(sed -n 's/.* wwid=\([^ ]*\).*/\1/p' <<<"$line")
                [ -n "$w" ] || { bad="$bad $n(no wwid)"; continue; }
                [ -z "$wwid" ] && wwid=$w
                [ "$w" = "$wwid" ] || bad="$bad $n(wwid=$w!=$wwid)" ;;
            *) bad="$bad $n(${line:-unreachable})" ;;
        esac
    done
    rm -rf "$td"
    if [ -n "$bad" ]; then
        pool_lock; release "$id"; pool_unlock
        die "lun$id: bind FAIL:$bad"
    fi
    echo "$wwid" > "$POOL/lun$id.wwid"
    pool_line "$id"
}

cmd_lookup() {
    local id
    case "${1:-}" in
        --owner)
            [ -n "${2:-}" ] || die "usage: lookup --owner <pid> | --nodes <a,b,..>"
            for id in $(ids); do
                owner_live "$id" && [ "$(owner_field "$id" 1)" = "$2" ] && { pool_line "$id"; return 0; }
            done ;;
        --nodes)
            [ -n "${2:-}" ] || die "usage: lookup --owner <pid> | --nodes <a,b,..>"
            for id in $(ids); do
                [ "$(owner_field "$id" 3)" = "$2" ] && { pool_line "$id"; return 0; }
            done ;;
        *) die "usage: lookup --owner <pid> | --nodes <a,b,..>" ;;
    esac
    return 1
}

# A copy of a LUN's platter, kept outside the pool: the next holder formats
# the LUN, so evidence of a corrupt filesystem has to leave it first.  Sparse,
# so a 20 GiB LUN costs what the filesystem had written.  Copy only while no
# node writes to it (the caller's cluster unmounted, or audited cold).
cmd_snapshot() {
    local id label dir snap
    id=$(printf %02d "$((10#${1:?usage: snapshot <id> <label>}))")
    label=${2:?usage: snapshot <id> <label>}
    [ -e "$(img_of "$id")" ] || die "no lun$id in $POOL"
    dir=$(dirname "$POOL")/snapshots
    mkdir -p "$dir" || die "cannot create $dir"
    snap=$dir/lun$id-$label-$(date -u +%Y%m%dT%H%M%SZ).img
    cp --sparse=always "$(img_of "$id")" "$snap" || die "copy to $snap failed"
    echo "$snap"
}

cmd_free() {
    local id="" owner="" force=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --owner) owner=${2:?}; shift 2 ;;
            --force) force=1; shift ;;
            *) id=$(printf %02d "$((10#$1))") || die "bad id $1"; shift ;;
        esac
    done
    pool_lock
    if [ -z "$id" ]; then
        [ -n "$owner" ] || die "usage: free <id> | --owner <pid> [--force]"
        local i
        for i in $(ids); do [ "$(owner_field "$i" 1)" = "$owner" ] && id=$i; done
        [ -n "$id" ] || { pool_unlock; echo "lun_pool: owner $owner holds no LUN"; return 0; }
    fi
    [ -e "$(img_of "$id")" ] || die "no lun$id in $POOL"
    [ -s "$(owner_of "$id")" ] || { pool_unlock; echo "lun$id already free"; return 0; }
    if owner_live "$id" && [ "$force" = 0 ] && [ "$(owner_field "$id" 1)" != "${owner:-$PPID}" ]; then
        die "lun$id is held by live owner: $(cat "$(owner_of "$id")") (--force to take it back)"
    fi
    release "$id"
    pool_unlock
    echo "freed lun$id"
}

cmd_status() {
    local id tgt state inis sess alloc
    [ -d "$POOL" ] || { echo "no pool at $POOL"; return 0; }
    printf '%-6s %-7s %-9s %-6s %-30s %-5s %-5s %s\n' LUN SIZE ON-DISK STATE NODES INIS SESS OWNER
    for id in $(ids); do
        tgt=$T/$(tgt_of "$id")
        if [ ! -s "$(owner_of "$id")" ]; then state=free
        elif owner_live "$id"; then state=held
        else state=kept; fi
        if [ -d "$tgt" ]; then
            inis=$(ls "$tgt/ini_groups/alloc/initiators" 2>/dev/null | grep -vc '^mgmt$')
            sess=$(sudo ls "$tgt/sessions" 2>/dev/null | grep -vc '^mgmt$')
        else
            inis=-; sess=-; state="$state/unreg"
        fi
        alloc=$(( $(stat -c %b "$(img_of "$id")") * $(stat -c %B "$(img_of "$id")") ))
        printf '%-6s %-7s %-9s %-6s %-30s %-5s %-5s %s\n' "lun$id" "$(numfmt --to=iec "$(lun_size "$id")")" \
            "$(numfmt --to=iec --round=nearest "$alloc")" "$state" "$(owner_field "$id" 3)" "$inis" "$sess" \
            "$(cut -d' ' -f1,4- "$(owner_of "$id")" 2>/dev/null)"
    done
}

cmd_destroy() {
    local id tgt dev
    id=$(printf %02d "$((10#${1:?usage: destroy <id>}))")
    pool_lock
    reclaim_stale
    [ -e "$(img_of "$id")" ] || die "no lun$id in $POOL"
    [ -s "$(owner_of "$id")" ] && die "lun$id is allocated: $(cat "$(owner_of "$id")")"
    tgt=$(tgt_of "$id"); dev=$(scstdev_of "$id")
    if [ -d "$T/$tgt" ]; then
        [ "$(sudo ls "$T/$tgt/sessions" 2>/dev/null | grep -vc '^mgmt$')" = 0 ] \
            || die "lun$id: $tgt still has sessions; free it from its nodes first"
        echo 0 | sudo tee "$T/$tgt/enabled" >/dev/null
        echo "del_target $tgt" | sudo tee "$T/mgmt" >/dev/null || die "del_target $tgt failed"
    fi
    if [ -d "/sys/kernel/scst_tgt/devices/$dev" ]; then
        echo "del_device $dev" | sudo tee "$H/mgmt" >/dev/null || die "del_device $dev failed"
    fi
    unlink "$(img_of "$id")" || die "could not remove $(img_of "$id")"
    unlink "$(owner_of "$id")" 2>/dev/null
    unlink "$POOL/lun$id.wwid" 2>/dev/null
    unlink "$POOL/lun$id.paths" 2>/dev/null
    pool_unlock
    echo "destroyed lun$id"
}

case "${1:-}" in
    create)  shift; cmd_create "$@" ;;
    up)      shift; cmd_up ;;
    alloc)   shift; cmd_alloc "$@" ;;
    lookup)  shift; cmd_lookup "$@" ;;
    free)    shift; cmd_free "$@" ;;
    status)  cmd_status ;;
    snapshot) shift; cmd_snapshot "$@" ;;
    destroy) shift; cmd_destroy "$@" ;;
    *) echo "usage: $0 create <count> [<size>] | up | alloc [--owner <pid>] [--what <text>] [--size <min>] <node>... | lookup --owner <pid> | lookup --nodes <a,b,..> | free <id>|--owner <pid> [--force] | status | snapshot <id> <label> | destroy <id>" >&2; exit 2 ;;
esac
