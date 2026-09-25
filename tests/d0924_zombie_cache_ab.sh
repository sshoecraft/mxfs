#!/bin/bash
# d0924_zombie_cache_ab.sh — is a module-unload "Objects remaining in mxfs_buf"
# report THIS load's leak, or a previous load's leak reported again?
#
# THE EVIDENCE THAT ASKED THE QUESTION.  In test1's 2026-09-08 boot, three
# unloads of three different builds (tests/evidence/20260908T212931Z_unload_s544g,
# 20260908T213600Z_unload_s545b, 20260908T214051Z_unload_s545d) each reported
# six objects remaining in mxfs_buf — the SAME six hashed addresses at the SAME
# slab offsets every time.  A fresh module load allocates from a fresh cache and
# cannot hand back a previous load's leaked objects, unless the cache was not
# fresh: when kmem_cache_destroy finds objects remaining it leaves the cache on
# the slab list with refcount 0, and the node kernel's kmem_cache_create merges a
# same-shape request with any listed mergeable cache (refcount 0 is mergeable;
# only a negative refcount is not), so the next load adopts the zombie, its
# stranded objects and all, and re-reports them at its own unload.  The build
# that "fixed" the leak grew struct xfs_buf by 16 bytes: a different size no
# longer merges.  The mxfs_buf sysfs entry on the nodes is an alias symlink,
# which is what a mergeable cache looks like.
#
# WHAT THIS MEASURES.  On one node, one boot, six load/unload cycles with a test
# knob that leaks exactly N buffer structs at unmount (dbg_leak_bufs: xfs_buf_free
# skips the RCU free for the next N buffers and prints each one's hashed
# address, the same hash the slab report prints):
#
#   control arm  (slab_merge=1, the pre-fix cache flags)
#     c1 leak 1  -> the unload reports 1 object, address X
#     c2 leak 0  -> the unload reports 1 object again, address X  (re-report)
#     c3 leak 0  -> the unload reports 1 object again, address X
#   fixed arm    (default: every mxfs cache created unmergeable)
#     c4 leak 0  -> no report (a fresh cache; the zombie from the control arm is
#                   not adopted)
#     c5 leak 1  -> the unload reports 1 object, address Y
#     c6 leak 0  -> no report (each load's report is its own)
#
# The peer stays UNMOUNTED for the cycles so the survivor's unmount is the cheap
# one (~3 s, not the 35-80 s per-page authority handoff), and the node is
# destroyed/started at the end: the deliberate leak sets the B and W taint bits
# and leaves zombie caches that only a reboot clears.  The fleet is then
# re-formed with prep_cluster.
#
# derived time budget: B umount with A live <= 80 s; per cycle umount ~3 s +
# rmmod ~2 s + captures ~3 s + insmod ~2 s + mount ~5 s = 15 s, x6 = 90 s;
# virsh destroy/start + ssh back ~60-150 s; prep 41-81 s.  Whole lap <= 400 s.
#
# Usage: tests/d0924_zombie_cache_ab.sh <label>
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; DEV=$MXFS_DEV_RESOLVED
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0924zombie_$LABEL
mkdir -p "$OUT"
filt() { grep -av '^Unauthorized\|^Warning:\|^If you\|^$'; }
# rs: tests/lib/rig.sh (sourced above) provides the same helper; a local copy would shadow it
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
KO=/root/mxfs.ko.prep      # the node-local copy prep_node.sh loads from
# The same load arguments tests/setup/prep_node.sh uses for this transport.
# target_cache_protected=1 is not optional: without it the mount is refused
# (rc=32) and every cycle after the first measures an unmounted node.
MODARGS="force_transport=1 target_cache_protected=1"
echo "=== d0924_zombie_cache_ab label=$LABEL A=$A B=$B sv=$SV $(date -u +%FT%TZ) ==="

# ---- preconditions ---------------------------------------------------------
fails=0
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion 2>/dev/null) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts) ko=\$(md5sum $KO 2>/dev/null | cut -c1-8) knob=\$(cat /sys/module/mxfs/parameters/dbg_leak_bufs 2>/dev/null) merge=\$(cat /sys/module/mxfs/parameters/slab_merge 2>/dev/null)" | tr -d '\n')
    echo "  INFO $n $st"
    case "$st" in "sv=$SV mnt=1 "*) ;; *) echo "  FAIL $n precondition (want sv=$SV mnt=1)"; fails=$((fails+1)) ;; esac
done
[ $fails = 0 ] || { echo "RESULT: FAIL label=$LABEL precondition fails=$fails"; exit 2; }
kmd5=$(md5sum mxfs.ko | cut -c1-8)
amd5=$(rs 25 "$A" "md5sum $KO | cut -c1-8")
[ "$kmd5" = "$amd5" ] || { echo "RESULT: FAIL label=$LABEL $A's $KO ($amd5) is not the tree's mxfs.ko ($kmd5)"; exit 2; }
# the knob must exist on this build or the leak cycles measure nothing
[ -n "$(rs 25 "$A" "cat /sys/module/mxfs/parameters/dbg_leak_bufs 2>/dev/null")" ] || { echo "RESULT: FAIL label=$LABEL build has no dbg_leak_bufs knob"; exit 2; }
TAINT0=$(rs 25 "$A" "cat /proc/sys/kernel/tainted")
echo "PRECOND_OK both on $SV, $A taint=$TAINT0"

# B leaves so A's unmounts are the lone ones
t0=$(date +%s)
rs 120 "$B" "sync; timeout 100 umount $MNT; echo B_UMOUNT_RC=\$?" | tr '\n' ' '; echo " wall=$(( $(date +%s) - t0 ))s"

# ---- one cycle: set the knob, unmount, unload, read the report, reload, mount
# $1 tag  $2 modargs for the NEXT load  $3 objects to leak at this unmount
cycle() {
    # Each name on its own `local`: bash expands every word of a `local` command
    # before it performs any of the assignments, so "local tag=$1 mk=...$tag"
    # reads an unset tag and set -u aborts the run.
    local tag=$1
    local args=$2
    local leak=$3
    local mk="D0924Z-$LABEL-$tag"
    local f="$OUT/cycle_$tag.txt"
    rs 120 "$A" "echo '$mk' > /dev/kmsg
        echo SYSFS_BEFORE=\$(readlink /sys/kernel/slab/mxfs_buf 2>/dev/null || { [ -d /sys/kernel/slab/mxfs_buf ] && echo DIR; })
        echo MERGE_LOADED=\$(cat /sys/module/mxfs/parameters/slab_merge 2>/dev/null)
        if [ $leak -gt 0 ]; then echo $leak > /sys/module/mxfs/parameters/dbg_leak_bufs; fi
        echo KNOB_SET=\$(cat /sys/module/mxfs/parameters/dbg_leak_bufs)
        t0=\$(date +%s%N); timeout 60 umount $MNT; echo URC=\$?
        echo KNOB_LEFT=\$(cat /sys/module/mxfs/parameters/dbg_leak_bufs)
        timeout 30 rmmod mxfs; echo RRC=\$?; t1=\$(date +%s%N); echo UNLOAD_MS=\$(( (t1 - t0) / 1000000 ))
        sleep 1
        echo SLABINFO_AFTER=\$(grep -a '^mxfs_buf ' /proc/slabinfo | awk '{print \"active=\"\$2\" num=\"\$3\" size=\"\$4}')
        echo SYSFS_AFTER=\$(readlink /sys/kernel/slab/mxfs_buf 2>/dev/null || { [ -d /sys/kernel/slab/mxfs_buf ] && echo DIR; } || echo GONE)
        echo TAINT=\$(cat /proc/sys/kernel/tainted)
        dmesg | sed -n '/$mk/,\$p' | grep -a 'Objects remaining\|Object 0x\|Slab cache still\|P-DBG-LEAK-BUF\|WARNING: CPU' | cut -c1-200
        insmod $KO dyndbg=+p $MODARGS $args; echo IRC=\$?
        timeout 60 mount -t mxfs $DEV $MNT; echo MRC=\$?
        # A refused mount makes every later cycle vacuous — no buffers are
        # allocated, so the leak knob strands nothing and the arm reports 0
        # objects for the same reason a fixed build would.  Say why, here.
        if ! grep -q ' $MNT mxfs ' /proc/mounts; then
            echo MOUNT_REFUSED_REASON=\"\$(dmesg | sed -n '/$mk/,\$p' | grep -a 'mxfs' | tail -5 | tr '\n' '|' | cut -c1-400)\"
        fi
        echo SV_LOADED=\$(cat /sys/module/mxfs/srcversion) MERGE_NEXT=\$(cat /sys/module/mxfs/parameters/slab_merge)
        echo SYSFS_LOADED=\$(readlink /sys/kernel/slab/mxfs_buf 2>/dev/null || { [ -d /sys/kernel/slab/mxfs_buf ] && echo DIR; })" > "$f" 2>&1
    local objs addrs leaked
    objs=$(grep -ac 'Object 0x' "$f"); addrs=$(grep -ao 'Object 0x[0-9a-f]*' "$f" | sed 's/Object //' | sort | tr '\n' ',')
    leaked=$(grep -a 'P-DBG-LEAK-BUF' "$f" | grep -ao 'bp=0x[0-9a-f]*' | sed 's/^bp=//' | sort | tr '\n' ',')
    echo "CYCLE tag=$tag leak=$leak next_args='$args' $(grep -a 'URC=\|RRC=\|IRC=\|MRC=\|UNLOAD_MS=\|KNOB_SET=\|KNOB_LEFT=\|MERGE_LOADED=\|SYSFS_BEFORE=\|SYSFS_AFTER=\|SLABINFO_AFTER=\|TAINT=\|SV_LOADED=\|SYSFS_LOADED=\|MOUNT_REFUSED_REASON=' "$f" | tr '\n' ' ') report_objects=$objs report_addrs=$addrs leaked_addrs=$leaked cache_still=$(grep -ac 'Slab cache still' "$f")"
    eval "OBJ_$tag=$objs; ADDR_$tag='$addrs'; LEAKED_$tag='$leaked'"
    eval "URC_$tag=$(sed -n 's/^URC=//p' "$f" | head -1); RRC_$tag=$(sed -n 's/^RRC=//p' "$f" | head -1); MRC_$tag=$(sed -n 's/^MRC=//p' "$f" | head -1)"
}

# c0: swap the prep load (default flags) for the control arm's mergeable one.
cycle c0 "slab_merge=1" 0
# Stop here if c0 did not leave a mounted filesystem behind.  Every later cycle
# would run against an unmounted node, allocate no buffers, strand none at the
# knob, and report zero objects in BOTH arms — a lap that reads like a clean
# result while having exercised nothing.
[ "${MRC_c0:-x}" = 0 ] || { echo "RESULT: FAIL label=$LABEL c0 left the node unmounted (MRC=${MRC_c0:-x}) — every later cycle would be vacuous; see $OUT/cycle_c0.txt"; exit 2; }
cycle c1 "slab_merge=1" 1
cycle c2 "slab_merge=1" 0
cycle c3 "" 0
cycle c4 "" 0
cycle c5 "" 1
cycle c6 "" 0

# ---- verdict from the raw numbers -------------------------------------------
BAD=0; NOTE=""
chk() { [ "$1" = "$2" ] || { BAD=$((BAD+1)); NOTE="$NOTE [$3: got=$1 want=$2]"; }; }
for t in c0 c1 c2 c3 c4 c5 c6; do
    eval "u=\$URC_$t; r=\$RRC_$t; m=\$MRC_$t"
    chk "${u:-x}" 0 "$t umount"; chk "${r:-x}" 0 "$t rmmod"
    chk "${m:-x}" 0 "$t mount"
done
chk "$OBJ_c0" 0 "c0 prep load leaked nothing"
chk "$OBJ_c1" 1 "c1 control leak reported once"
chk "$LEAKED_c1" "$ADDR_c1" "c1 the reported object is the one the knob leaked"
# the re-report: c2 and c3 unload loads that leaked nothing, yet report c1's object
chk "$OBJ_c2" 1 "c2 control re-report count"; chk "$ADDR_c2" "$ADDR_c1" "c2 control re-report address"
chk "$OBJ_c3" 1 "c3 control re-report count"; chk "$ADDR_c3" "$ADDR_c1" "c3 control re-report address"
chk "$OBJ_c4" 0 "c4 fixed load reports nothing (zombie not adopted)"
chk "$OBJ_c5" 1 "c5 fixed leak reported once"
chk "$LEAKED_c5" "$ADDR_c5" "c5 the reported object is the one the knob leaked"
chk "$OBJ_c6" 0 "c6 fixed load after a leak reports nothing"
[ "$ADDR_c5" != "$ADDR_c1" ] || { BAD=$((BAD+1)); NOTE="$NOTE [c5 reported the control arm's object]"; }
# cache shape: a mergeable cache's sysfs entry is an alias symlink (SLUB names
# the directory by a unique id and links the cache name to it).  The control
# loads must show that.  The fixed loads are recorded only: once a zombie's
# alias symlink named mxfs_buf exists, a later unmergeable cache of that name
# cannot add its own sysfs directory (EEXIST) and the stale link is what is
# read, so the shape after c1 says nothing about the new cache.
for t in c0 c1 c2; do s=$(sed -n 's/^SYSFS_LOADED=//p' "$OUT/cycle_$t.txt"); case "$s" in :*) ;; *) BAD=$((BAD+1)); NOTE="$NOTE [$t control load sysfs='$s' (want an alias)]";; esac; done
echo "SYSFS fixed loads: $(for t in c3 c4 c5 c6; do printf '%s=%s ' "$t" "$(sed -n 's/^SYSFS_LOADED=//p' "$OUT/cycle_$t.txt")"; done)"

echo "D0924Z label=$LABEL sv=$SV control: c1=$OBJ_c1 c2=$OBJ_c2 c3=$OBJ_c3 addrs c1=$ADDR_c1 c2=$ADDR_c2 c3=$ADDR_c3 | fixed: c4=$OBJ_c4 c5=$OBJ_c5 c6=$OBJ_c6 addr c5=$ADDR_c5 | bad=$BAD$NOTE evidence=$OUT"

# ---- restore: the node carries the deliberate leak's taint and two zombie
# caches; only a reboot clears them.  Then re-form the fleet.
echo "RESTORE destroy/start $A $(date -u +%T)"
virsh -c qemu:///system destroy "$A" >/dev/null 2>&1; sleep 3
virsh -c qemu:///system start "$A" >/dev/null 2>&1
up=""
for i in $(seq 1 15); do sleep 10; up=$(rs 15 "$A" "uptime" 2>/dev/null | grep -a 'load average' | head -1); [ -n "$up" ] && break; done
echo "RESTORE $A back after $((i*10))s: ${up:-NOT BACK}"
t0=$(date +%s)
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep_after.txt" 2>&1; prc=$?
echo "RESTORE prep rc=$prc wall=$(( $(date +%s) - t0 ))s $(grep -a 'prep OK\|PREP FAIL' "$OUT/prep_after.txt" | head -1)"
TAINT1=$(rs 25 "$A" "cat /proc/sys/kernel/tainted")
echo "RESTORE $A taint=$TAINT1 (was $TAINT0 before the lap)"
[ "$prc" = 0 ] || BAD=$((BAD+1))

if [ "$BAD" = 0 ]; then
    echo "RESULT: PASS label=$LABEL — the control cache re-reported the c1 object at c2 and c3; the unmergeable cache reported only its own load's leak"
else
    echo "RESULT: FAIL label=$LABEL bad=$BAD$NOTE"
fi
[ "$BAD" = 0 ]
