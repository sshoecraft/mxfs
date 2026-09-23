#!/bin/bash
# tests/open_mark_lone_close.sh <label> <arm lone|multi|openalone>
#
# arm openalone (the SET side): B opens F while ALONE (no mark is published
# alone), A joins and unlinks F.  A's EX must BAST B's cached grant, whose
# release -- now multi-node -- publishes B's mark, so A defers; B's held fd
# must still read F's original bytes.  DATA-LOSS if it does not.
#
# D-OPEN-LAST-CLOSE-SKIPS-THE-CLEAR-WHEN-ALONE-LEAVING-A-DURABLE-OPEN-MARK.
#
# mxfs_dlm_open_last_close returns early while the node is alone, so a last
# close does not clear an open mark this node published while multi-node.  On
# TCP a mark changes only inside a release, and a node at NL releases nothing
# unless something BASTs it.  The question is whether that stale mark stops a
# peer that joins later from ever freeing the file after it unlinks it.
#
#   1  both mounted; B creates F, holds it open (a sleeping reader's fd) and
#      reads it (B caches a grant)
#   2  A writes F: A's EX BASTs B, whose release publishes B's open mark
#      (P90-OPEN-PUBLISH on B) and leaves B at NL
#   3  arm lone:  A unmounts, B closes F alone, A mounts again
#      arm multi: B closes F with A still mounted (the control)
#   4  A unlinks F, and A's kernel log is read for the free: P87-OPEN-DEFER
#      (a peer's mark stops it) and P88-REAP-RETRY (the 30 s reap retries)
#
# Verdicts: DEFECT: in the lone arm A is still deferring on B's mark after
# OBSERVE_S, with no fd open anywhere.  CLEAN: no P87-OPEN-DEFER for F after
# the unlink, or a defer that stops.  VACUOUS: B never published its mark in
# step 2 (P90 absent), so the arm measured nothing.
#
# derived time budgets: prep 400 s (the same 2/tcp prep bound as
# tests/dirent_durability_loop.sh); unmount and mount ~5 s each (d0959
# harness measurement); OBSERVE_S = 75 s covers the first reap attempt (5 s)
# and two 30 s retries (MXFS_REAP_FIRST_MS / MXFS_REAP_RETRY_MS); each ssh
# step is bounded at the number beside it.
set -u
LABEL=${1:?label}
ARM=${2:?arm lone|multi|openalone}
OBSERVE_S=${OBSERVE_S:-75}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
MNT=/mnt/shared
. "$(dirname "$0")/lib/rig.sh"
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_omlc_${ARM}_$LABEL
mkdir -p "$OUT"
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== open_mark_lone_close label=$LABEL arm=$ARM sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

timeout 400 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1 \
    || { echo "RESULT: ABORT label=$LABEL stage=prep evidence=$OUT"; exit 2; }
mxfs_dev_resolve "$A"; DEV=$MXFS_DEV_RESOLVED

F=$MNT/omlc_$LABEL
MK="OMLC-MARK-$LABEL-$$"
for n in $A $B; do rs 20 "$n" "echo $MK > /dev/kmsg" > /dev/null; done

if [ "$ARM" = openalone ]; then
    echo "  A_LEAVE $(rs 120 "$A" "umount $MNT; echo rc=\$?" | tr '\n' ' ')"
    sleep 3
    s1=$(rs 60 "$B" "echo original-$LABEL > $F; sync -f $MNT; exec 3< $F; nohup bash -c 'sleep 90; cat /proc/self/fd/0' < $F > /tmp/omlc_read.txt 2>&1 & echo \$! > /tmp/omlc_holder.pid; cat $F > /dev/null; echo INO=\$(stat -c %i $F) ALONE=\$(dmesg | grep -a MXFS-MEMBERSHIP | tail -1 | grep -ao 'active_count=[0-9]*')")
    echo "  B $s1"
    INO=$(printf '%s' "$s1" | grep -ao 'INO=[0-9]*' | cut -d= -f2)
    echo "  A_JOIN $(rs 180 "$A" "mount -t mxfs $DEV $MNT; echo rc=\$?" | tr '\n' ' ')"
    UMK="OMLC-UNLINK-$LABEL-$$"
    rs 60 "$A" "echo $UMK > /dev/kmsg; rm -f $F; sync -f $MNT; for i in \$(seq 1 20); do : > $MNT/omlc_fill_$LABEL.\$i; done; sync -f $MNT" > /dev/null
    sleep 100
    rd=$(rs 30 "$B" "cat /tmp/omlc_read.txt")
    rs 30 "$A" "rm -f $MNT/omlc_fill_$LABEL.*; dmesg | sed -n '/$UMK/,\$p'" > "$OUT/A_after_unlink.txt" 2>/dev/null
    rs 30 "$B" "dmesg | sed -n '/$MK/,\$p'" > "$OUT/B_window.txt" 2>/dev/null
    pub=$(grep -a "P90-OPEN-PUBLISH ino=$INO " "$OUT/B_window.txt" | wc -l)
    defer=$(grep -a "ino=$INO " "$OUT/A_after_unlink.txt" | grep -ac 'P87-OPEN-DEFER ')
    echo "  B published after the join: $pub  A defers: $defer  B read through its fd: '$rd'"
    [ "$rd" = "original-$LABEL" ] && { echo "RESULT: CLEAN label=$LABEL arm=openalone pub=$pub defers=$defer evidence=$OUT"; exit 0; }
    echo "RESULT: DATA-LOSS label=$LABEL arm=openalone — B's held fd read '$rd', not the original bytes evidence=$OUT"; exit 1
fi

s1=$(rs 60 "$B" "echo data-$LABEL > $F; sync -f $MNT; nohup sleep 600 < $F > /dev/null 2>&1 & echo \$! > /tmp/omlc_holder.pid; cat $F > /dev/null; echo INO=\$(stat -c %i $F) HOLDER=\$(cat /tmp/omlc_holder.pid)")
echo "  B $s1"
INO=$(printf '%s' "$s1" | grep -ao 'INO=[0-9]*' | cut -d= -f2)
[ -n "$INO" ] || { echo "RESULT: ABORT label=$LABEL no inode number from $B: $s1"; exit 2; }

rs 60 "$A" "echo a-write >> $F; sync -f $MNT" > /dev/null
sleep 2
pub=$(rs 30 "$B" "dmesg | sed -n '/$MK/,\$p' | grep -a 'P90-OPEN-PUBLISH ino=$INO ' | wc -l")
echo "  B published its open mark (P90 for ino=$INO): ${pub:-0}"

if [ "$ARM" = lone ]; then
    echo "  A_LEAVE $(rs 120 "$A" "umount $MNT; echo rc=\$?" | tr '\n' ' ')"
    sleep 3
    echo "  B_ALONE $(rs 30 "$B" "dmesg | grep -a 'MXFS-MEMBERSHIP' | tail -1 | grep -ao 'active_count=[0-9]*'")"
    echo "  B_CLOSE $(rs 30 "$B" "kill \$(cat /tmp/omlc_holder.pid); sleep 1; dmesg | sed -n '/$MK/,\$p' | grep -a 'ino=$INO ' | grep -ac 'P977-OPEN-CLEAR-RIDE\|P91-OPEN-EAGER-CLEAR'" | sed 's/^/clears_logged=/')"
    echo "  A_JOIN $(rs 180 "$A" "mount -t mxfs $DEV $MNT; echo rc=\$?" | tr '\n' ' ')"
else
    echo "  B_CLOSE $(rs 30 "$B" "kill \$(cat /tmp/omlc_holder.pid); sleep 1; dmesg | sed -n '/$MK/,\$p' | grep -a 'ino=$INO ' | grep -ac 'P977-OPEN-CLEAR-RIDE\|P91-OPEN-EAGER-CLEAR'" | sed 's/^/clears_logged=/')"
fi
sleep 2
echo "  B_FDS_ON_F $(rs 30 "$B" "ls -l /proc/[0-9]*/fd 2>/dev/null | grep -c 'omlc_$LABEL'")"

UMK="OMLC-UNLINK-$LABEL-$$"
rs 30 "$A" "echo $UMK > /dev/kmsg; rm -f $F; sync -f $MNT; echo 3 > /proc/sys/vm/drop_caches" > /dev/null
sleep "$OBSERVE_S"
rs 30 "$A" "dmesg | sed -n '/$UMK/,\$p'" > "$OUT/A_after_unlink.txt" 2>/dev/null
rs 30 "$B" "dmesg | sed -n '/$MK/,\$p'" > "$OUT/B_window.txt" 2>/dev/null
defer=$(grep -a "ino=$INO " "$OUT/A_after_unlink.txt" | grep -ac 'P87-OPEN-DEFER ')
retry=$(grep -a "ino=$INO " "$OUT/A_after_unlink.txt" | grep -ac 'P88-REAP-RETRY')
check=$(grep -a "ino=$INO " "$OUT/A_after_unlink.txt" | grep -ac 'P87-OPEN-CHECK')
last=$(grep -a "ino=$INO " "$OUT/A_after_unlink.txt" | grep -a 'P87-OPEN-DEFER \|P87-OPEN-CHECK' | tail -1 | cut -c1-220)
echo "  A after unlink over ${OBSERVE_S}s: open_checks=$check defers=$defer reap_retries=$retry"
[ -n "$last" ] && echo "  last: $last"

if [ "${pub:-0}" = 0 ]; then echo "RESULT: VACUOUS label=$LABEL arm=$ARM — B never published its open mark (no P90 for ino=$INO) evidence=$OUT"; exit 1; fi
if [ "$ARM" = lone ] && [ "${defer:-0}" -ge 2 ]; then
    echo "RESULT: DEFECT label=$LABEL arm=lone — A deferred the free $defer times on B's mark with no fd open anywhere evidence=$OUT"; exit 1
fi
if [ "${defer:-0}" -ge 2 ]; then echo "RESULT: FAIL label=$LABEL arm=$ARM — the control deferred $defer times evidence=$OUT"; exit 1; fi
echo "RESULT: CLEAN label=$LABEL arm=$ARM defers=${defer:-0} evidence=$OUT"; exit 0
