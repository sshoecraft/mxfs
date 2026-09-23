#!/bin/bash
# hot_inode_peer_unlink_2node.sh — a peer's unlink of a file this node is
# writing in a tight loop, on the two-node TCP rig.
#
# Measured sess522 (0.75.38, tests/affine_stale_dentry_2node.sh leg 2b before
# it moved here): A runs an unpaced `echo > f` loop (open O_CREAT|O_TRUNC,
# write, close; ~0.8 ms per iteration); B's `rm f` issued 0.5 s in returned
# 2534 ms later, 110 ms AFTER A's loop ended (s522g), and 3030 ms / 94 ms
# after (s522h); B logged P-LKTIMEOUT-HOLDER held_ms=1528/2552 hmode=EX req=PR.
# A's trace on the inode: the peer's BAST arrives, bast_process enters with
# no holders, the drain reports in_ail=1 flushing=1 and waits for the inode
# to come clean — while 7864 local holds are admitted in the DEMOTING state
# and keep re-dirtying it — and the release completes 2.47 s later, the
# moment the loop stops.  The queued remote requester loses to every local
# re-acquire until the local writer stops of its own accord.
#
# Bound (derived): the DLM's own per-request deadline is the alarm that
# fired (P-LKTIMEOUT-*, ~1 s).  A fair hand-off completes inside one request
# deadline, and the unlink returns while the writer is still running.
#
# the budget rule (derived): prep 55 s measured (2/tcp QNAP) + create 1 s + loop ~3.5 s
# + capture 10 s = ~70 s; chain bound 300 (prep manifest) + 120.
#
# Usage: tests/hot_inode_peer_unlink_2node.sh <label> [ITERS=4000]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2; A = writer, B = peer),
#        NOPREP=1 to reuse the current mount.
set -u
LABEL=${1:?label}
ITERS=${2:-4000}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# MXFS_DEV: the caller's, else prep_cluster's per-transport rig default
# (no other rig's device path is assumed here)
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/hotino_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_hotino_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.  A loop that hits its
# bound (status 124) is reported by its own missing line, not an ABORT.
. "$(dirname "$0")/lib/rig.sh"
loop_require() { [ "$1" = 124 ] || capture_require "$2" "$3" "$4"; }
HEALTH='corruption\|shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io'
offset_ms() {
    local t0 tr t1
    t0=$(date +%s%N); tr=$(rs 15 "$1" "date +%s%N" | tr -dc 0-9); t1=$(date +%s%N)
    python3 -c "print(int(($tr - ($t0 + $t1) / 2) / 1e6))"
}

echo "=== hot_inode_peer_unlink_2node label=$LABEL A=$A B=$B iters=$ITERS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -z "${NOPREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat /sys/module/mxfs/parameters/force_transport)" | tr -d '\n')"
done
ck "both nodes mounted on the tree's build" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
offA=$(offset_ms "$A"); offB=$(offset_ms "$B")
MK="HOTINO-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

P=/sys/module/mxfs/parameters
value_now_into ino "$A" 30 "$OUT/rv_ino_1.txt" '^[0-9]+$' "ino on $A" "mkdir -p $D && echo payload > $D/f && sync -f $MNT && stat -c %i $D/f"
y0=$(rs 15 "$A" "cat $P/file_yield_n 2>/dev/null; echo knob=\$(cat $P/file_yield_on_demote 2>/dev/null)" | tr '\n' ' ')
echo "  INFO A f ino=$ino yield_before='$y0'"
ckge "A created f" "$ino" 1
( rsx 90 "$A" "s=\$(date +%s%N); i=0; while [ \$i -lt $ITERS ]; do i=\$((i+1)); echo Y\$i > $D/f 2>/dev/null; done; e=\$(date +%s%N); echo A_LOOP done iters=\$i wall_ms=\$(( (e - s) / 1000000 )) end=\$e" > "$OUT/loop_$A.txt"; echo $? > "$OUT/loop_$A.rc" ) &
LPID=$!
sleep 0.5
value_now_into brm "$B" 60 "$OUT/rv_brm_2.txt" '^B_RM ' "brm on $B" "s=\$(date +%s%N); rm $D/f; rc=\$?; e=\$(date +%s%N); echo B_RM rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) end=\$e"
wait $LPID
loop_require "$(cat "$OUT/loop_$A.rc")" "$OUT/loop_$A.txt" '^A_LOOP done ' "A's writer loop"
echo "  INFO $brm | $(cat "$OUT/loop_$A.txt")"
rmw=$(echo "$brm" | grep -ao 'wall_ms=[0-9]*' | cut -d= -f2)
lend=$(grep -ao 'end=[0-9]*' "$OUT/loop_$A.txt" | cut -d= -f2)
rend=$(echo "$brm" | grep -ao 'end=[0-9]*' | cut -d= -f2)
lwall=$(grep -ao 'wall_ms=[0-9]*' "$OUT/loop_$A.txt" | cut -d= -f2)
after_loop_ms=$(python3 -c "print(int(($rend - $offB*1e6) / 1e6 - ($lend - $offA*1e6) / 1e6))" 2>/dev/null)
value_now_into bsee "$B" 30 "$OUT/rv_bsee_3.txt" '^B_SEES ' "bsee on $B" "sleep 0.5; echo B_SEES f=\$(stat -c %i $D/f 2>/dev/null || echo gone) content=\$(cat $D/f 2>/dev/null)"
echo "  INFO $bsee"

for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
done
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
bast=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$A.txt")
bp_entry=$(grep -ac "P70-BP ino=$ino ENTRY" "$OUT/dmesg_full_$A.txt")
bp_full=$(grep -ac "P70-BP ino=$ino EXIT=full" "$OUT/dmesg_full_$A.txt")
holds_demoting=$(grep -a "P71-HOLD ino=$ino " "$OUT/dmesg_full_$A.txt" | grep -ac 'state=3')
hold_labels=$(grep -a "P71-HOLD ino=$ino " "$OUT/dmesg_full_$A.txt" | grep -a 'state=3' | grep -ao "P71-HOLD ino=$ino [a-z-]*" | awk '{print $3}' | sort | uniq -c | awk '{printf "%s=%s,", $2, $1}')
bast_dur=$(grep -a "P138-BAST ino=$ino " "$OUT/dmesg_full_$A.txt" | grep -ao 'dur_us=[0-9]*' | cut -d= -f2 | sort -n | tail -1)
lkto=$(grep -ac 'P-LKTIMEOUT' "$OUT/dmesg_full_$B.txt")
y1=$(rs 15 "$A" "cat $P/file_yield_n 2>/dev/null" | tr -d '\n')
yields=$(grep -ac "P-FILE-YIELD ino=$ino " "$OUT/dmesg_full_$A.txt")
echo "  HOTINO-MEASURE $LABEL peer_unlink_wall_ms=${rmw:-?} unlink_returned_after_loop_end_ms=${after_loop_ms:-?} loop_wall_ms=${lwall:-?} iters=$ITERS peer_lock_timeouts=$lkto A_basts=$bast A_bast_process_entries=$bp_entry A_full_releases=$bp_full A_holds_admitted_while_demoting=$holds_demoting labels=$hold_labels longest_bast_us=${bast_dur:-0} file_yield_n=${y0%% *}->${y1:-?} yield_lines=$yields"
[ "$lkto" != 0 ] && echo "  INFO B lock-timeout lines: $(grep -a 'P-LKTIMEOUT' "$OUT/dmesg_full_$B.txt" | head -3 | sed 's/^\[[^]]*\] mxfs: //' | cut -c1-140 | tr '\n' ';')"
ck "B unlinked f rc=0" "$(echo "$brm" | grep -ac 'B_RM rc=0')" "1"
ck "A's loop ran to completion" "$(grep -ac "A_LOOP done iters=$ITERS" "$OUT/loop_$A.txt")" "1"
ck "fairness: B's unlink under A's hot writer completed inside one DLM request deadline (<=1000 ms)" "$( [ "${rmw:-99999}" -le 1000 ] && echo 1 || echo 0)" "1"
ck "fairness: B's unlink returned while A's loop was still running" "$( [ "${after_loop_ms:-99999}" -lt 0 ] && echo 1 || echo 0)" "1"
ck "fairness: no DLM request deadline expired on B" "$lkto" "0"
ck "B sees the file A recreated after the unlink (no lost create)" "$(echo "$bsee" | grep -ac "content=Y$ITERS")" "1"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
