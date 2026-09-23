#!/bin/bash
# hot_inode_peer_rename_2node.sh — a peer's rename of a file this node is
# rewriting in a tight loop, on the two-node TCP rig.
#
# Sibling of tests/hot_inode_peer_unlink_2node.sh.  The rename path shares
# the remove path's AG pre-acquire (mxfs_trans_preacquire_inode_ags) and the
# source inode's release drain, so it is exposed to the same three
# mechanisms that harness found (D-0916 admit starvation, D-0917 pre-acquire
# convoy, D-0918 shared-admit EX leak) plus one of its own: the target name
# lands in the directory while the source inode is still the writer's hot
# inode, and A's next O_CREAT recreates f as a NEW inode.
#
# A runs an unpaced `echo Y$i > f` loop (open O_CREAT|O_TRUNC, write, close).
# B issues `mv f g` 0.5 s in.  Afterwards B must see BOTH names: g holding
# one complete "Y<n>" line A wrote to the old inode (never empty, never
# torn), and f holding A's final line on the recreated inode.
#
# Bound (derived, same as the unlink harness): a fair hand-off completes
# inside one DLM request deadline (~1 s) and the rename returns while A's
# loop is still running.
#
# the budget rule (derived): prep 55 s measured (2/tcp QNAP) + create 1 s + loop ~3.5 s
# + capture 10 s = ~70 s; chain bound 300 (prep manifest) + 120.
#
# Usage: tests/hot_inode_peer_rename_2node.sh <label> [ITERS=4000]
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
D=$MNT/hotren_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_hotren_$LABEL
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

echo "=== hot_inode_peer_rename_2node label=$LABEL A=$A B=$B iters=$ITERS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
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
MK="HOTREN-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

value_now_into ino "$A" 30 "$OUT/rv_ino_1.txt" '^[0-9]+$' "ino on $A" "mkdir -p $D && echo payload > $D/f && sync -f $MNT && stat -c %i $D/f"
echo "  INFO A f ino=$ino"
ckge "A created f" "$ino" 1
( rsx 90 "$A" "s=\$(date +%s%N); i=0; while [ \$i -lt $ITERS ]; do i=\$((i+1)); echo Y\$i > $D/f 2>/dev/null; done; e=\$(date +%s%N); echo A_LOOP done iters=\$i wall_ms=\$(( (e - s) / 1000000 )) end=\$e" > "$OUT/loop_$A.txt"; echo $? > "$OUT/loop_$A.rc" ) &
LPID=$!
sleep 0.5
value_now_into bmv "$B" 60 "$OUT/rv_bmv_2.txt" '^B_MV ' "bmv on $B" "s=\$(date +%s%N); mv $D/f $D/g; rc=\$?; e=\$(date +%s%N); echo B_MV rc=\$rc wall_ms=\$(( (e - s) / 1000000 )) end=\$e"
wait $LPID
loop_require "$(cat "$OUT/loop_$A.rc")" "$OUT/loop_$A.txt" '^A_LOOP done ' "A's writer loop"
echo "  INFO $bmv | $(cat "$OUT/loop_$A.txt")"
mvw=$(echo "$bmv" | grep -ao 'wall_ms=[0-9]*' | cut -d= -f2)
lend=$(grep -ao 'end=[0-9]*' "$OUT/loop_$A.txt" | cut -d= -f2)
rend=$(echo "$bmv" | grep -ao 'end=[0-9]*' | cut -d= -f2)
lwall=$(grep -ao 'wall_ms=[0-9]*' "$OUT/loop_$A.txt" | cut -d= -f2)
after_loop_ms=$(python3 -c "print(int(($rend - $offB*1e6) / 1e6 - ($lend - $offA*1e6) / 1e6))" 2>/dev/null)
# B's view after the loop: both names, g one complete line on the OLD inode,
# f A's last line on a NEW inode.  A's view must agree (same inode numbers,
# same bytes) — a divergent view is the data-integrity failure this exists for.
value_now_into bsee "$B" 30 "$OUT/rv_bsee_3.txt" '^B_SEES ' "bsee on $B" "sleep 0.5; echo B_SEES g_ino=\$(stat -c %i $D/g 2>/dev/null || echo gone) g_size=\$(stat -c %s $D/g 2>/dev/null || echo -) g=\$(cat $D/g 2>/dev/null | tr -d '\n') f_ino=\$(stat -c %i $D/f 2>/dev/null || echo gone) f=\$(cat $D/f 2>/dev/null | tr -d '\n') names=\$(ls $D | tr '\n' ,)"
asee=$(rs 30 "$A" "echo A_SEES g_ino=\$(stat -c %i $D/g 2>/dev/null || echo gone) g=\$(cat $D/g 2>/dev/null | tr -d '\n') f_ino=\$(stat -c %i $D/f 2>/dev/null || echo gone) f=\$(cat $D/f 2>/dev/null | tr -d '\n') names=\$(ls $D | tr '\n' ,)" | tail -1)
echo "  INFO $bsee"
echo "  INFO $asee"
g_ino=$(echo "$bsee" | grep -ao 'g_ino=[^ ]*' | cut -d= -f2)
g_val=$(echo "$bsee" | grep -ao ' g=[^ ]*' | cut -d= -f2)
f_ino=$(echo "$bsee" | grep -ao 'f_ino=[^ ]*' | cut -d= -f2)
f_val=$(echo "$bsee" | grep -ao ' f=[^ ]*' | cut -d= -f2)
ag_ino=$(echo "$asee" | grep -ao 'g_ino=[^ ]*' | cut -d= -f2)
ag_val=$(echo "$asee" | grep -ao ' g=[^ ]*' | cut -d= -f2)
af_ino=$(echo "$asee" | grep -ao 'f_ino=[^ ]*' | cut -d= -f2)
af_val=$(echo "$asee" | grep -ao ' f=[^ ]*' | cut -d= -f2)

for n in $A $B; do
    measure "$n" 40 "$OUT/dmesg_full_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs' | grep -av '$NOISE'; echo DMESG_END"
done
capture_require "$OUT/dmesg_full_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_full_$B.txt" '^DMESG_END$' "the kernel log on $B"
bast=$(grep -ac "P7B-BASTNOTIFY ino=$ino " "$OUT/dmesg_full_$A.txt")
bp_full=$(grep -ac "P70-BP ino=$ino EXIT=full" "$OUT/dmesg_full_$A.txt")
holds_demoting=$(grep -a "P71-HOLD ino=$ino " "$OUT/dmesg_full_$A.txt" | grep -ac 'state=3')
lkto=$(grep -ac 'P-LKTIMEOUT' "$OUT/dmesg_full_$B.txt")
preacq=$(grep -ac 'P271-PREACQ-POLL' "$OUT/dmesg_full_$B.txt")
underflow=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P71-UNDERFLOW')
lkwait=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -ac 'P-LKWAIT-LIVE')
echo "  HOTREN-MEASURE $LABEL peer_rename_wall_ms=${mvw:-?} rename_returned_after_loop_end_ms=${after_loop_ms:-?} loop_wall_ms=${lwall:-?} iters=$ITERS peer_lock_timeouts=$lkto A_basts=$bast A_full_releases=$bp_full A_holds_admitted_while_demoting=$holds_demoting B_preacq_polls=$preacq underflow=$underflow lkwait_live=$lkwait old_ino=$ino g_ino=$g_ino f_ino=$f_ino"
[ "$lkto" != 0 ] && echo "  INFO B lock-timeout lines: $(grep -a 'P-LKTIMEOUT' "$OUT/dmesg_full_$B.txt" | head -3 | sed 's/^\[[^]]*\] mxfs: //' | cut -c1-140 | tr '\n' ';')"
ck "B renamed f to g rc=0" "$(echo "$bmv" | grep -ac 'B_MV rc=0')" "1"
ck "A's loop ran to completion" "$(grep -ac "A_LOOP done iters=$ITERS" "$OUT/loop_$A.txt")" "1"
ck "fairness: B's rename under A's hot writer completed inside one DLM request deadline (<=1000 ms)" "$( [ "${mvw:-99999}" -le 1000 ] && echo 1 || echo 0)" "1"
ck "fairness: B's rename returned while A's loop was still running" "$( [ "${after_loop_ms:-99999}" -lt 0 ] && echo 1 || echo 0)" "1"
ck "fairness: no DLM request deadline expired on B" "$lkto" "0"
ck "integrity: g is the ORIGINAL inode" "$g_ino" "$ino"
ck "integrity: g holds one complete line A wrote (Y<n>, 1<=n<=$ITERS, never empty or torn)" "$(python3 -c "
import re,sys
v='$g_val'; m=re.fullmatch(r'Y(\d+)', v)
print(1 if m and 1 <= int(m.group(1)) <= $ITERS else 0)")" "1"
ck "integrity: f was recreated by A as a NEW inode" "$( [ -n "$f_ino" ] && [ "$f_ino" != gone ] && [ "$f_ino" != "$ino" ] && echo 1 || echo 0)" "1"
ck "integrity: f holds A's final line Y$ITERS" "$f_val" "Y$ITERS"
ck "coherency: A and B agree on g (inode + bytes)" "$( [ "$ag_ino" = "$g_ino" ] && [ "$ag_val" = "$g_val" ] && echo 1 || echo 0)" "1"
ck "coherency: A and B agree on f (inode + bytes)" "$( [ "$af_ino" = "$f_ino" ] && [ "$af_val" = "$f_val" ] && echo 1 || echo 0)" "1"
ck "coherency: B lists exactly f and g" "$(echo "$bsee" | grep -ao 'names=[^ ]*' | cut -d= -f2)" "f,g,"
ck "no hold-count underflow on either node" "$underflow" "0"
ck "no live-holder lock wait on either node" "$lkwait" "0"
health=$(cat "$OUT/dmesg_full_$A.txt" "$OUT/dmesg_full_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (full window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
