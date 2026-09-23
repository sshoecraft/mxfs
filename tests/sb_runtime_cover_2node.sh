#!/bin/bash
# sb_runtime_cover_2node.sh — D-SB-RUNTIME-COVER-WRITES-PRIVATE-COUNTERS-
# OUTSIDE-SUMMARY-LOCK-0536 on the two-node TCP rig.
#
# Shape (the sess475 chain 116 v2 adversarial arm, cut down to two nodes):
# X unmounts with its SB summary critical section parked at point 2 (after
# the recount, before the cover) for PAUSE_MS; Y, still mounted, is made to
# cover its log once per second (xfssyncd_centisecs=100 after a create/rm
# burst).  Every SB-sector write is witnessed at the submission chokepoint
# (P-SB-WRITE-SUBMIT locked=0/1).
#
# The defect: Y's periodic cover logs the whole superblock with Y's PRIVATE
# lazy counters folded in and the AIL writes the sector unlocked, inside X's
# critical section.  Verdict on a fixed build:
#   - Y submits NO unlocked SB-sector write at all after the marker;
#   - Y's cover still happens, under the summary lock (P-SB-RUNTIME-COVER),
#     and every one of Y's SB writes is locked=1;
#   - X parks at point 2, sees no POST mismatch, unmounts rc=0 with a wall of
#     at least the pause; Y is healthy afterwards; X remounts.
# On the unfixed build the first two checks FAIL — that is the measurement.
#
# the budget rule (derived): prep 50 s measured (2/tcp QNAP) + pause 20 s + umount
# ~3 s + burst/capture ~25 s + remount ~5 s = ~105 s; chain bound 300 (prep
# manifest) + 120 = 420 s.
#
# Usage: tests/sb_runtime_cover_2node.sh <label> [PAUSE_MS=20000]
# Env:   MXFS_DEV, MXFS_NODE_LIST (default test1,test2; X = first, Y = second)
set -u
LABEL=${1:?label}
PAUSE_MS=${2:-20000}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
X=${MXFS_NODE_LIST%%,*}
Y=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_sbrc_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
ckge() { if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=${2:-?} want>=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require/mxfs_dev_resolve (tests/lib/rig.sh): every
# capture a verdict is taken from is proven to hold its tool's shape first;
# a failed acquisition is an ABORT, never a count of zero.  MXFS_DEV: X's
# live mount after prep (MXFS_DEV overrides; no rig's device is assumed).
. "$(dirname "$0")/lib/rig.sh"
SBPAT='P-SB-\|P30-QUIESCE-RECOUNT\|will fix summary\|P-UNMOUNT'

echo "=== sb_runtime_cover_2node label=$LABEL X=$X Y=$Y pause_ms=$PAUSE_MS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
prc=$?
echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
for n in $X $Y; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat $P/force_transport) knobs=\$(ls $P/dbg_sb_pause_point $P/dbg_sb_pause_ms 2>/dev/null | wc -l)" | tr -d '\n')"
done
for n in $X $Y; do
    measure "$n" 20 "$OUT/${n}_mounted.txt" '^[0-9]+$' "the mount count on $n" "grep -c ' $MNT mxfs ' /proc/mounts || true"
done
ck "both nodes mounted on the tree's build" "$(cat "$OUT/${X}_mounted.txt" "$OUT/${Y}_mounted.txt" | tr -d '\n')" "11"
mxfs_dev_resolve "$X"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV
echo "  INFO device=$MXFS_DEV (from $X's live mount)"

MK="SBRC-$LABEL"
for n in $X $Y; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done
# Y covers once per second whenever its log is idle
# (s520j/s520k: neither fs/xfs nor the fork's fs/mxfs sysctl directory
# exists on the node; 0.75.34 exposes the period as a module parameter)
measure "$Y" 15 "$OUT/${Y}_syncd.txt" '^[0-9]+$' "the syncd_centisecs knob on $Y" "echo 100 > $P/syncd_centisecs; cat $P/syncd_centisecs"
ysy=$(tr -d '\n' < "$OUT/${Y}_syncd.txt")
echo "  INFO Y syncd_centisecs: $ysy"
ck "Y covers every 1 s (mxfs.syncd_centisecs=100)" "$ysy" "100"
# X parks inside its critical section at point 2 for the pause
measure "$X" 15 "$OUT/${X}_pause_knobs.txt" '^[0-9]+$' "the SB pause knobs on $X" "echo $PAUSE_MS > $P/dbg_sb_pause_ms; echo 2 > $P/dbg_sb_pause_point; cat $P/dbg_sb_pause_point $P/dbg_sb_pause_ms"
xk=$(tr '\n' ' ' < "$OUT/${X}_pause_knobs.txt")
echo "  INFO X pause knobs: $xk"
ck "X armed: dbg_sb_pause_point=2 dbg_sb_pause_ms=$PAUSE_MS" "$xk" "2 $PAUSE_MS "

# Y's burst dirties the log, then Y idles so the 1 s cover fires repeatedly
# through X's hold; the post-hold create proves Y is still a working mount.
# A failed post-hold create is the measurement (no burst_done line), so the
# list ends in a sentinel and the status stays 0.
( rsx $(( PAUSE_MS / 1000 + 40 )) "$Y" "mkdir -p $MNT/.sbburst_$LABEL; for i in \$(seq 1 200); do echo x > $MNT/.sbburst_$LABEL/f\$i; done; rm -f $MNT/.sbburst_$LABEL/f*; sleep $(( PAUSE_MS / 1000 + 8 )); echo post > $MNT/.sbburst_$LABEL/post && sync -f $MNT/.sbburst_$LABEL && echo burst_done=\$(cat $MNT/.sbburst_$LABEL/post); echo BURST_END" > "$OUT/burst_$Y.txt" ) &
BPID=$!
sleep 1
tu=$(date +%s)
measure "$X" $(( PAUSE_MS / 1000 + 60 )) "$OUT/umount_$X.txt" '^P-UNMOUNT node=' "the unmount of $X" "s=\$(date +%s%N); timeout $(( PAUSE_MS / 1000 + 50 )) umount $MNT; rc=\$?; e=\$(date +%s%N); echo P-UNMOUNT node=$X rc=\$rc wall_ms=\$(( (e - s) / 1000000 ))"
echo "  INFO X umount: $(cat "$OUT/umount_$X.txt") (harness wall $(( $(date +%s) - tu )) s)"
wait $BPID
capture_require "$OUT/burst_$Y.txt" '^BURST_END$' "the burst workload on $Y"
echo "  INFO Y burst: $(grep -av '^BURST_END$' "$OUT/burst_$Y.txt" | tail -1)"

# capture, with each node's boot epoch so dmesg stamps convert to wall time
for n in $X $Y; do
    measure "$n" 40 "$OUT/dmesg_$n.txt" '^BOOT_EPOCH=[0-9.]+$' "the kernel log on $n from the lap marker" "echo BOOT_EPOCH=\$(awk -v u=\$(cut -d' ' -f1 /proc/uptime) 'BEGIN{printf \"%.3f\", systime()-u}'); dmesg | sed -n '/$MK/,\$p' | grep -a '$SBPAT'; true"
done
# the same two captures by name, so the per-node verdicts below read from a
# path the boundary was crossed for
capture_require "$OUT/dmesg_$X.txt" '^BOOT_EPOCH=[0-9.]+$' "the kernel log on $X"
capture_require "$OUT/dmesg_$Y.txt" '^BOOT_EPOCH=[0-9.]+$' "the kernel log on $Y"
xb=$(grep -a '^BOOT_EPOCH=' "$OUT/dmesg_$X.txt" | cut -d= -f2); yb=$(grep -a '^BOOT_EPOCH=' "$OUT/dmesg_$Y.txt" | cut -d= -f2)
ts() { echo "$1" | grep -ao '^\[ *[0-9.]*\]' | tr -dc '0-9.'; }
xp=$(ts "$(grep -a 'P-SB-SUMMARY-PAUSE slot=[0-9]* point=2 ' "$OUT/dmesg_$X.txt" | head -1)")
xpe=$(ts "$(grep -a 'P-SB-SUMMARY-PAUSE-END' "$OUT/dmesg_$X.txt" | head -1)")
xun=$(ts "$(grep -a 'P-SB-SUMMARY-UNLOCK' "$OUT/dmesg_$X.txt" | tail -1)")
xe=$(grep -a 'P-SB-SUMMARY-LOCK slot=[0-9]* rc=0' "$OUT/dmesg_$X.txt" | grep -ao 'epoch=[0-9]*' | tail -1 | cut -d= -f2)
w0=$(python3 -c "print(float('${xb:-0}')+float('${xp:-0}'))"); w1=$(python3 -c "print(float('${xb:-0}')+float('${xpe:-0}'))")
echo "  INFO X hold: pause=${xp:-?} pause_end=${xpe:-?} unlock=${xun:-?} epoch=${xe:-?} (wall window $w0..$w1)"
# Y's SB-sector writes: total, unlocked, unlocked inside X's hold, locked covers
y_all=$(grep -ac 'P-SB-WRITE-SUBMIT' "$OUT/dmesg_$Y.txt")
y_unl=$(grep -a 'P-SB-WRITE-SUBMIT' "$OUT/dmesg_$Y.txt" | grep -ac 'locked=0')
y_lck=$(grep -a 'P-SB-WRITE-SUBMIT' "$OUT/dmesg_$Y.txt" | grep -ac 'locked=1')
y_unl_in=$(grep -a 'P-SB-WRITE-SUBMIT' "$OUT/dmesg_$Y.txt" | grep -a 'locked=0' | while read -r l; do t=$(ts "$l"); python3 -c "import sys; w=float('${yb:-0}')+float('$t'); sys.exit(0 if $w0 <= w <= $w1 else 1)" && echo in; done | grep -c in)
y_rc=$(grep -ac 'P-SB-RUNTIME-COVER slot=' "$OUT/dmesg_$Y.txt")
y_rc_skip=$(grep -ac 'P-SB-RUNTIME-COVER-\(BUSY\|LOCK-FAIL\|READ-FAIL\|SKIP\)' "$OUT/dmesg_$Y.txt")
y_rc_first_e=$(grep -a 'P-SB-RUNTIME-COVER slot=' "$OUT/dmesg_$Y.txt" | grep -ao 'epoch=[0-9]*' | head -1 | cut -d= -f2)
echo "  D0536-MEASURE $LABEL Y_sb_writes=$y_all Y_unlocked=$y_unl Y_unlocked_in_hold=$y_unl_in Y_locked=$y_lck Y_runtime_covers=$y_rc Y_cover_skips=$y_rc_skip Y_first_cover_epoch=${y_rc_first_e:-none} X_epoch=${xe:-none} X_post_mismatch=$(grep -ac 'P-SB-SYNC-POST-MISMATCH' "$OUT/dmesg_$X.txt")"
echo "  INFO Y SB writes (first 6): $(grep -a 'P-SB-WRITE-SUBMIT' "$OUT/dmesg_$Y.txt" | head -6 | grep -ao 'seq=[0-9]* epoch=[0-9]* locked=[01]' | tr '\n' ';')"
ck "X parked at point 2 inside its critical section" "$(grep -ac 'P-SB-SUMMARY-PAUSE slot=[0-9]* point=2 ' "$OUT/dmesg_$X.txt")" "1"
ck "X unmounted rc=0" "$(grep -ac 'rc=0' "$OUT/umount_$X.txt")" "1"
ckge "X's umount wall >= the pause (ms)" "$(grep -ao 'wall_ms=[0-9]*' "$OUT/umount_$X.txt" | cut -d= -f2)" "$PAUSE_MS"
ck "X: zero P-SB-SYNC-POST-MISMATCH (nobody wrote the sector inside X's section)" "$(grep -ac 'P-SB-SYNC-POST-MISMATCH' "$OUT/dmesg_$X.txt")" "0"
ck "X: last SB write locked, none sealed" "$(grep -a 'P-SB-WRITE-SUBMIT' "$OUT/dmesg_$X.txt" | tail -1 | grep -ac 'locked=1 sealed=0')" "1"
ckge "Y covered its log at least once after the marker (P-SB-WRITE-SUBMIT)" "$y_all" 1
ck "D-0536: Y submitted ZERO unlocked SB-sector writes" "$y_unl" "0"
ckge "D-0536: Y's covers ran under the summary lock (P-SB-RUNTIME-COVER)" "$y_rc" 1
ck "D-0536: every SB write Y submitted was locked" "$(( y_all - y_lck ))" "0"
ck "Y healthy after the hold (post-hold create + fsync)" "$(grep -ac 'burst_done=post' "$OUT/burst_$Y.txt")" "1"
# leave the rig whole: clear X's knobs (one-shot, but be explicit) and remount X
measure "$X" 60 "$OUT/${X}_remount.txt" '^mount_rc=[0-9]+ mounted=[0-9]+$' "the remount of $X" "echo 0 > $P/dbg_sb_pause_point; timeout 45 mount -t mxfs $MXFS_DEV $MNT; echo mount_rc=\$? mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts)"
xr=$(tail -1 "$OUT/${X}_remount.txt")
echo "  INFO X remount: $xr"
ck "X remounted (rig left as 2 nodes)" "$(echo "$xr" | grep -ac 'mount_rc=0 mounted=1')" "1"
rs 15 "$Y" "echo 3000 > $P/syncd_centisecs" >/dev/null
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
