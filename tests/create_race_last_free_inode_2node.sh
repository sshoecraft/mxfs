#!/bin/bash
# create_race_last_free_inode_2node.sh — several concurrent create loops on
# ONE node, each in its own directory, on the two-node TCP rig.
#
# What it exists to catch.  On 0.75.44 (sess525/526 rig logs, test1, 2/tcp)
# a plain create returned EUCLEAN twice with 'Internal error i != 1 && j != 1'
# from xfs_dialloc_ag_finobt_near and 'Corruption detected' — on a healthy
# filesystem: every later create in the same AG succeeded and the AG kept
# growing.  In both events the kernel log shows another local bash taking
# the AG's LAST free inode (P150-ALLOC-FIN post=0x0/0, P-AGIFC-MOD
# agi_freecount=0) in the same millisecond, and the failing create's
# P72-INSTR line reads holders=2: two local tasks inside the same AG.
#
# The two-phase allocator (mxfs_dialloc_two_phase, sess430 containment)
# releases the AGI buffer between picking a candidate and taking it, so a
# concurrent local create in the same AG can consume the last free inode in
# that window; phase 2 then re-reads an AGI with freecount 0, finds an EMPTY
# finobt and the near-search's corruption check fires.  The user sees
# 'Structure needs cleaning' on a create, the AG's finobt is marked sick and
# the log says to run xfs_repair, for a filesystem with nothing wrong.
#
# Shape: RACERS bash loops on node A, each creating FILES empty files in
# its own directory (different parents, so the VFS parent lock does not
# serialise them; same node, so they share the node's owned AG).  Every 64
# creates exhaust a chunk, which is one race opportunity.  VALIDATE=0
# switches the two-phase off (mxfs.dialloc_validate) for the A/B leg: the
# same workload with the window removed must show zero events.
#
# Pace: private-dir creates on this rig measure 22-40 ms each with the
# two-phase on (that pace is the open D-TCP-LEDGER-SMALLFILE-WORKLOAD-PACE
# record, not this harness's subject); the loops are serialised by the AGI
# lock, so the bound is RACERS*FILES*40 ms + 10 s.  A timeout is a FAIL.
#
# Usage: tests/create_race_last_free_inode_2node.sh <label> [RACERS=4] [FILES=800] [VALIDATE=1]
# Env:   MXFS_NODE_LIST (default test1,test2; A = the racing node, B = idle peer)
set -u
LABEL=${1:?label}
RACERS=${2:-4}
FILES=${3:-800}
VALIDATE=${4:-1}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
D=$MNT/race_$LABEL
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_race_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/measure/capture_require (tests/lib/rig.sh): every capture a verdict
# is counted from crosses the boundary in the parent shell first; a failed
# acquisition is an ABORT, never a count of zero.  The racer loop that runs
# out its derived bound (124) is the pace FAIL below, not an ABORT.
. "$(dirname "$0")/lib/rig.sh"
HEALTH='shutting down\|shut down\|BUG:\|Oops\|P95-OPEN-PROTECT\|P-INODE-WEDGE\|P-WITHDRAW\|P277-\|unrecoverable\|lock request failed'
NOISE='P-TAUTH-PREPARED\|P-TAUTH-ACTIVATE\|PAGE-MINE\|HANDOFF\|TAKEOVER-RETIRE\|bdev_io\|P-AGIFC-MOD\|P150-\|P74-GRANT'
LOOP_BOUND_S=$(( RACERS * FILES * 40 / 1000 + 10 ))
PARAM=/sys/module/mxfs/parameters/dialloc_validate

echo "=== create_race_last_free_inode_2node label=$LABEL A=$A B=$B racers=$RACERS files=$FILES validate=$VALIDATE sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
for n in $A $B; do
    echo "  INFO $n $(rs 20 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) ft=\$(cat /sys/module/mxfs/parameters/force_transport) validate=\$(cat $PARAM)" | tr -d '\n')"
done
ck "both nodes mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
# arm the knob on the racing node and PROVE the arm took (a leg whose knob
# did not land measures the wrong build state)
value_now_into rv1 "$A" 20 "$OUT/rv_rv1_1.txt" '^-?[0-9]+$' "rv1 on $A" "echo $VALIDATE > $PARAM; cat $PARAM"
ck "dialloc_validate=$VALIDATE armed on $A" "$rv1" "$VALIDATE"
MK="RACE-$LABEL"
for n in $A $B; do rs 15 "$n" "echo '$MK' > /dev/kmsg" >/dev/null; done

measure "$A" 60 "$OUT/dirs.txt" '^r[0-9]+ ino=[0-9]+$' "the racer directories on $A" "mkdir -p $D && for r in \$(seq 1 $RACERS); do mkdir $D/r\$r; done && for r in \$(seq 1 $RACERS); do echo r\$r ino=\$(stat -c %i $D/r\$r); done"
echo "  INFO racer dirs: $(tr '\n' ' ' < "$OUT/dirs.txt")"
ck "$RACERS racer directories created" "$(grep -c 'ino=' "$OUT/dirs.txt")" "$RACERS"

LOOP_TO=$(( LOOP_BOUND_S + 30 ))
rsx $LOOP_TO "$A" "cd $D || exit 3; s=\$(date +%s%N); \
for r in \$(seq 1 $RACERS); do ( i=0; f=0; while [ \$i -lt $FILES ]; do i=\$((i+1)); : 2>>r\$r.err > r\$r/f\$i || { f=\$((f+1)); echo \"RACER_FAIL r=\$r i=\$i\"; }; done; e=\$(date +%s%N); echo \"RACER_DONE r=\$r iters=\$i fails=\$f wall_ms=\$(( (e - s) / 1000000 ))\" ) & done; wait; \
echo ALL_DONE wall_ms=\$(( (\$(date +%s%N) - s) / 1000000 )); \
for r in \$(seq 1 $RACERS); do echo \"ERRS r=\$r \$(sort r\$r.err | uniq -c | tr '\n' ';')\"; done" > "$OUT/loop_$A.txt"
lrc=$?
[ "$lrc" = 124 ] || capture_require "$OUT/loop_$A.txt" '^ALL_DONE wall_ms=' "the racer loop on $A"
echo "  INFO $(grep -a 'RACER_DONE\|ALL_DONE' "$OUT/loop_$A.txt" | tr '\n' ' ')"
echo "  INFO $(grep -a 'ERRS' "$OUT/loop_$A.txt" | grep -av 'ERRS r=[0-9]* $' | tr '\n' ' ')"
wall_ms=$(grep -ao 'ALL_DONE wall_ms=[0-9]*' "$OUT/loop_$A.txt" | cut -d= -f2)
done_n=$(grep -ac "RACER_DONE r=[0-9]* iters=$FILES " "$OUT/loop_$A.txt")
rfail=$(grep -ac 'RACER_FAIL' "$OUT/loop_$A.txt")
eucl=$(grep -ac 'Structure needs cleaning' "$OUT/loop_$A.txt")

for n in $A $B; do
    measure "$n" 60 "$OUT/dmesg_$n.txt" '^DMESG_END$' "the kernel log on $n from the lap marker" "dmesg | sed -n '/$MK/,\$p' | grep -a 'mxfs\|XFS\|Internal error\|Corruption' | grep -av '$NOISE'; echo DMESG_END"
    measure "$n" 60 "$OUT/exhaust_$n.txt" '^[0-9]+$' "the AGI exhaustion count on $n" "dmesg | sed -n '/$MK/,\$p' | grep -ac 'P-AGIFC-MOD site=dialloc_ag.*agi_freecount=0 '; true"
done
capture_require "$OUT/dmesg_$A.txt" '^DMESG_END$' "the kernel log on $A"
capture_require "$OUT/dmesg_$B.txt" '^DMESG_END$' "the kernel log on $B"
ierr=$(grep -ac 'Internal error' "$OUT/dmesg_$A.txt")
corr=$(grep -ac 'Corruption detected' "$OUT/dmesg_$A.txt")
p72=$(grep -ac 'P72-INSTR finobt-near-fail' "$OUT/dmesg_$A.txt")
e117=$(grep -ac 'P-DIALLOC .*err=-117' "$OUT/dmesg_$A.txt")
lost=$(grep -ac 'P-DIALLOC-VALIDATED-LOST' "$OUT/dmesg_$A.txt")
grow=$(grep -ac 'P-DIALLOC-RESV-GROW' "$OUT/dmesg_$A.txt")
p2e=$(grep -ac 'P-DIALLOC-P2-EMPTY' "$OUT/dmesg_$A.txt")
exh=$(tr -d '[:space:]' < "$OUT/exhaust_$A.txt")
lkto=$(cat "$OUT/dmesg_$A.txt" "$OUT/dmesg_$B.txt" | grep -ac 'P-LKTIMEOUT')
echo "  RACE-MEASURE $LABEL validate=$VALIDATE racers=$RACERS files=$FILES wall_ms=${wall_ms:-?} loop_rc=$lrc racer_fails=$rfail eucl=$eucl chunk_exhaustions=${exh:-?} internal_error=$ierr corruption=$corr p72=$p72 err117=$e117 validated_lost=$lost grow=$grow p2_empty=$p2e"
grep -a 'P72-INSTR\|P-DIALLOC .*err=\|P-DIALLOC-P2-EMPTY' "$OUT/dmesg_$A.txt" | cut -c1-300 | head -6 | sed 's/^/  EVIDENCE /'
ck "every racer created all $FILES files" "$done_n" "$RACERS"
ck "no create returned an error" "$rfail" "0"
ck "no 'Structure needs cleaning' (EUCLEAN) from a create" "$eucl" "0"
ck "no XFS internal error on $A" "$ierr" "0"
ck "no 'Corruption detected' on $A" "$corr" "0"
ck "no finobt-near failure (P72-INSTR) on $A" "$p72" "0"
ck "pace: the racers finished inside $LOOP_BOUND_S s" "$( [ -n "${wall_ms:-}" ] && [ "$wall_ms" -le $(( LOOP_BOUND_S * 1000 )) ] && echo 1 || echo 0)" "1"
ck "no DLM request deadline expired on either node" "$lkto" "0"
health=$(cat "$OUT/dmesg_$A.txt" "$OUT/dmesg_$B.txt" | grep -aic "$HEALTH")
ck "kernel health A+B (window)" "$health" "0"
ck "both nodes still mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"
# leave the rig on the default: the knob is rig state, not session state
value_now_into rv2 "$A" 20 "$OUT/rv_rv2_2.txt" '^-?[0-9]+$' "rv2 on $A" "echo 1 > $PARAM; cat $PARAM"
ck "dialloc_validate restored to 1 on $A" "$rv2" "1"
wall=$(( $(date +%s) - s ))
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
