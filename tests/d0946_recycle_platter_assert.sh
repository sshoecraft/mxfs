#!/bin/bash
# d0946_recycle_platter_assert.sh — does the inode allocator ever hand out a
# number whose platter dinode is still LIVE?  Asserted at the create's own
# recycle gate, on every recycled number, under both arms of the allocator.
#
# D-DIALLOC-REISSUES-INODE-WHOSE-PLATTER-DINODE-IS-STILL-LIVE-DIRTY-CANCEL-SHUTDOWN-0946.
# The chain, proven three times on the two-node TCP rig with nothing killed:
# xfs_dialloc's candidate validator ALLOWED a number on the strength of this
# node's own open FREE obligation (our unpublished free, so the platter still
# carries our live predecessor image), the create's recycle gate then read
# that platter image, called it cross-node incoherence, and returned
# -EFSCORRUPTED on an already-dirty transaction -- a whole-filesystem shutdown.
# The fix (0.75.117-0.75.121) REFUSES such a candidate before anything is
# dirtied, cools it down transiently, kicks the publication and re-picks;
# dialloc_pubpend_refuse=0 keeps the pre-fix arm as the A/B control.
#
# Why the record was still open: the recycle gate's platter read is reached
# only by a "deferred deadshell" (a freed shell that still carries a mode or
# blocks, which ordinary churn never produces -- it took a death/rejoin lap, at
# 3 hits in 16 laps), so the control arm had never reproduced the shutdown on
# demand and no run had ever asserted, for the fix arm, that a handed-out
# number's platter image is free.  0.84.17 adds a test-only knob,
# dbg_recycle_platter_assert, that takes the same platter verdict at EVERY
# create-path recycle (a coherent plain read, never the buffer cache), with
# exact counters (dbg_recycle_platter_checked / _live) so a round proves the
# check ran, and exact counters for the allocator arm itself
# (dialloc_pubpend_refused / _allowed) because its dmesg lines are budgeted.
#
# The workload is the tight churn: FILES fallocated files are primed, then each
# round frees one and immediately re-creates one, twice over, with NO sync
# anywhere -- each free leaves an unpublished image and the very next create
# asks for the lowest free number, which is the one just freed.
#
#   MXFS_D0946_ARM=fix (default): dialloc_pubpend_refuse=1.  Every round must
#     complete every create, the allocator's refusal counter must be non-zero
#     (the arm the fix changed was exercised), the recycle assertion must have
#     RUN (checked > 0) and never fired (live = 0), no shutdown, both nodes
#     mounted, and the files must be present cold on the peer at the end.
#   MXFS_D0946_ARM=control: dialloc_pubpend_refuse=0.  The original chain must
#     appear -- an ALLOW, the assertion firing LIVE, P-CR3-CANCEL trans_dirty=1
#     and the shutdown -- and the run then stops: it has destroyed the mount by
#     design and says so.  Re-prep before anything else is measured.
#
# Usage: tests/d0946_recycle_platter_assert.sh <label> [ROUNDS=6] [FILES=400] [SZ=64k]
# Exit 0 PASS, 1 FAIL, 2 ABORT.  Knobs are restored at the end and on abort.
#
# derived time budget: a tight round of 400 free+create pairs measured
# 3.1-4.7 s on 0.75.117-0.75.121; the assertion adds one plain platter read
# (~0.3 ms) per create; priming ~2 s; the cold check on the peer ~5 s; so
# 6 rounds are under 40 s of rig time and the whole fix run is bounded at
# 180 s (ssh dispatch included).  The control run stops inside round 1.
set -u
LABEL=${1:?label}
ROUNDS=${2:-6}
FILES=${3:-400}
SZ=${4:-64k}
ARM=${MXFS_D0946_ARM:-fix}
case $ARM in
    fix) REFUSE=1 ;;
    control) REFUSE=0 ;;
    *) echo "ABORT: MXFS_D0946_ARM must be fix or control (got '$ARM')"; exit 2 ;;
esac
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=${MXFS_MNT:-/mnt/shared}
P=/sys/module/mxfs/parameters
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_d0946recycle_${ARM}_$LABEL
mkdir -p "$OUT"
# rs/rsx/measure/capture_require/value_now_into/window_into (tests/lib/rig.sh):
# every capture a verdict is taken from crosses the boundary in the parent
# shell first; a failed acquisition is an ABORT, never a count of zero or an
# empty value.
. "$(dirname "$0")/lib/rig.sh"
fails=0
# ck: tests/lib/rig.sh (sourced above) provides it, and its version ABORTs on an EMPTY value instead of printing a FAIL about MXFS
ckge() { if [ -n "$2" ] && [ "$2" -ge "$3" ] 2>/dev/null; then echo "  PASS $1 ($2 >= $3)"; else echo "  FAIL $1 got=$2 want>=$3"; fails=$((fails+1)); fi; }
fld() { echo "$1" | grep -ao "$2=[0-9]*" | head -1 | cut -d= -f2; }
restore_knobs() { rs 20 "$A" "echo 0 > $P/dbg_recycle_platter_assert; echo 1 > $P/dialloc_pubpend_refuse" >/dev/null; }
t0=$(date +%s)
el() { echo $(( $(date +%s) - t0 )); }
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== d0946_recycle_platter_assert label=$LABEL arm=$ARM rounds=$ROUNDS files=$FILES sz=$SZ sv=$SV out=$OUT $(date -u +%FT%TZ) ==="

# PRECONDITION: both nodes on this tree's build and mounted (the validator and
# the assertion are both disabled for a lone mount), the knobs writable on A.
for n in $A $B; do
    st=$(rs 25 "$n" "echo sv=\$(cat /sys/module/mxfs/srcversion) mnt=\$(grep -c ' $MNT mxfs ' /proc/mounts) k=\$(for f in dbg_recycle_platter_assert dbg_recycle_platter_checked dbg_recycle_platter_live dialloc_pubpend_refuse dialloc_pubpend_refused dialloc_pubpend_allowed; do test -w $P/\$f || exit 0; done; echo 1)" | tr -d '\n')
    echo "  INFO $n $st"
    [[ "$st" == *"sv=$SV"* ]] || { echo "ABORT: $n srcversion != tree $SV ($st)"; exit 2; }
    [[ "$st" == *"mnt=1"* ]]  || { echo "ABORT: $n not mounted ($st)"; exit 2; }
    [[ "$st" == *"k=1"* ]]    || { echo "ABORT: $n lacks a writable knob (build older than 0.84.17)"; exit 2; }
done
wprobe=$(rs 40 "$A" "mkdir -p $MNT/.d0946probe.$$ 2>&1 && rmdir $MNT/.d0946probe.$$ 2>&1 && echo WRITABLE || echo NOTWRITABLE")
[[ "$wprobe" == *WRITABLE* ]] && [[ "$wprobe" != *NOTWRITABLE* ]] || { echo "ABORT: $A mounted but not writable: $wprobe"; exit 2; }

D=$MNT/d0946_${LABEL}
# Prime, no sync: FILES live files whose numbers the churn will recycle.
pr=$(rs 120 "$A" "mkdir -p $D || exit 1; cerr=0; for i in \$(seq 1 $FILES); do fallocate -l $SZ $D/f\$i 2>/dev/null || cerr=\$((cerr+1)); done; echo PRIME cerr=\$cerr present=\$(ls $D | grep -c '^f')")
echo "  INFO $pr at +$(el)s"
[ "$(fld "$pr" cerr)" = 0 ] || { echo "ABORT: priming failed ($pr)"; exit 2; }

value_now_into arm "$A" 30 "$OUT/rv_arm_1.txt" '^ARM ' "arm on $A" "echo $REFUSE > $P/dialloc_pubpend_refuse; echo 0 > $P/dialloc_pubpend_refused; echo 0 > $P/dialloc_pubpend_allowed; echo 1 > $P/dbg_recycle_platter_assert; echo ARM refuse=\$(cat $P/dialloc_pubpend_refuse) assert=\$(cat $P/dbg_recycle_platter_assert)"
echo "  INFO $arm"
ck "arm set on $A: dialloc_pubpend_refuse" "$(fld "$arm" refuse)" "$REFUSE"
ck "assertion armed on $A: dbg_recycle_platter_assert" "$(fld "$arm" assert)" "1"
[ "$fails" = 0 ] || { restore_knobs; echo "ABORT: knobs did not take"; exit 2; }

MK0=""
stopped=""
for r in $(seq 1 "$ROUNDS"); do
    MK="D0946R-$LABEL-$$-r$r"
    [ -z "$MK0" ] && MK0=$MK
    out=$(rs 150 "$A" "echo '$MK' > /dev/kmsg
        echo 0 > $P/dbg_recycle_platter_checked; echo 0 > $P/dbg_recycle_platter_live
        echo 0 > $P/dialloc_pubpend_refused; echo 0 > $P/dialloc_pubpend_allowed
        t0=\$(date +%s%N); cerr=0; derr=0
        for i in \$(seq 1 $FILES); do
            rm -f $D/f\$i 2>/dev/null || derr=\$((derr+1))
            fallocate -l $SZ $D/g\$i 2>/dev/null || cerr=\$((cerr+1))
        done
        for i in \$(seq 1 $FILES); do
            rm -f $D/g\$i 2>/dev/null || derr=\$((derr+1))
            fallocate -l $SZ $D/f\$i 2>/dev/null || cerr=\$((cerr+1))
        done
        t1=\$(date +%s%N)
        echo ROUND r=$r cerr=\$cerr derr=\$derr ms=\$(( (t1-t0)/1000000 )) mounted=\$(grep -c ' $MNT mxfs ' /proc/mounts) checked=\$(cat $P/dbg_recycle_platter_checked) live=\$(cat $P/dbg_recycle_platter_live) refused=\$(cat $P/dialloc_pubpend_refused) allowed=\$(cat $P/dialloc_pubpend_allowed) refuse=\$(cat $P/dialloc_pubpend_refuse)
        dmesg | awk '/$MK/{f=1} f' > /tmp/d0946r_win.txt
        echo ALIVE=\$(grep -ac 'P946-RECYCLE-ASSERT-DISKLIVE' /tmp/d0946r_win.txt) AREAD=\$(grep -ac 'P946-RECYCLE-ASSERT-READFAIL' /tmp/d0946r_win.txt) DEFERLIVE=\$(grep -ac 'P-CR63-DEFER-DISKLIVE' /tmp/d0946r_win.txt) CR62=\$(grep -ac 'P-CR62 ' /tmp/d0946r_win.txt) CR3=\$(grep -ac 'P-CR3-CANCEL' /tmp/d0946r_win.txt) DIRTY=\$(grep -ac 'P-CR3-CANCEL.*trans_dirty=1' /tmp/d0946r_win.txt) SHUT=\$(grep -ac 'Shutting down filesystem\|P-WITHDRAW ' /tmp/d0946r_win.txt) VDISKLIVE=\$(grep -ac 'P-DIALLOC-DISKLIVE agno' /tmp/d0946r_win.txt) PSTORM=\$(grep -ac 'P946-DIALLOC-PUBPEND-STORM' /tmp/d0946r_win.txt) CHAINLIVE=\$(grep -ac 'P-FREEOB-CHAIN-LIVE' /tmp/d0946r_win.txt) PUBPEND_LINES=\$(grep -ac 'P946-VALIDATE-PUBPEND' /tmp/d0946r_win.txt) ALLOW_LINES=\$(grep -ac 'P946-VALIDATE-ALLOW' /tmp/d0946r_win.txt)
        grep -a 'P946-VALIDATE-ALLOW\|P946-RECYCLE-ASSERT\|P-CR63-DEFER-DISKLIVE\|P-CR62 \|P-CR3-CANCEL\|Shutting down\|P-WITHDRAW ' /tmp/d0946r_win.txt | head -8 | cut -c1-230")
    echo "  --- round $r at +$(el)s"
    echo "$out" | sed 's/^/     /'
    echo "$out" > "$OUT/round$r.txt"
    rl=$(echo "$out" | grep -a '^ROUND' | head -1)
    cl=$(echo "$out" | grep -a '^ALIVE=' | head -1)
    [ -n "$rl" ] && [ -n "$cl" ] || { echo "  FAIL round $r returned no ROUND/ALIVE line (ssh or node failure)"; fails=$((fails+1)); stopped=r$r; break; }
    if [ "$ARM" = fix ]; then
        ck "round $r: every create succeeded (cerr)" "$(fld "$rl" cerr)" "0"
        ck "round $r: every unlink succeeded (derr)" "$(fld "$rl" derr)" "0"
        ckge "round $r: the recycle assertion RAN (checked)" "$(fld "$rl" checked)" 1
        ck "round $r: no recycled number read LIVE on the platter (live counter)" "$(fld "$rl" live)" "0"
        ck "round $r: no P946-RECYCLE-ASSERT-DISKLIVE line" "$(fld "$cl" ALIVE)" "0"
        ck "round $r: no platter read failure at the assertion" "$(fld "$cl" AREAD)" "0"
        ckge "round $r: the allocator's refusal arm was exercised (refused)" "$(fld "$rl" refused)" 1
        ck "round $r: the control arm never ran (allowed)" "$(fld "$rl" allowed)" "0"
        ck "round $r: no deferred-deadshell DISKLIVE" "$(fld "$cl" DEFERLIVE)" "0"
        ck "round $r: no dirty transaction cancel" "$(fld "$cl" CR3)" "0"
        ck "round $r: no shutdown or withdraw on $A" "$(fld "$cl" SHUT)" "0"
        ck "round $r: no validator LIVE quarantine (the number the allocator handed out was free on the platter for the allocator too)" "$(fld "$cl" VDISKLIVE)" "0"
        ck "round $r: $A still mounted" "$(fld "$rl" mounted)" "1"
    else
        if [ "$(fld "$cl" ALIVE)" != 0 ] || [ "$(fld "$cl" SHUT)" != 0 ] || [ "$(fld "$rl" mounted)" != 1 ]; then
            stopped=r$r
            break
        fi
    fi
done

if [ "$ARM" = fix ]; then
    value_now_into pb "$B" 60 "$OUT/rv_pb_2.txt" '^present_on_B=' "pb on $B" "echo 3 > /proc/sys/vm/drop_caches; echo present_on_B=\$(ls $D 2>/dev/null | grep -c '^f')"
    echo "  INFO $pb (cold on $B) at +$(el)s"
    ck "all $FILES files of the last round present on $B, cold" "$(fld "$pb" present_on_B)" "$FILES"
    value_now_into kn "$A" 20 "$OUT/rv_kn_3.txt" '^refuse=' "kn on $A" "echo refuse=\$(cat $P/dialloc_pubpend_refuse) assert=\$(cat $P/dbg_recycle_platter_assert)"
    ck "the arm held for the whole run ($kn)" "$kn" "refuse=1 assert=1"
    restore_knobs
    rs 90 "$A" "rm -rf $D; sync -f $MNT" >/dev/null
else
    # The control arm is expected to destroy the mount: the chain must be the
    # original one, and it must be the assertion that caught it.
    last=$(cat "$OUT/round${stopped#r}.txt" 2>/dev/null)
    rl=$(echo "$last" | grep -a '^ROUND' | head -1)
    cl=$(echo "$last" | grep -a '^ALIVE=' | head -1)
    ck "control: the run stopped on a fire (round)" "${stopped:-none}" "${stopped:-r?}"
    ckge "control: the allocator ALLOWED a number with an open obligation of ours (allowed)" "$(fld "$rl" allowed)" 1
    ckge "control: the recycle assertion read that number's platter dinode LIVE (P946-RECYCLE-ASSERT-DISKLIVE)" "$(fld "$cl" ALIVE)" 1
    ckge "control: the create failed (cerr)" "$(fld "$rl" cerr)" 1
    ckge "control: the failure cancelled a DIRTY transaction (P-CR3-CANCEL trans_dirty=1)" "$(fld "$cl" DIRTY)" 1
    ckge "control: the filesystem shut down (the original consequence)" "$(fld "$cl" SHUT)" 1
    ck "control: the assertion never fired for a number the fix arm would have handed out (refused)" "$(fld "$rl" refused)" "0"
    restore_knobs
    echo "  PRECOND: the control arm shut $A's filesystem down BY DESIGN.  Re-prep the fleet before any other measurement:"
    echo "           MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster   (or scripts/module_swap_deploy.sh 2 tcp)"
fi
rs 60 "$A" "dmesg | awk '/$MK0/{f=1} f'" > "$OUT/dmesg_${A}.txt"
rs 60 "$B" "dmesg | tail -400" > "$OUT/dmesg_${B}_tail.txt"
echo "=== d0946_recycle_platter_assert $LABEL arm=$ARM: fails=$fails rounds_run=${stopped:-$ROUNDS} wall=$(el)s out=$OUT $(date -u +%FT%TZ) ==="
[ "$fails" = 0 ] && exit 0 || exit 1
