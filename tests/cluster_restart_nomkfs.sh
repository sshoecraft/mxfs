#!/bin/bash
# cluster_restart_nomkfs.sh — a whole-cluster restart WITHOUT mkfs after a
# concurrent unmount that left live grants behind.  Two-node TCP rig.
#
# Why: every prep re-formats the LUN, so the laps that measure a concurrent
# unmount (tests/unload_laps.sh) never see what the NEXT mount inherits from
# it.  A concurrent departure leaves each node's ledger pages either ACTIVE
# under its departed incarnation or PREPARED to a target that also left (the
# peer dropped the FROZEN at its own quiesce); the next era's bootstrap must
# take every one of them over (P-TAUTH-TAKEOVER departed=...) or requests on
# them park (P-TAUTH-PAGE-PARKED, 'lock request failed after').  D-0925.
#
# Shape: both nodes mounted (from a prep, or PREP=1) -> the cross-grant
# workload (~300 live grants per node, half peer-mastered) -> concurrent
# umount+rmmod of both (tests/fleet_unload_check.sh) -> both nodes insmod+mount
# CONCURRENTLY with no mkfs -> wait for the bootstrap node's departure work
# -> the workload again in a fresh directory (its walls against the first
# run's are the pace verdict) -> concurrent unmount again.
#
# the budget rule (derived): workload ~10 s; unload ~10 s; joins 1-5 s healthy, bound
# 20 s each; departure work <= 20 s ceiling; second workload ~10 s; second
# unload ~10 s.  Healthy wall ~60 s; bound 200 s.
#
# Usage: tests/cluster_restart_nomkfs.sh <label> [COUNT=300]
# Env:   MXFS_NODE_LIST (default test1,test2), MXFS_DEV, MXFS_MODARGS (default
#        target_cache_protected=1 force_transport=1), PREP=1 to prep first.
set -u
LABEL=${1:?label}
COUNT=${2:-300}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
export MXFS_TRANSPORT=${MXFS_TRANSPORT:-tcp}
A=${MXFS_NODE_LIST%%,*}
B=${MXFS_NODE_LIST##*,}
SSH=tools/mxfs_sshpass.sh
MNT=/mnt/shared
KO=/root/mxfs.ko.prep
JOIN_BOUND=20
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_restart_$LABEL
mkdir -p "$OUT"
fails=0
ck() { if [ "$2" = "$3" ]; then echo "  PASS $1 ($2)"; else echo "  FAIL $1 got=$2 want=$3"; fails=$((fails+1)); fi; }
# rs/rsx/capture_require/mxfs_dev_resolve (tests/lib/rig.sh): every capture a
# verdict is taken from is proven to hold its tool's shape first; a failed
# acquisition is an ABORT, never a count of zero.  MXFS_DEV: resolved on A
# (its live mount if any, else the MXFS_TRANSPORT rig default).
. "$(dirname "$0")/lib/rig.sh"
field() { grep -ao "^$2=[^ ]*" "$1" | head -1 | cut -d= -f2; }
MODARGS=${MXFS_MODARGS:-$(mxfs_rig_modargs)}   # rig-derived: includes this rig's retirement contract
# jl <node> <mark> > <file>: a kernel journal window; the caller validates
# the file with capture_require 'kernel: ' before counting anything in it
jl() { rsx 20 "$1" "journalctl -k --since @$2 --no-pager 2>/dev/null | cut -c1-700"; }
mxfs_dev_resolve "$A"
MXFS_DEV=$MXFS_DEV_RESOLVED
export MXFS_DEV

echo "=== cluster_restart_nomkfs label=$LABEL A=$A B=$B count=$COUNT sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
s=$(date +%s)
if [ -n "${PREP:-}" ]; then
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep.log" 2>&1
    prc=$?
    echo "STAGE prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then echo "RESULT: FAIL label=$LABEL prep rc=$prc"; exit 2; fi
fi
# Stage 2's join, also used up front when the rig is unmounted (a previous
# run of this harness leaves it so): both nodes insmod + mount at once, no mkfs.
join() {  # <node> <tag>
    rs 60 "$1" "M=\$(date +%s); echo MARK=\$M; lsmod | grep -q '^mxfs ' || insmod $KO $MODARGS; echo INSMOD_RC=\$?; T0=\$(date +%s%N); mountpoint -q $MNT || timeout $JOIN_BOUND mount -t mxfs $MXFS_DEV $MNT; R=\$?; echo MOUNT_RC=\$R; echo WALL_MS=\$(( (\$(date +%s%N) - T0) / 1000000 )); mountpoint -q $MNT && echo MOUNTED || echo NOT_MOUNTED" > "$OUT/$2_join.txt"
}
if [ "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" != 11 ]; then
    join "$A" "A0" & join "$B" "B0" & wait
    echo "STAGE join0 (the rig was unmounted; a no-mkfs join of both first) A rc=$(field "$OUT/A0_join.txt" MOUNT_RC) wall=$(field "$OUT/A0_join.txt" WALL_MS)ms B rc=$(field "$OUT/B0_join.txt" MOUNT_RC) wall=$(field "$OUT/B0_join.txt" WALL_MS)ms"
    sleep 8     # the previous era's departure work (takeover ~6 s measured) before the workload
fi
ck "both nodes mounted" "$(for n in $A $B; do rs 20 "$n" "grep -c ' $MNT mxfs ' /proc/mounts"; done | tr -d '\n')" "11"

# Stage 1: the workload, then the concurrent unmount.
timeout 60 tests/cross_grant_workload.sh "${LABEL}r1" "$COUNT" > "$OUT/work1.log" 2>&1
echo "STAGE work1 rc=$? $(grep -a '^RESULT:\|XGRANT-MEASURE' "$OUT/work1.log" | tr '\n' ' ' | cut -c1-300)"
MODE=parallel timeout 130 tests/fleet_unload_check.sh "${LABEL}u1" > "$OUT/unload1.log" 2>&1
echo "STAGE unload1 rc=$? $(grep -a 'UNLOAD-MEASURE\|departure releases' "$OUT/unload1.log" | sed 's/^ *//' | tr '\n' ' ' | cut -c1-400)"

# Stage 2: both nodes insmod + mount at once, no mkfs.
join "$A" "A" & join "$B" "B" & wait
for n in $A $B; do
    t=$([ "$n" = "$A" ] && echo A || echo B)
    ck "$n remounted without mkfs (rc=$(field "$OUT/${t}_join.txt" MOUNT_RC) wall=$(field "$OUT/${t}_join.txt" WALL_MS)ms, bound ${JOIN_BOUND}s)" "$(field "$OUT/${t}_join.txt" MOUNT_RC)" "0"
done
# The bootstrap node's departure work for the previous era's incarnations
# (its own predecessor settled at P305, the peer's at the monitor) reports
# P-DEPART-WORK; wait for at least one on either node, bounded.
for i in $(seq 1 20); do
    got=0
    for n in $A $B; do
        t=$([ "$n" = "$A" ] && echo A || echo B)
        rs 15 "$n" "journalctl -k --since @$(field "$OUT/${t}_join.txt" MARK) --no-pager 2>/dev/null | grep -aq 'P-DEPART-WORK ' && echo DEPART_DONE" | grep -q DEPART_DONE && got=1
    done
    [ $got = 1 ] && break
    sleep 1
done
echo "  INFO waited ${i}s for the departure work after the remount"
for n in $A $B; do
    t=$([ "$n" = "$A" ] && echo A || echo B)
    jl "$n" "$(field "$OUT/${t}_join.txt" MARK)" > "$OUT/${t}_join_journal.txt"
    f="$OUT/${t}_join_journal.txt"
    ck "$n: zero P-TAUTH-PAGE-PARKED since the remount" "$(grep -ac 'P-TAUTH-PAGE-PARKED' "$f")" "0"
    ck "$n: zero 'lock request failed after' since the remount" "$(grep -ac 'lock request failed after' "$f")" "0"
    ck "$n: zero P-TAUTH-TAKEOVER-NOINC since the remount" "$(grep -ac 'P-TAUTH-TAKEOVER-NOINC' "$f")" "0"
    ck "$n: zero 'shutting down filesystem' since the remount" "$(grep -ac 'shutting down filesystem' "$f")" "0"
    ck "$n: zero 'NOT replayed' mount-recovery rounds" "$(grep -ac 'NOT replayed' "$f")" "0"
    echo "  INFO $n takeover: $(grep -a 'P-TAUTH-TAKEOVER departed=\|P-DEPART-WORK \|P-TAUTH-DEPART-LEFT\|P-TAUTH-IMPORT-RESIDUE\|P305-RETIRE-SETTLED' "$f" | sed 's/.*kernel: //' | grep -ao 'P-TAUTH-TAKEOVER departed=[0-9/]* pages_prepared=[0-9]* skipped=[0-9]*\|cand=[0-9]*\|scan_ms=[0-9]*\|P-DEPART-WORK node=[0-9]* [^ ]* [^ ]* why=[^ ]*\|purge_rc=[-0-9]*\|takeover_ms=[0-9]*\|total_ms=[0-9]*\|P-TAUTH-IMPORT-RESIDUE[^|]*\|P305-RETIRE-SETTLED slot=[0-9]*' | tr '\n' ' ' | cut -c1-600)"
done

# Stage 3: the workload again, in a fresh directory; the walls are the pace
# verdict for the pages the restart inherited.
timeout 60 tests/cross_grant_workload.sh "${LABEL}r2" "$COUNT" > "$OUT/work2.log" 2>&1
w2rc=$?
echo "STAGE work2 rc=$w2rc $(grep -a '^RESULT:\|XGRANT-MEASURE' "$OUT/work2.log" | tr '\n' ' ' | cut -c1-300)"
ck "the workload after the restart passed" "$w2rc" "0"
w1=$(grep -ao 'XGRANT-MEASURE.*' "$OUT/work1.log" | grep -ao 'wall_s=[0-9]*' | cut -d= -f2)
w2=$(grep -ao 'XGRANT-MEASURE.*' "$OUT/work2.log" | grep -ao 'wall_s=[0-9]*' | cut -d= -f2)
ck "the workload after the restart is within 2x the first run's wall (${w2:-?}s vs ${w1:-?}s)" "$([ -n "$w1" ] && [ -n "$w2" ] && [ "$w2" -le $(( w1 * 2 + 1 )) ] && echo 1 || echo 0)" "1"
for n in $A $B; do
    t=$([ "$n" = "$A" ] && echo A || echo B)
    jl "$n" "$(field "$OUT/${t}_join.txt" MARK)" > "$OUT/${t}_journal_after_work2.txt"
    capture_require "$OUT/${t}_journal_after_work2.txt" 'kernel: ' "the kernel journal on $n through the second workload"
    ck "$n: zero P-TAUTH-PAGE-PARKED through the second workload" "$(grep -ac 'P-TAUTH-PAGE-PARKED' "$OUT/${t}_journal_after_work2.txt")" "0"
    ck "$n: zero 'lock request failed after' through the second workload" "$(grep -ac 'lock request failed after' "$OUT/${t}_journal_after_work2.txt")" "0"
    ck "$n: zero P-LKTIMEOUT through the second workload" "$(grep -ac 'P-LKTIMEOUT' "$OUT/${t}_journal_after_work2.txt")" "0"
done

# Stage 4: the concurrent unmount again (the rig is left unmounted).
MODE=parallel timeout 130 tests/fleet_unload_check.sh "${LABEL}u2" > "$OUT/unload2.log" 2>&1
u2rc=$?
echo "STAGE unload2 rc=$u2rc $(grep -a 'UNLOAD-MEASURE\|departure releases' "$OUT/unload2.log" | sed 's/^ *//' | tr '\n' ' ' | cut -c1-400)"
ck "the second concurrent unmount passed its checks" "$u2rc" "0"

wall=$(( $(date +%s) - s ))
echo "  RESTART-MEASURE label=$LABEL joinA_ms=$(field "$OUT/A_join.txt" WALL_MS) joinB_ms=$(field "$OUT/B_join.txt" WALL_MS) work1_s=${w1:-?} work2_s=${w2:-?} $(grep -a 'UNLOAD-MEASURE' "$OUT/unload1.log" | grep -ao 'test[12]_umount_ms=[0-9]*' | sed 's/^/u1_/' | tr '\n' ' ')$(grep -a 'UNLOAD-MEASURE' "$OUT/unload2.log" | grep -ao 'test[12]_umount_ms=[0-9]*' | sed 's/^/u2_/' | tr '\n' ' ')"
if [ $fails = 0 ]; then echo "RESULT: PASS label=$LABEL wall=${wall}s evidence=$OUT"; else echo "RESULT: FAIL label=$LABEL fails=$fails wall=${wall}s evidence=$OUT"; fi
exit $fails
