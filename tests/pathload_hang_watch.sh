#!/bin/bash
# tests/pathload_hang_watch.sh — run tests/mpath/pathload.py on every node of a
# formed cluster with no fault injected, and catch any operation that blocks.
#
# Why: on 2/disk/caw/mpath (2026-10-04, D-CAW-TWO-NODE-SHARED-DIR-OPS-HANG-
# 480S-UNDER-PATHLOAD) one node's churn and the other node's mutex operation in
# the same shared directory blocked together for 480 s and then completed
# within 0.2 s of each other, and by the time anyone looked the kernel logs of
# the window had rotated away.  This watches for that and records what a
# diagnosis needs WHILE the operations are still blocked:
#   - every node's kernel log, followed into a file on the node from a mark
#     (dmesg --follow), so nothing depends on the journal or the ring;
#   - the kernel stack of each node's load process and of every task in D
#     state (/proc/<pid>/stack, /proc/*/stat: both safe to read on a node
#     with a wedged task, unlike cmdline);
#   - the lock-slot table as the platter holds it (tools/caw_slotdump
#     --held-only), on disk/caw configurations;
# then keeps watching until the operations complete, and records when.
#
# A hang is no completed operation on a node for HANG_S seconds.  Healthy
# operations of this load take milliseconds and there are no faults here, so
# 20 s is far outside anything legitimate.
#
# Usage (cluster formed and mounted):
#   MXFS_NODE_LIST=test15,test16 MXFS_CONFIG=2/disk/caw/mpath \
#       tests/pathload_hang_watch.sh [duration_s] [hang_s] [resolve_s]
#     duration_s  how long to run the load (default 1800)
#     hang_s      no completion for this long is a hang (default 20)
#     resolve_s   after a hang, how long to keep watching for it to end
#                 (default 900)
# Env: MXFS_MNT (default /mnt/shared), MXFS_DEV (default /dev/mapper/mpatha),
#      HW_MAX_CAPTURES (default 3),
#      HW_CYCLE_S (default 0 = one load for the whole duration): stop the load
#      on every node and start it again each time it has run this long.  The
#      one hang on record began 17.7 s after both nodes' loads were started
#      together, and 30 minutes of one continuous load did not show another,
#      so the start is worth repeating.
# Exit 0 when no hang was seen, 1 when one was.
#
# derived time budget: duration + at most HW_MAX_CAPTURES x resolve_s, plus
# ~60 s to stop the load and copy the logs.
set -u
cd "$(dirname "$0")/.." || exit 2
. tests/lib/rig.sh
DUR=${1:-1800}
HANG_S=${2:-20}
RESOLVE_S=${3:-900}
MAXCAP=${HW_MAX_CAPTURES:-3}
NODES_CSV=${MXFS_NODE_LIST:?MXFS_NODE_LIST}
NODES=${NODES_CSV//,/ }
MNT=${MXFS_MNT:-/mnt/shared}
DEV=${MXFS_DEV:-/dev/mapper/mpatha}
CFG=${MXFS_CONFIG:-}
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=tests/evidence/pathload_hang_watch_$TS
LABEL="hw_$TS"
mkdir -p "$OUT"
MARK="HW-MARK-$TS"
KFILE=/run/mxfs_hw_kmsg.$TS
STOP=/run/mxfs_hw.$TS.stop
now_ms() { date +%s%3N; }
set -- $NODES
W=$1

echo "  INFO nodes=[$NODES] config=${CFG:-?} duration=${DUR}s hang=${HANG_S}s resolve=${RESOLVE_S}s evidence=$OUT"
for n in $NODES; do kmsg_follow_start "$n" "$MARK" "$KFILE"; done
CYCLE_S=${HW_CYCLE_S:-0}
cycles=0
start_loads() {
    local n pids=()
    for n in $NODES; do
        mkdir -p "$OUT/load_$n"
        rs 20 "$n" "rm -f $STOP; nohup setsid python3 /src/mxfs/tests/mpath/pathload.py run $n $MNT /src/mxfs/$OUT/load_$n $STOP > /src/mxfs/$OUT/load_$n/run.out 2>&1 < /dev/null &" >/dev/null &
        pids+=($!)
    done
    wait "${pids[@]}"
    cycles=$((cycles + 1))
    t_cycle=$(( $(date +%s) + CYCLE_S ))
}
restart_loads() {  # stop every node's load, see each end, start them together again
    local n i
    for n in $NODES; do ( rs 15 "$n" "touch $STOP" >/dev/null 2>&1 ) & done; wait
    for n in $NODES; do
        i=0; while [ $i -lt 45 ] && ! grep -aq '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null; do sleep 1; i=$((i + 1)); done
        grep -a '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null | tail -1 >> "$OUT/load_$n/cycles.txt"
        grep -aq '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null || return 1
    done
    start_loads
}
start_loads
cleanup() {
    local n
    for n in $NODES; do ( rs 15 "$n" "touch $STOP" >/dev/null 2>&1 ) & done; wait
}
trap cleanup EXIT

last_ok() {  # <node>: end time (ms) of the newest completed operation, or 0
    tail -c 8192 "$OUT/load_$1/ops.log" 2>/dev/null | tr -d '\000' \
        | awk 'NF >= 4 && $4 == "ok" && $2 ~ /^[0-9]+$/ {t = $2} END {print t + 0}'
}
inflight() {  # <node>: the operation after the newest logged one
    tail -c 8192 "$OUT/load_$1/ops.log" 2>/dev/null | tr -d '\000' \
        | awk 'NF >= 4 && $2 ~ /^[0-9]+$/ {o = $3} END {print o}'
}

# What a node runs to show its blocked tasks.  The state is the first field
# after the parenthesised comm, which may itself contain spaces.
STACKS='p=$(cat PIDFILE 2>/dev/null); [ -n "$p" ] || p=none
echo "LOAD_PID=$p state=$(sed "s/.*) //" /proc/$p/stat 2>/dev/null | cut -d" " -f1) wchan=$(cat /proc/$p/wchan 2>/dev/null)"
cat /proc/$p/stack 2>/dev/null
echo "--- tasks in D state"
for s in /proc/[0-9]*/stat; do
    d=${s%/stat}
    st=$(sed "s/.*) //" $s 2>/dev/null | cut -d" " -f1)
    [ "$st" = D ] || continue
    echo "TASK pid=${d#/proc/} comm=$(cat $d/comm 2>/dev/null)"
    cat $d/stack 2>/dev/null
done
echo STACKS_END'

capture() {  # <tag>
    local tag=$1 n
    for n in $NODES; do
        (
            rsx 60 "$n" "${STACKS//PIDFILE//src/mxfs/$OUT/load_$n/pid}" > "$OUT/${tag}_stacks_$n.txt"
            rsx 60 "$n" "sed -n '/$MARK/,\$p' $KFILE | grep -a 'P-LKWAIT\|P-CAWEXH\|P139-LOCKTOTAL\|EDEADLK\|P109\|P221\|P204\|P203\|STANDBACK\|P912\|P958\|inode lock\|LKTIMEOUT\|P-CAW-ANSWER\|hutting down\|P-WITHDRAW\|blocked for more' | tail -300; echo LOG_END" > "$OUT/${tag}_kmsg_$n.txt"
        ) &
    done
    wait
    case "$CFG" in
        */disk/caw/*|*/disk/caw)
            rsx 120 "$W" "/src/mxfs/tools/caw_slotdump $DEV --held-only --max 400 2>&1; echo SLOTDUMP_END" > "$OUT/${tag}_slotdump.txt" ;;
    esac
    echo "  INFO $tag captured: $(for n in $NODES; do printf '%s[load %s] ' "$n" "$(grep -ao 'state=[A-Z]* wchan=[^ ]*' "$OUT/${tag}_stacks_$n.txt" | head -1)"; done)"
}

t_end=$(( $(date +%s) + DUR ))
hangs=0; caps=0; summary=""
sleep 10
while [ "$(date +%s)" -lt "$t_end" ]; do
    sleep 2
    now=$(now_ms); worst=0; who=""
    for n in $NODES; do
        l=$(last_ok "$n")
        [ "$l" -gt 0 ] || continue
        a=$((now - l))
        [ "$a" -gt "$worst" ] && { worst=$a; who=$n; }
    done
    if [ "$worst" -lt $((HANG_S * 1000)) ]; then
        if [ "$CYCLE_S" -gt 0 ] && [ "$(date +%s)" -ge "$t_cycle" ]; then
            restart_loads || echo "  INFO cycle $cycles: a load did not end within 45 s of being told to; leaving it for the hang check"
            sleep 5
        fi
        continue
    fi
    hangs=$((hangs + 1))
    h0=$now
    ops=$(for n in $NODES; do printf '%s:%s(%ss) ' "$n" "$(inflight "$n")" "$(( (now - $(last_ok "$n")) / 1000 ))"; done)
    echo "  HANG $hangs at $(date -u +%T): no completion on $who for $((worst / 1000)) s; in flight after the last logged op: $ops"
    if [ "$caps" -lt "$MAXCAP" ]; then caps=$((caps + 1)); capture "hang${hangs}_t0"; fi
    resolved=""
    t_res=$(( $(date +%s) + RESOLVE_S )); mid=0
    while [ "$(date +%s)" -lt "$t_res" ]; do
        sleep 2
        ok=1
        for n in $NODES; do [ "$(last_ok "$n")" -gt "$h0" ] || ok=0; done
        [ "$ok" = 1 ] && { resolved=$(( ($(now_ms) - h0) / 1000 + worst / 1000 )); break; }
        if [ "$mid" = 0 ] && [ $(( $(now_ms) - h0 )) -ge 120000 ] && [ "$caps" -le "$MAXCAP" ]; then
            mid=1; capture "hang${hangs}_t120"
        fi
    done
    if [ -n "$resolved" ]; then
        echo "  HANG $hangs ended: every node completed operations again; blocked about ${resolved} s in all"
        summary="$summary hang$hangs=${resolved}s"
        capture "hang${hangs}_after"
    else
        echo "  HANG $hangs did NOT end within ${RESOLVE_S} s of detection"
        summary="$summary hang$hangs=unresolved"
        capture "hang${hangs}_unresolved"
        break
    fi
done

trap - EXIT
cleanup
for n in $NODES; do
    i=0; while [ $i -lt 45 ] && ! grep -aq '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null; do sleep 1; i=$((i + 1)); done
    echo "  INFO $n: $(grep -a '^PATHLOAD ' "$OUT/load_$n/run.out" 2>/dev/null | tail -1)"
done
for n in $NODES; do
    rsx 180 "$n" "kill \$(cat $KFILE.pid 2>/dev/null) 2>/dev/null; sed -n '/$MARK/,\$p' $KFILE; rm -f $KFILE $KFILE.pid" > "$OUT/kmsg_$n.txt"
    gzip -f "$OUT/kmsg_$n.txt"
done
echo "RESULT: hangs=$hangs${summary:+ $summary} duration=${DUR}s load_starts=$cycles evidence=$OUT"
[ "$hangs" = 0 ]
