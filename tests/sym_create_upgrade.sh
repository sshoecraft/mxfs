#!/bin/bash
# tests/sym_create_upgrade.sh — every node creates the same new name in the
# same directory at the same instant, each holding the directory's shared lock
# from a listing a moment before.
#
# Why: on 2/disk/caw/mpath, 2026-10-04T14:37:52Z, the first operation of a load
# on a freshly formed cluster was exactly this (both nodes `makedirs` the same
# directory in the mount root).  Both nodes' exclusive requests on the root
# inode were answered EDEADLK 65 times over 56 s and both shut down ("EDEADLK
# retry livelock").  This drives that shape on purpose and counts.
#
# Per round, at one agreed wall-clock instant every node runs
#     ls <dir>; mkdir <dir>/r<round>
# and reports how long it took and what it returned.  A round is good when
# exactly one node created the directory, every other got "exists", and none
# took longer than ROUND_BOUND_S.
#
# Usage (cluster formed and mounted, e.g. after ./run.sh <config> --group <g> prep_cluster):
#   MXFS_NODE_LIST=test15,test16 tests/sym_create_upgrade.sh [rounds] [subdir]
#     rounds  default 20
#     subdir  default "" = the mount root itself (the measured shape); a name
#             makes the rounds run in <mount>/<name> instead
# Env: MXFS_MNT (default /mnt/shared), ROUND_BOUND_S (default 10: a mkdir is
#      milliseconds; a lock wait behind one peer is well under a second).
#
# derived time budget: rounds x (3 s lead + bound) worst case; ~4 s per good round.
set -u
cd "$(dirname "$0")/.." || exit 2
. tests/lib/rig.sh
ROUNDS=${1:-20}
SUB=${2:-}
NODES=${MXFS_NODE_LIST:?MXFS_NODE_LIST}
NODES=${NODES//,/ }
MNT=${MXFS_MNT:-/mnt/shared}
BOUND=${ROUND_BOUND_S:-10}
DIR=$MNT${SUB:+/$SUB}
TAG=sym$(date -u +%H%M%S)
OUT=tests/evidence/sym_create_upgrade_$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"
T0=$(date -u '+%Y-%m-%d %H:%M:%S')
set -- $NODES
W=$1
[ -z "$SUB" ] || rs 20 "$W" "mkdir -p $DIR" >/dev/null
good=0; bad=0; slow=0
for r in $(seq 1 "$ROUNDS"); do
    at=$(( $(date +%s) + 3 ))
    for n in $NODES; do
        ( rsx $((BOUND + 20)) "$n" "while [ \$(date +%s) -lt $at ]; do sleep 0.01; done; ls $DIR >/dev/null 2>&1; s=\$(date +%s%3N); timeout $BOUND mkdir $DIR/${TAG}_r$r 2>/tmp/sym.err; rc=\$?; e=\$(date +%s%3N); echo ROUND=$r node=$n rc=\$rc ms=\$((e-s)) err=\$(tr -d '\n' < /tmp/sym.err | cut -c1-200)" > "$OUT/r${r}_$n.txt" ) &
    done
    wait
    made=0; exists=0; other=0; worst=0
    for n in $NODES; do
        l=$(grep -a '^ROUND=' "$OUT/r${r}_$n.txt" | tail -1)
        rc=$(sed -n 's/.* rc=\([0-9]*\).*/\1/p' <<<"$l"); ms=$(sed -n 's/.* ms=\([0-9]*\).*/\1/p' <<<"$l")
        case "$rc" in
            0) made=$((made + 1)) ;;
            1) if grep -qa 'File exists' <<<"$l"; then exists=$((exists + 1)); else other=$((other + 1)); fi ;;
            *) other=$((other + 1)) ;;
        esac
        [ "${ms:-999999}" -gt "$worst" ] && worst=${ms:-999999}
    done
    set -- $NODES
    if [ "$made" = 1 ] && [ "$exists" = $(( $# - 1 )) ] && [ "$other" = 0 ]; then good=$((good + 1)); else bad=$((bad + 1)); fi
    [ "$worst" -ge 2000 ] && slow=$((slow + 1))
    echo "round $r: made=$made exists=$exists other=$other worst_ms=$worst"
    [ "$other" = 0 ] || { grep -ah '^ROUND=' "$OUT"/r${r}_*.txt | cut -c1-200; break; }
done
for n in $NODES; do
    rsx 60 "$n" "journalctl -k --since '$T0' --no-pager | grep -ac 'inode lock failed.*rc=-35'; journalctl -k --since '$T0' --no-pager | grep -acE 'retry livelock|hutting down filesystem'" > "$OUT/kern_$n.txt"
    echo "$n: edeadlk=$(sed -n 1p "$OUT/kern_$n.txt") shutdown_lines=$(sed -n 2p "$OUT/kern_$n.txt")"
done
echo "RESULT: rounds=$ROUNDS good=$good bad=$bad slow_ge_2s=$slow dir=$DIR evidence=$OUT"
[ "$bad" = 0 ]
