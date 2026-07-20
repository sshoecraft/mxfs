#!/bin/bash
# repro_barrier_coherency.sh — minimal reproducer for the shared-directory
# concurrent-DISTINCT-entry add coherency bug that makes the cluster test
# barriers (barrier_signal/barrier_wait) time out.
#
# This mirrors what tests/lib/cluster.sh::barrier_signal+barrier_wait do:
#   - every node concurrently creates a distinct file  D/node<N>   (a dirent
#     add into the SHARED directory D, like a barrier signal)
#   - then every node repeatedly lists D and must converge to seeing ALL N
#     node<x> entries (like barrier_wait polling for N signals)
#
# Unlike repro_modea.sh (concurrent SAME-path mkdir → EEXIST races), here
# every entry is distinct, so the ONLY way a node fails to see a peer's
# entry is a lost-update / stale-cache coherency failure in the shared dir.
#
# Reports, per poll round, each node's seen-set, and how long until every
# node sees all N (convergence time).  A stable partition (e.g. 1&4 see
# {1,4}; 2&3 see {2,3}) that never converges is the bug.
#
# Usage: tests/repro_barrier_coherency.sh [nodes_csv] [poll_secs]
#   default nodes: test1,test2,test3,test4   poll window: 120s
set -u
NODES_CSV="${1:-test1,test2,test3,test4}"
POLL="${2:-120}"
IFS=',' read -r -a NODES <<< "$NODES_CSV"
N=${#NODES[@]}
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
D="$MNT/.repro_bc_$$"

run() { timeout 30 "$SSH" "$1" "$PASS" "$2" 2>/dev/null | grep -vE 'Warning|Unauthorized|disconnect|^$'; }

# node index -> marker name node1..nodeN (by position in NODES)
echo "=== repro_barrier_coherency: $N nodes [$NODES_CSV] dir=$D ==="

# Phase 0: node 1 creates the shared dir
run "${NODES[0]}" "mkdir -p $D; sync"

# Phase 1: every node concurrently adds its distinct marker (the "signal")
for idx in "${!NODES[@]}"; do
    id=$((idx+1))
    ( run "${NODES[$idx]}" "echo sig > $D/node$id; sync" >/dev/null ) &
done
wait
echo "all $N markers written (concurrent)"

# Phase 2: poll — each node lists D until it sees all N, up to POLL secs
declare -A converged
start=$SECONDS
allconv=0
while [ $((SECONDS - start)) -lt "$POLL" ]; do
    missing_any=0
    line=""
    for idx in "${!NODES[@]}"; do
        n="${NODES[$idx]}"
        seen=$(run "$n" "ls $D 2>/dev/null | tr '\n' ',' ")
        cnt=$(echo "$seen" | tr ',' '\n' | grep -c '^node[0-9]')
        line="$line  $n=[$seen]($cnt/$N)"
        if [ "$cnt" -ge "$N" ] && [ -z "${converged[$n]:-}" ]; then
            converged[$n]=$((SECONDS - start))
        fi
        [ "$cnt" -ge "$N" ] || missing_any=1
    done
    echo "t=$((SECONDS - start))s$line"
    if [ "$missing_any" = 0 ]; then allconv=1; break; fi
    sleep 3
done

echo "=== convergence ==="
for n in "${NODES[@]}"; do
    echo "  $n: converged at ${converged[$n]:-NEVER}s"
done
run "${NODES[0]}" "rm -rf $D 2>/dev/null" >/dev/null
if [ "$allconv" = 1 ]; then
    echo "RESULT: PASS (all nodes saw all $N markers)"
    exit 0
else
    echo "RESULT: FAIL (stable partition / lost-update; not all nodes converged in ${POLL}s)"
    exit 1
fi
