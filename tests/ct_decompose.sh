#!/bin/bash
# ct_decompose.sh — decompose concurrent_touch cost into create vs stat vs ls.
# Assumes cluster already mounted at /mnt/shared on test1..testN.
# Runs 3 phases, each launched simultaneously on all N nodes, timing each.
# Usage: tests/ct_decompose.sh [N]   (default 16)
set -u
N=${1:-16}
SSH=/home/steve/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
DIR=/mnt/shared/.ctd_${CTD_TAG:-run}
FPN=100

NODES=(); for i in $(seq 1 "$N"); do NODES+=("test$i"); done

run_all() {  # $1 = remote command (with $ID available)
  local cmd="$1"; local pids=()
  for i in $(seq 1 "$N"); do
    timeout 300 $SSH "test$i" "$PF" "ID=$i; $cmd" >/tmp/ctd_n$i.out 2>&1 &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done
}

echo "=== setup: clean $DIR (node1) + warm parent lookup on all nodes ==="
timeout 30 $SSH test1 "$PF" "rm -rf $DIR; mkdir -p $DIR; sync" >/dev/null 2>&1
sleep 1
# Warm the $DIR lookup on every node so the create storm doesn't race the
# parent-dir lookup/incarnation propagation (the real test uses mkdir -p on
# every node + barriers; this mimics that coherent setup).
for i in $(seq 1 "$N"); do timeout 20 $SSH "test$i" "$PF" "ls $DIR >/dev/null 2>&1; stat $DIR >/dev/null 2>&1" >/dev/null 2>&1 & done; wait

echo "=== PHASE create: $N nodes x $FPN files, parallel $(date -u +%T) ==="
t0=$(date +%s.%N)
run_all "t=\$(date +%s.%N); for j in \$(seq 1 $FPN); do touch $DIR/n\${ID}_f\${j}; done; t2=\$(date +%s.%N); echo create_done \$(echo \"\$t2-\$t\"|bc)"
t1=$(date +%s.%N)
echo "  create wall=$(echo "$t1-$t0"|bc)s"
grep -h create_done /tmp/ctd_n*.out | sort -t' ' -k2 -n | sed -n '1p;'"${N}"'p'

echo "=== converge: sync all nodes + sleep 3 $(date -u +%T) ==="
for i in $(seq 1 "$N"); do timeout 20 $SSH "test$i" "$PF" "sync" >/dev/null 2>&1 & done; wait
sleep 3
echo "=== converged per-node ls count (expect $((N*FPN))) ==="
for i in 1 8 16; do [ "$i" -le "$N" ] || continue; printf "  test%s: " "$i"; timeout 30 $SSH "test$i" "$PF" "ls $DIR 2>/dev/null | wc -l" 2>/dev/null | tr -d ' '; done

echo "=== PHASE stat-own: each node stats its own $FPN files $(date -u +%T) ==="
t0=$(date +%s.%N)
run_all "t=\$(date +%s.%N); miss=0; for j in \$(seq 1 $FPN); do [ -e $DIR/n\${ID}_f\${j} ] || miss=\$((miss+1)); done; t2=\$(date +%s.%N); echo stat_done \$(echo \"\$t2-\$t\"|bc) miss=\$miss"
t1=$(date +%s.%N)
echo "  stat-own wall=$(echo "$t1-$t0"|bc)s"
grep -h stat_done /tmp/ctd_n*.out | awk '{print}' | sort -t' ' -k2 -n | sed -n '1p;'"${N}"'p'
echo "  total miss: $(grep -h stat_done /tmp/ctd_n*.out | grep -oE 'miss=[0-9]+' | cut -d= -f2 | paste -sd+ | bc)"

echo "=== PHASE ls-all: node1 ls full dir $(date -u +%T) ==="
t0=$(date +%s.%N)
cnt=$(timeout 120 $SSH test1 "$PF" "ls $DIR | wc -l" 2>/dev/null | tr -d ' ')
t1=$(date +%s.%N)
echo "  ls-all wall=$(echo "$t1-$t0"|bc)s count=$cnt expected=$((N*FPN))"

echo "=== done $(date -u +%T) ==="
