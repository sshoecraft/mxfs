#!/bin/bash
# shareddir_probe.sh — measure 4-node concurrent create in ONE shared dir.
# Each node creates N files concurrently, we time the slowest node, then
# check every node sees ALL 4*N files (cross-node dir coherency at scale).
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
D=/mnt/shared/.sdp
N=${1:-20}
NODES="test1 test2 test3 test4"
s(){ timeout 300 "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE 'Warning|Unauthorized|authorized user'; }
s test1 "rm -rf $D; mkdir -p $D; sync"; sleep 1
echo "== phase1: each node creates $N files concurrently =="
for n in $NODES; do
  ( t0=$(date +%s.%N); s $n "for i in \$(seq 1 $N); do echo c_${n}_\$i > $D/${n}_f\$i; done; sync"; t1=$(date +%s.%N); echo "$n create wall: $(echo "$t1-$t0"|bc)s" ) &
done
wait
sleep 2
echo "== phase2: each node sees all $((4*N)) files? =="
for n in $NODES; do
  cnt=$(s $n "ls $D 2>/dev/null | wc -l")
  echo "$n sees: $cnt / $((4*N))"
done
s test1 "rm -rf $D; sync"
