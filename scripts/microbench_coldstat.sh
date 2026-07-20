#!/bin/bash
# microbench_coldstat.sh — cross-node cold-stat latency probe.
#
# Node A creates NFILES small files; node B then stats+reads each one,
# timing every op. This measures the foreign-inode first-access path
# (EX->PR handoff when the creator still holds cached EX; with
# write-once demote (0.11.11+) the creator should have released EX
# ~250ms after close and B's stat should be ~1ms).
#
# Usage: microbench_coldstat.sh [creator] [reader] [nfiles]
set -u
CREATOR=${1:-test1}
READER=${2:-test2}
NFILES=${3:-50}
PASS=/tmp/.mxfs_pass
SSH=/src/mxfs/tools/mxfs_sshpass.sh
DIR=/mnt/shared/.coldstat.$$

echo "== coldstat: $CREATOR creates $NFILES x 64k, $READER stats+reads =="

timeout 60 "$SSH" "$CREATOR" "$PASS" 'rm -rf '"$DIR"'; mkdir -p '"$DIR"'; for i in $(seq 1 '"$NFILES"'); do dd if=/dev/urandom of='"$DIR"'/f$i bs=64k count=1 conv=fsync 2>/dev/null; done; echo CREATE_DONE' | grep -q CREATE_DONE || { echo "FAIL: create phase"; exit 1; }

# > demote window (default 250ms) so write-once demote has fired
sleep 1

timeout 60 "$SSH" "$READER" "$PASS" '
tot=0; max=0; maxf=""; n=0
totr=0; maxr=0
for i in $(seq 1 '"$NFILES"'); do
  f='"$DIR"'/f$i
  t0=$(date +%s%N); stat "$f" >/dev/null 2>&1; t1=$(date +%s%N)
  dd if="$f" of=/dev/null bs=64k 2>/dev/null; t2=$(date +%s%N)
  s=$(( (t1-t0)/1000 )); r=$(( (t2-t1)/1000 ))
  tot=$((tot+s)); totr=$((totr+r)); n=$((n+1))
  [ $s -gt $max ] && { max=$s; maxf=f$i; }
  [ $r -gt $maxr ] && maxr=$r
done
echo "STAT avg_us=$((tot/n)) max_us=$max maxfile=$maxf  READ avg_us=$((totr/n)) max_us=$maxr  n=$n"'

timeout 30 "$SSH" "$CREATOR" "$PASS" 'rm -rf '"$DIR"'' >/dev/null 2>&1
