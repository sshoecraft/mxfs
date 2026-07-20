#!/bin/bash
# RULE-4 repro for the concurrent shared-dir "one lost entry" bug seen in
# test_unlink_visibility / test_rename_vis_dbg at 2 nodes.
# Orchestrated from clyde; phases sequenced via ssh (no in-test barriers).
# Discriminates write-loss vs read-staleness with a fresh reader + remount.
#
# Usage: tests/repro_lost_entry.sh [FILES_PER_NODE] [ITERS]
set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
PF=/tmp/.mxfs_pass
M=/mnt/shared
FPN=${1:-30}
ITERS=${2:-3}

run() { local n="$1"; shift; timeout 80 "$SSH" "test$n" "$PF" "$*" 2>/dev/null; }

for it in $(seq 1 "$ITERS"); do
  T="$M/.mxfs_test/lerepro_$it"
  echo "===== ITER $it (FPN=$FPN) dir=$T ====="
  # parent-dir creation RACE (both nodes), like the real tests
  run 1 "rm -rf $T 2>/dev/null" >/dev/null
  ( run 1 "mkdir -p $T" & run 2 "mkdir -p $T" & wait ) >/dev/null
  # concurrent create: node1 + node2 each FPN files into the SAME dir
  ( run 1 "for i in \$(seq 1 $FPN); do echo d1_\$i > $T/node1_file\$i; done; sync; echo n1done" &
    run 2 "for i in \$(seq 1 $FPN); do echo d2_\$i > $T/node2_file\$i; done; sync; echo n2done" &
    wait ) | tr '\n' ' '; echo
  sleep 1
  exp=$((2*FPN))
  echo "--- counts (node1 owner, node2 peer, node3 fresh) ---"
  for n in 1 2 3; do
    c=$(run $n "ls $T/node*_file* 2>/dev/null | wc -l")
    miss=$(run $n "for i in \$(seq 1 $FPN); do [ -e $T/node1_file\$i ] || echo -n n1f\$i' '; [ -e $T/node2_file\$i ] || echo -n n2f\$i' '; done")
    echo "node$n: count=$c/$exp  missing:[$miss]"
  done
  echo "--- node1 remount, recount (read-staleness test) ---"
  run 1 "cd /; umount $M 2>/dev/null && mount -t mxfs /dev/sda $M 2>/dev/null; echo remounted rc=\$?"
  sleep 1
  c1=$(run 1 "ls $T/node*_file* 2>/dev/null | wc -l")
  miss1=$(run 1 "for i in \$(seq 1 $FPN); do [ -e $T/node1_file\$i ] || echo -n n1f\$i' '; [ -e $T/node2_file\$i ] || echo -n n2f\$i' '; done")
  echo "node1 AFTER remount: count=$c1/$exp  missing:[$miss1]"
done
