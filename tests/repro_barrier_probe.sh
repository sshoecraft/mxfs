#!/bin/bash
# sess50 discriminating experiment (NO build): reproduce the barrier stall, then
# on a STUCK node, force an EX acquire (touch a probe file in the same dir) and
# re-check whether the missing marker becomes visible immediately.
#   - If EX-write makes it visible instantly  => reader PR re-acquire fails to
#     force the EX holder to flush; a writer (EX) does. (forcing-function bug)
#   - If still invisible after EX-write        => deeper (dir-block not flushed
#     even on BAST, or concurrent-EX divergence).
set -u
PASS=/tmp/.mxfs_pass
MNT=/mnt/shared
NODES=(test1 test2 test3 test4)
ITERS=${1:-12}
for i in $(seq 1 "$ITERS"); do
  bdir="$MNT/.repro_probe/b$i"
  bash tools/mxfs_sshpass.sh test1 "$PASS" "mkdir -p $MNT/.repro_probe 2>/dev/null; rm -rf $bdir 2>/dev/null" >/dev/null 2>&1
  tmpd=$(mktemp -d)
  # concurrent signal: each node creates the dir + its marker
  for idx in 1 2 3 4; do
    n=${NODES[$((idx-1))]}
    bash tools/mxfs_sshpass.sh "$n" "$PASS" "mkdir -p $bdir 2>/dev/null; touch $bdir/node$idx 2>&1; echo RC=\$?" >"$tmpd/$idx" 2>/dev/null &
  done
  wait
  # Give peers ~3s to converge the normal way
  sleep 3
  # Check each node's view
  stuck=""
  for idx in 1 2 3 4; do
    n=${NODES[$((idx-1))]}
    c=$(bash tools/mxfs_sshpass.sh "$n" "$PASS" "find $bdir -maxdepth 1 -name 'node*' 2>/dev/null | wc -l" 2>/dev/null | tr -d ' ')
    if [ "${c:-0}" -lt 4 ]; then stuck="$stuck $idx:$c"; fi
  done
  if [ -z "$stuck" ]; then
    echo "iter $i: converged (all 4) — no stall"
    rm -rf "$tmpd"; continue
  fi
  echo "iter $i: STALL stuck nodes(idx:count)=$stuck"
  # On the first stuck node, force EX via a probe write, then re-check.
  sidx=$(echo $stuck | awk '{print $1}' | cut -d: -f1)
  sn=${NODES[$((sidx-1))]}
  before=$(bash tools/mxfs_sshpass.sh "$sn" "$PASS" "find $bdir -maxdepth 1 -name 'node*' 2>/dev/null | sort | tr '\n' ',' " 2>/dev/null)
  bash tools/mxfs_sshpass.sh "$sn" "$PASS" "touch $bdir/.probe_ex 2>/dev/null" >/dev/null 2>&1
  after=$(bash tools/mxfs_sshpass.sh "$sn" "$PASS" "find $bdir -maxdepth 1 -name 'node*' 2>/dev/null | sort | tr '\n' ',' " 2>/dev/null)
  echo "   node$sidx before-EX: $before"
  echo "   node$sidx after-EX : $after"
  rm -rf "$tmpd"
done
