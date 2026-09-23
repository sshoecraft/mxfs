#!/bin/bash
# sess419_post_chain.sh — follow-on rig sequence, relay-proof (setsid+nohup):
#   0. WAIT for tests/d0286_race_chain.sh's DONE line (never rebuild mxfs.ko
#      while a rig run is in flight — the preps insmod the tree's .ko over
#      NFS and a rebuild splits the run's srcversion).
#   1. build 0.29.1 (make modules + make tools) — the ICLUS set-time refusal.
#   2. 32/caw prep, tests/f2_iclus_refusal.sh (gate item 2 verification).
#   3. 32/tcp prep (mpatha condition), tests/d0287_remaster_measure.sh with
#      the clean-departure trigger (MODE=umount default) — first instrumented
#      measurement of D-0287.
#   4. 32/caw prep to leave the rig in the board condition.
#
# the budget rule (derived): wait <= 3600 s (chain: 5 x ~370 s + board ~29 min from
# 04:59Z); build ~180 s (near-full after pal.h changed in 0.29.0; measured
# sess418 build.log) cap 400; prep 236 s cap 300 each; f2_iclus 70 s cap 90;
# d0287 120 s cap 200.
# Usage: setsid nohup tests/sess419_post_chain.sh <label> <chain-log>
LABEL=${1:?label}; CHAIN=${2:?chain log}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/sess419_post_chain_${LABEL}.log
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
TCPENV="MXFS_DEV=$MXFS_DEV MXFS_CRIT=/src/mxfs/criteria.tcpmp.json"
{
  echo "=== post-chain $LABEL start $(date -u +%FT%TZ) waiting on $CHAIN ==="
  w=0
  while ! grep -aq '^DONE ' "$CHAIN" 2>/dev/null; do
    sleep 30; w=$((w+30))
    if [ $w -ge 3600 ]; then echo "ABORT: chain not DONE after ${w}s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  done
  echo "chain DONE seen after ${w}s $(date -u +%FT%TZ)"
  echo "--- build $(cat VERSION)"
  timeout 400 make modules > "tests/evidence/sess419_build_${LABEL}.log" 2>&1
  brc=$?
  timeout 120 make tools >> "tests/evidence/sess419_build_${LABEL}.log" 2>&1
  echo "STAGE build rc=$brc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "tests/evidence/sess419_build_${LABEL}.log")"
  if [ $brc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  echo "--- caw prep $(date -u +%FT%TZ)"
  timeout 300 ./run.sh 32 caw prep_cluster > "tests/evidence/sess419_prep_caw1_${LABEL}.log" 2>&1
  echo "STAGE prep caw1 rc=$?"
  timeout 90 tests/f2_iclus_refusal.sh "$LABEL" test5
  echo "STAGE f2_iclus rc=$?"
  echo "--- tcp prep $(date -u +%FT%TZ)"
  env $TCPENV timeout 300 ./run.sh 32 tcp prep_cluster > "tests/evidence/sess419_prep_tcp1_${LABEL}.log" 2>&1
  echo "STAGE prep tcp1 rc=$?"
  timeout 200 tests/d0287_remaster_measure.sh "$LABEL"
  echo "STAGE d0287 rc=$?"
  echo "--- caw prep (leave rig in board condition) $(date -u +%FT%TZ)"
  timeout 300 ./run.sh 32 caw prep_cluster > "tests/evidence/sess419_prep_caw2_${LABEL}.log" 2>&1
  echo "STAGE prep caw2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
