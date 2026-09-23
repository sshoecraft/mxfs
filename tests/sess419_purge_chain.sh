#!/bin/bash
# sess419_purge_chain.sh — D-PURGE-NONATOMIC-PUBLICATION closure laps,
# relay-proof (setsid+nohup; run it through tests/rig_after.sh so it starts
# only after the previous rig chain's DONE line — never rebuild mxfs.ko
# while a rig run is in flight).
#   build (make modules + make tools) -> for arm in concurrent midscan
#   prefinal: 32/caw prep, tests/d_purge_nonatomic_verify.sh <label> <arm>
#   -> final 32/caw prep.
# the budget rule (derived): build ~400 s cap 500; prep 236 s cap 300 x4; arm 130 s
# cap 200 x3 => ~30 min.
# Usage: tests/sess419_purge_chain.sh <label>
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/sess419_purge_chain_${LABEL}.log
{
  echo "=== purge chain $LABEL start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  timeout 500 make modules > "tests/evidence/sess419_purge_build_${LABEL}.log" 2>&1
  brc=$?
  timeout 120 make tools >> "tests/evidence/sess419_purge_build_${LABEL}.log" 2>&1
  echo "STAGE build rc=$brc sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') warnings=$(grep -c 'warning:' "tests/evidence/sess419_purge_build_${LABEL}.log")"
  if [ $brc -ne 0 ]; then echo "ABORT: build failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  for arm in concurrent midscan prefinal; do
    timeout 300 ./run.sh 32 caw prep_cluster > "tests/evidence/sess419_purge_prep_${LABEL}_$arm.log" 2>&1
    echo "STAGE prep $arm rc=$?"
    timeout 200 tests/d_purge_nonatomic_verify.sh "$LABEL" "$arm"
    echo "STAGE arm $arm rc=$?"
  done
  timeout 300 ./run.sh 32 caw prep_cluster > "tests/evidence/sess419_purge_prep_${LABEL}_final.log" 2>&1
  echo "STAGE prep final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
