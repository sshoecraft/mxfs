#!/bin/bash
# d0286_race_chain.sh — the D-0286 review-item F.1 verification sequence
# on the tree's mxfs.ko, relay-proof: run it under setsid+nohup, it logs
# to tests/evidence (NOT the session scratchpad — sess400 trap) and the
# caller reads the log afterwards.
#
#   for p in 1..5: prep_cluster(32/caw) ; d0286_depart_race.sh <label> p
#   then tests/sess416_board_0286.sh (its own prep + full 32/caw board)
#
# the budget rule (derived, 32/caw): prep 236 s measured (cap 300) + lap <=135 s
# (cap 160) => 5 x ~370 s = ~31 min, then the board chain (~29 min:
# prep 300 + board cap 1400).  Total ~60 min.
#
# Usage: setsid nohup tests/d0286_race_chain.sh <label> [dlm] [points]
#   e.g. tests/d0286_race_chain.sh s419 caw "1 2 3 4 5"
LABEL=${1:?label}; DLM=${2:-caw}; POINTS=${3:-"1 2 3 4 5"}
cd "$(dirname "$0")/.." || exit 2
LOG=tests/evidence/d0286_race_chain_${LABEL}.log
{
  echo "=== d0286 race chain $LABEL dlm=$DLM points=[$POINTS] start $(date -u +%FT%TZ) build=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for p in $POINTS; do
    echo "--- prep before p$p $(date -u +%FT%TZ)"
    timeout 300 ./run.sh 32 "$DLM" prep_cluster > "tests/evidence/d0286_race_chain_${LABEL}_prep_p$p.log" 2>&1
    echo "STAGE prep p$p rc=$?"
    timeout 160 tests/d0286_depart_race.sh "$LABEL" "$p"
    echo "STAGE lap p$p rc=$?"
  done
  echo "--- board chain $(date -u +%FT%TZ)"
  timeout 1900 bash tests/sess416_board_0286.sh
  echo "STAGE boardchain rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
