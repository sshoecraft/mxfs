#!/bin/bash
# sess415 chain — finish the 0.28.0 board verification after the sess414 abort:
#   1. node_death_replay (the row the aborted session never recorded; run.sh
#      preps the fleet first — test9 is shut off from the aborted kill)
#   2. crash_consistency x2 — run 1 after prep may hit the known D-401
#      fresh-prep pace face; run 2 (warm) must PASS in ~16-25s to prove the
#      0.28.0 board FAIL was the pace face and not a D-512 regression.
# Stage timeouts derived (budget):
#   prep_cluster: normal prep ~120s + test9 VM boot ~90s + slack = 300s
#   ndr: 470s test budget + 12s harness + 20s = 500s (cluster already prepped)
#   cc:  90s budget + 12s harness + 30s slack = 132s -> 140s
# v2: run.sh with a test filter refuses to prep a cluster with a stale node
#     marker (test9 down) — an explicit prep_cluster stage is required first.
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_chain.log
{
  echo "=== sess415 chain start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 500 ./run.sh 32 caw node_death_replay
  echo "STAGE ndr rc=$?"
  timeout 140 ./run.sh 32 caw crash_consistency
  echo "STAGE cc1 rc=$?"
  timeout 140 ./run.sh 32 caw crash_consistency
  echo "STAGE cc2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
