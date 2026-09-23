#!/bin/bash
# sess415 cc pair — after node_death_replay's victim kills, prep_cluster
# restores the killed victims' mounts, then crash_consistency twice:
# run 1 may hit the known D-401 fresh-prep pace face; run 2 (warm) must PASS
# ~16-25s to prove the 0.28.0 board cc FAIL was the pace face, not a D-512
# regression.  Timeouts: prep 300s (VM boot), cc 90s budget + 12s + 30s = 140s.
cd /src/mxfs || exit 1
LOG=tests/evidence/sess415_cc.log
{
  echo "=== sess415 cc pair start $(date -u +%FT%TZ) build=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster
  echo "STAGE prep rc=$?"
  timeout 140 ./run.sh 32 caw crash_consistency
  echo "STAGE cc1 rc=$?"
  timeout 140 ./run.sh 32 caw crash_consistency
  echo "STAGE cc2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
