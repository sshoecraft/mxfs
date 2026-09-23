#!/bin/bash
# sess436 chain 11: D-RSYNC-OVERWRITE item 2 verification — fence_live_node
# churn arm on 0.41.10 (P-EBADE-BOUNDARY): the victim's churn must show zero
# EBADE.  Gated on chain 10.  Harness bound: prep inside (~130 s) + 75 s
# withdraw + 95 s survivors + sweeps => bound 420 s; then prep.
cd /src/mxfs || exit 1
LABEL=${1:-s436k}
LOG=tests/evidence/sess436_chain11_fln_churn_$LABEL.log
GATE=tests/evidence/sess436_chain10_estale_dlmscaling_s436j.log
{
  echo "=== sess436 chain11 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain10 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 420 tests/fence_live_node.sh $LABEL churn test20 test1 32; echo "STAGE fln_churn rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
