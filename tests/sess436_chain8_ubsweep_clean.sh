#!/bin/bash
# sess436 chain 8: clean rerun of the fixed ubsweep harness (own-slot re-drive
# path + no-holder free on U accepted), then prep.  Gated on chain 7.
#   ubsweep ~330 s (bound 400); prep 300
cd /src/mxfs || exit 1
LABEL=${1:-s436h}
LOG=tests/evidence/sess436_chain8_ubsweep_clean_$LABEL.log
GATE=tests/evidence/sess436_chain7_s420_queue_s436g.log
{
  echo "=== sess436 chain8 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain7 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 400 tests/crossnode_unlink_ubsweep.sh $LABEL; echo "STAGE ubsweep rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
