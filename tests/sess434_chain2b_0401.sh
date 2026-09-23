#!/bin/bash
# sess434 chain 2b (0.40.1 on the fleet): waits for chain 2's DONE, then takes
# the budget rule lone-node rsync BASELINE on 0.40.1 (memory-only lone grants) so
# 0.41.0 (real on-disk lone grants, D-0354 candidate A) has a same-rig, same-day
# comparison.  Two laps; leaves the fleet prepped.
#   lone_rsync_bench x2   120 s each (harness-derived)
#   prep 32/caw           300 s
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s434c}
LOG=tests/evidence/sess434_chain2b_0401_$LABEL.log
{
  echo "=== sess434 chain2b start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 150); do grep -q '^DONE' tests/evidence/sess434_chain2_0401_s434b.log 2>/dev/null && break; sleep 10; done
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 120 tests/lone_rsync_bench.sh ${LABEL}_b1 test1 32; echo "STAGE bench1 rc=$?"
  timeout 120 tests/lone_rsync_bench.sh ${LABEL}_b2 test1 32; echo "STAGE bench2 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
