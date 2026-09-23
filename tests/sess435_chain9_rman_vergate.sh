#!/bin/bash
# sess435 chain 9: D-FOREIGN-REPLAY-UNGATED-IMAGES default-on gate items with
# NO real evidence yet (sess435 inventory): the sess420 rman matrix aborted at
# prep on all 9 arms (tests/evidence/sess420_rman_0300/matrix.txt: rc=3
# 'prep_cluster FAILED'), and vergate mixed_build last ran on 0.39.13.
# Waits for chain 8 (0.41.2 board) to print DONE, then:
#   prep 32/caw
#   tests/rman_matrix.sh  all 9 arms (budget: each arm carries its own wrap 260-330 s)
#   prep 32/caw
#   tests/vergate.sh test32 mixed_build (240 s)
#   prep 32/caw
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s435b}
LOG=tests/evidence/sess435_chain9_rman_vergate_$LABEL.log
GATE=tests/evidence/sess435_chain8_0412_s435a.log
{
  echo "=== sess435 chain9 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 300); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain8 not DONE after 3000 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 3000 tests/rman_matrix.sh tests/evidence/sess435_rman_0412_$LABEL; echo "STAGE rman_matrix rc=$?"
  cat tests/evidence/sess435_rman_0412_$LABEL/matrix.txt
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 240 tests/vergate.sh test32 mixed_build; echo "STAGE vergate_mixed_build rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
