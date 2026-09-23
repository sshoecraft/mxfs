#!/bin/bash
# sess436 chain 4: on 0.41.8, burst lap (census-widened refusal assertions)
# + clean lap, prep between.  Gated on chain 3's DONE.
#   burst ~115 s (bound 180); clean ~110 s (bound 180); prep ~130 s (bound 300)
cd /src/mxfs || exit 1
LABEL=${1:-s436d}
LOG=tests/evidence/sess436_chain4_intents_laps_$LABEL.log
GATE=tests/evidence/sess436_chain3_0418_intents_s436c.log
{
  echo "=== sess436 chain4 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain3 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 180 tests/d_intents_undischarged_verify.sh ${LABEL}b burst; echo "STAGE intents burst rc=$?"
  sudo virsh -c qemu:///system start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 180 tests/d_intents_undischarged_verify.sh ${LABEL}c clean; echo "STAGE intents clean rc=$?"
  sudo virsh -c qemu:///system start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
