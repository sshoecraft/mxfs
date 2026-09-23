#!/bin/bash
# sess436 chain 6: (a) D-CROSSNODE-OPEN-UNLINK ubsweep rerun on 0.41.8 (the
# s420 rerun aborted: test2 unprepped, srcversion ''); (b) one more intents
# burst lap with the domain-aware survivors assertion; prep between.
#   ubsweep ~330 s (bound 400); burst ~115 s (180); prep ~130 s (300)
cd /src/mxfs || exit 1
LABEL=${1:-s436f}
LOG=tests/evidence/sess436_chain6_ubsweep_burst_$LABEL.log
GATE=tests/evidence/sess436_chain5_cc_private_s436e.log
{
  echo "=== sess436 chain6 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 600); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain5 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 400 tests/crossnode_unlink_ubsweep.sh $LABEL; echo "STAGE ubsweep rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 180 tests/d_intents_undischarged_verify.sh ${LABEL}b burst; echo "STAGE intents burst rc=$?"
  sudo virsh -c qemu:///system start test8 >/dev/null 2>&1; sleep 45
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
