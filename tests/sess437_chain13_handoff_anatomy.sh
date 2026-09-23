#!/bin/bash
# sess437 chain 13: sharding increment 0 measurement — tests/handoff_anatomy.sh
# at the default MHT quantum (300 ms) and at mht=0, 32 nodes x 100 O_SYNC
# creates into one directory, on whatever build chain 12 deployed (0.41.11).
# Gated on chain 12 printing DONE.  Bound per run 300 s (burst <= 100 s at the
# crash_consistency shape + fleet journal harvest); prep between runs (300 s).
cd /src/mxfs || exit 1
LABEL=${1:-s437b}
LOG=tests/evidence/sess437_chain13_handoff_anatomy_$LABEL.log
GATE=tests/evidence/sess437_chain12_04111_takeover_zeroinc_s437a.log
{
  echo "=== sess437 chain13 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 900); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain12 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 300 tests/handoff_anatomy.sh ${LABEL}_mht300 32 100 keep 50; echo "STAGE anatomy_mht300 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 300 tests/handoff_anatomy.sh ${LABEL}_mht0 32 100 0 50; echo "STAGE anatomy_mht0 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
