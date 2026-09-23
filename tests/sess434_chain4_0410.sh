#!/bin/bash
# sess434 chain 4: waits for chain 3's DONE (0.41.0 on the fleet, prepped), then
# runs the D-379 item-5 verification (chk_mxfs in-progress guard classification,
# forged on an unmounted fleet, sector restored) and re-preps.
#   chk_guard_inprogress_verify   90 s (harness-derived)
#   prep 32/caw                   300 s
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s434g}
LOG=tests/evidence/sess434_chain4_0410_$LABEL.log
GATE=tests/evidence/sess434_chain3_0410_s434e.log
{
  echo "=== sess434 chain4 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 360); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain3 not DONE after 3600 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 90 tests/chk_guard_inprogress_verify.sh ${LABEL}_gip 5 test1 32; echo "STAGE chk_guard_inprogress rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
