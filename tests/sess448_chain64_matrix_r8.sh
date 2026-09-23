#!/bin/bash
# sess448 chain 64: domain admission matrix R1-R8 on the 0.55.x PRODUCTION
# build (chain 63 leaves the tree's mxfs.ko as the production build, fleet
# prepped).  R8 = force_transport=1 must be REFUSED 'transport is not CAW'
# (sess448 design-consult ruling; D-0288 containment).  budget: matrix measured 34-35 s
# for 7 rows on 0.54.0 -> 8 rows + rejoin bound 120 s; prep 300.  Gated on
# chain 63 DONE.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess448_chain63_p6p8_rows_s448f.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448g}
LOG=tests/evidence/sess448_chain64_matrix_r8_$LABEL.log
{
  echo "=== sess448 chain64 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) modinfo_lab=$(modinfo mxfs.ko | grep -c '_lab') tcpstr=$(strings -a mxfs.ko | grep -c 'transport is not CAW') ==="
  T0=$(date +%s); timeout 120 tests/domain_admission_matrix.sh ${LABEL}m test32; echo "STAGE domain_matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_after rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
