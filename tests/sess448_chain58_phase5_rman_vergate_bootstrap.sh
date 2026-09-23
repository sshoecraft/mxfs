#!/bin/bash
# sess448 chain 58 (0.54.0, PRODUCTION DEFAULTS — no harness arming): the
# remaining design-consult phase-5 coverage for D-FOREIGN-REPLAY-UNGATED-IMAGES after
# chains 55-57: all 9 rman arms (tests/rman_matrix.sh), the vergate LUN arms
# (legacy_refuse upgrade mixed_build), the whole-cluster restart 32/32
# (tests/bootstrap_full_restart.sh) and its ICREATE negative arm.
# the budget rule bounds are the MEASURED walls: rman 9 arms summed 2217 s on 0.41.2
# (sess435 chain 9) -> 2500; vergate LUN 300 (prior bound, RESULT lines carry
# the walls); bootstrap restart 1080 (prior bound; last positive 0.53.x walls
# ~300 s); negative arm measured 189 s -> 1080 bound kept (same harness).
# Waits for chain 57 DONE; must not run concurrently with any other chain.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain57_pending_rows_s447g.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s448a}
LOG=tests/evidence/sess448_chain58_phase5_$LABEL.log
{
  echo "=== sess448 chain58 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 2500 tests/rman_matrix.sh tests/evidence/sess448_rman_0540_$LABEL; echo "STAGE rman_matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  grep -a 'VERDICT\|arm=' tests/evidence/sess448_rman_0540_$LABEL/matrix.txt 2>/dev/null | grep -a VERDICT | cut -c1-200
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep2 rc=$prc"
MXFS_DEV=${MXFS_DEV:?this chain ran the tcpmp condition, TCP over the multipath LUN: name that LUN with MXFS_DEV (never assumed from a rig path)}
  T0=$(date +%s); VG_DEV=$MXFS_DEV timeout 300 tests/vergate.sh test32 legacy_refuse upgrade mixed_build; echo "STAGE vergate_lun rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep3 rc=$prc"
  T0=$(date +%s); timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep4 rc=$prc"
  T0=$(date +%s); MXFS_ICREATE_CORRUPT=test5 timeout 1080 tests/bootstrap_full_restart.sh ${LABEL}n 32 test1; echo "STAGE bootstrap_full_restart_negative rc=$? wall=$(( $(date +%s) - T0 ))s"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
