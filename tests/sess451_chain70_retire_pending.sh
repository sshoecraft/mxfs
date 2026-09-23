#!/bin/bash
# sess451 chain 70: 0.59.1 RETIRE_PENDING — the sess450 design-consult STOP-SHIP fixes
# (tri-state key state, re-read after a lost CAS, RETIRE_PENDING in the
# admission barrier, P305 same-boot settlement, departure lock) verified on
# the production build:
#   lap 1 pr_unregister_fail_restamp restamp (victim test2)
#   lap 2 pr_unregister_fail_restamp crash   (victim test11)
#   lap 3 pr_unregister_fail_restamp crash   (victim test20)
#   lap 4 retire_pending_admission sameboot  (victim test5, joiner test6)
#   lap 5 retire_pending_admission joiner    (victim test7, joiner test8)
#   lap 6 retire_pending_admission sameboot  (victim test9, joiner test10)
# ABORTs unless the tree's mxfs.ko carries the 0.59.1 strings (no rebuild
# here: the module was built by the session; RULE: never rebuild under a run).
# budget: restamp 300 s, crash 330 s, sameboot 200 s, joiner 270 s (derived
# in the harness headers); tools 120; prep 300 (measured 72-154 s at 32).
cd /src/mxfs || exit 1
LABEL=${1:-s451a}
LOG=tests/evidence/sess451_chain70_retire_pending_$LABEL.log
{
  echo "=== sess451 chain70 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) p305settled=$(strings -a mxfs.ko | grep -c 'P305-RETIRE-SETTLED') admithold=$(strings -a mxfs.ko | grep -c 'P-ADMIT-RETIRE-PENDING-HELD') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'P305-RETIRE-SETTLED')" = 0 ]; then echo "ABORT: mxfs.ko is not a 0.59.1 build"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 120 make tools > tests/evidence/sess451_chain70_tools_$LABEL.log 2>&1; echo "STAGE tools rc=$?"
  T0=$(date +%s); timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 300 tests/pr_unregister_fail_restamp.sh 32 test2 test1 restamp; echo "STAGE pr_restamp mode=restamp victim=test2 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 330 tests/pr_unregister_fail_restamp.sh 32 test11 test1 crash; echo "STAGE pr_restamp mode=crash victim=test11 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 330 tests/pr_unregister_fail_restamp.sh 32 test20 test1 crash; echo "STAGE pr_restamp mode=crash victim=test20 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 200 tests/retire_pending_admission.sh 32 test5 test6 test1 sameboot; echo "STAGE retire_adm arm=sameboot victim=test5 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 270 tests/retire_pending_admission.sh 32 test7 test8 test1 joiner; echo "STAGE retire_adm arm=joiner victim=test7 joiner=test8 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 200 tests/retire_pending_admission.sh 32 test9 test10 test1 sameboot; echo "STAGE retire_adm arm=sameboot victim=test9 rc=$? wall=$(( $(date +%s) - T0 ))s"
  T0=$(date +%s); timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_after rc=$? wall=$(( $(date +%s) - T0 ))s"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
