#!/bin/bash
# sess469 chain 107: D-SAMENODE-WAITER-CANCEL-COLLISION / D-RECONCILE-SLOT-
# IDENTITY-UNCHECKED closure evidence — the samenode stage chain 99 could not
# finish (the clyde reset at 11:10Z cut its lap 3 and the pair2 lap).
#
# Chain 99 laps 1-2 (frozen 0.64.4): every kernel arm PASSED its contract
# (P275-SAMENODE PASS x4 per lap: collide/collide_late/collide_owed with hex=1
# guard=2 defer=24..30 gm=5 tenure_ex=1, negative with hex=0 w=0 wex=0
# post_hex=0 gm=0 guard=0 defer=0); the selftest's only FAIL was the negative
# arm's stale regex (it did not allow the sess467 post_hex= field) — fixed
# sess469 in tests/caw_samenode_selftest.sh.
#
# This chain: on whatever production module the tree carries when its gate
# opens (chain 102 leaves the 0.64.4 prod module installed), prep_cluster,
# then 3 laps test1/test2 + pair test7/test19, exactly chain 99's stage.
# Budgets: prep 300 s (measured 88-107 s); selftest 150 s (measured 61-63 s).
cd /src/mxfs || exit 1
LABEL=${1:-s469a}
GATE=${GATE:-tests/evidence/sess468_chain102_d377_cond45_s468a.log}
LOG=tests/evidence/sess469_chain107_samenode_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
{
  echo "=== sess469 chain107 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  lap 300 prep_samenode ./run.sh 32 caw prep_cluster
  for lapn in 1 2 3; do
    T1=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test1 test2 all > tests/evidence/sess469_chain107_samenode_${lapn}_$LABEL.log 2>&1; echo "STAGE samenode lap=$lapn rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^=== caw_samenode_selftest' tests/evidence/sess469_chain107_samenode_${lapn}_$LABEL.log | tail -1)"
  done
  T1=$(date +%s); timeout 150 tests/caw_samenode_selftest.sh test7 test19 all > tests/evidence/sess469_chain107_samenode_pair2_$LABEL.log 2>&1; echo "STAGE samenode pair2 rc=$? wall=$(( $(date +%s) - T1 ))s $(grep -a '^=== caw_samenode_selftest' tests/evidence/sess469_chain107_samenode_pair2_$LABEL.log | tail -1)"
  grep -ah '\[samenode\] FAIL\|INFRA' tests/evidence/sess469_chain107_samenode_*_$LABEL.log | sort | uniq -c | sort -rn | head -n 8
  echo "P275 kernel verdicts across all laps: PASS=$(grep -ah 'P275-SAMENODE PASS' tests/evidence/sess469_chain107_samenode_*_$LABEL.log | wc -l) FAIL=$(grep -ah 'P275-SAMENODE FAIL' tests/evidence/sess469_chain107_samenode_*_$LABEL.log | wc -l)"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
