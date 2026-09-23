#!/bin/bash
# sess460 chain 88 — three rig-only closure/measurement items, gated on chain 87
# (tests/sess460_chain87_ndr_streak_0616.sh) DONE.  Builds 0.61.7 (the
# P383-RESOLVE caller probe for D-32NODE-SHARED-DIR-CREATE-PACE step 1; no
# behaviour change) production + tools here.
#   1  D-401 step 1 measurement: tests/shared_dir_slot_cost.sh 32 8 — per
#      logical create, WHO asked for each resolution of the directory's slot
#      (P383-RESOLVE histogram by caller and by path).
#   2  D-RELOAD-FREED-ADOPT-BOGUS-IMODE verification: guard_race_arms.sh
#      joiner (the recorded producer) then a fleet sweep asserting ZERO
#      'init_special_inode: bogus i_mode' lines and reporting the
#      P116-ZOMBIE-ADOPT / P-RELOAD-IOPS-REWIRE counts.
#   3  D-MATRIX-UNMEASURED: the caw column at 16, 8 and 2 nodes on THIS build
#      (full board each; the tcp/cawd/cawp columns are retired rig conditions,
#      see compiled-test-environment-infra-reference).
#   then prep 32/caw so the fleet is whole again.
# budget: build 600; prep 300; slot_cost 32x8 measured ~2-3 min -> 300;
# guard_race joiner cap 560 (its header); boards: 16 nodes ~10 min, 8 ~8 min,
# 2 ~6 min (per-row budgets from the manifest inside run.sh).
cd /src/mxfs || exit 1
LABEL=${1:-s460c}
GATE=${GATE:-tests/evidence/sess460_chain87_ndr_streak_s460b.log}
LOG=tests/evidence/sess460_chain88_matrix_resolve_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
lap() { # <budget_s> <label> <cmd...>
  local b="$1" l="$2"; shift 2
  local T0=$(date +%s)
  timeout "$b" "$@"; echo "STAGE $l rc=$? wall=$(( $(date +%s) - T0 ))s"
}
SSH=tools/mxfs_sshpass.sh
{
  echo "=== sess460 chain88 START $(date -u +%FT%TZ) tree VERSION=$(cat VERSION) sv_before=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  T0=$(date +%s)
  timeout 600 make modules > tests/evidence/sess460_chain88_build_$LABEL.log 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess460_chain88_build_$LABEL.log 2>&1
  echo "STAGE build rc=$brc wall=$(( $(date +%s) - T0 ))s sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') errors=$(grep -c 'error:' tests/evidence/sess460_chain88_build_$LABEL.log) resolve_string=$(strings -a mxfs.ko | grep -c 'P383-RESOLVE')"
  if [ "$brc" != 0 ] || [ "$(strings -a mxfs.ko | grep -c 'P383-RESOLVE')" = 0 ]; then echo "ABORT: build failed or probe string missing"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  lap 300 prep ./run.sh 32 caw prep_cluster
  lap 300 "slot_cost 32x8 resolve census" tests/shared_dir_slot_cost.sh 32 8
  lap 300 prep_after_cost ./run.sh 32 caw prep_cluster
  # 2. D-RELOAD verification
  D=$(mktemp -d)
  for i in $(seq 1 32); do ( timeout 20 $SSH test$i "dmesg --clear; echo ok" > "$D/clr$i" 2>&1 ) & done; wait
  lap 560 "guard_race joiner B=test2 FDH=test1" tests/guard_race_arms.sh joiner test2 test1
  for i in $(seq 1 32); do ( timeout 25 $SSH test$i "dmesg | grep -ac 'bogus i_mode'; dmesg | grep -ac 'P116-ZOMBIE-ADOPT'; dmesg | grep -ac 'P-RELOAD-IOPS-REWIRE'" > "$D/sw$i" 2>/dev/null; echo "rc=$?" >> "$D/sw$i" ) & done; wait
  bog=0; zom=0; rew=0; miss=0
  for i in $(seq 1 32); do set -- $(grep -v '^rc=' "$D/sw$i" | tr '\n' ' '); [ $# -ge 3 ] || { miss=$((miss+1)); continue; }; bog=$((bog+$1)); zom=$((zom+$2)); rew=$((rew+$3)); done
  echo "RELOAD-SWEEP bogus_imode=$bog zombie_adopt=$zom iops_rewire=$rew nodes_missing=$miss"
  lap 300 prep_after_guard ./run.sh 32 caw prep_cluster
  # 3. the matrix columns
  for n in 16 8 2; do
    lap 300 "prep $n/caw" ./run.sh $n caw prep_cluster
    T1=$(date +%s); ./run.sh $n caw > tests/evidence/sess460_chain88_board_${n}caw_$LABEL.log 2>&1; echo "STAGE board $n/caw rc=$? wall=$(( $(date +%s) - T1 ))s"
    grep -a 'Total:\|FAIL \|POLICY' tests/evidence/sess460_chain88_board_${n}caw_$LABEL.log | tail -n 6 | cut -c1-200
  done
  lap 300 prep_final ./run.sh 32 caw prep_cluster
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
