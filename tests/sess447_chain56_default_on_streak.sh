#!/bin/bash
# sess447 chain 56 (0.54.0, production defaults): design-consult phase-5 streak after
# chain 55 — domain matrix re-run (parser fixed, expect 7/7), unlinker_death
# x N_OUD (production defaults, no harness arming), node_death_replay x N_NDR
# (continues chain 55's 3 toward >= 10 consecutive).  Any FAIL is reported and
# resets the streak count in the ledger (do not hide it).
# budget: matrix 240; per unlinker_death case ~4 min (400) + prep 300; per NDR
# row prep 300 + row 500.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain55_0540_default_on_s447e.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447f}; N_OUD=${2:-10}; N_NDR=${3:-7}
LOG=tests/evidence/sess447_chain56_default_on_streak_$LABEL.log
{
  echo "=== sess447 chain56 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 240 tests/domain_admission_matrix.sh ${LABEL}m test32; echo "STAGE domain_matrix rc=$? wall=$(( $(date +%s) - T0 ))s"
  oud_pass=0
  for i in $(seq 1 $N_OUD); do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_oud$i rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; break; fi
    EV=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_oud_${LABEL}_$i; mkdir -p "$EV"
    T0=$(date +%s); timeout 400 tests/openunlink_deaths.sh unlinker_death test1 test2 > "$EV/deaths.txt" 2>&1; rc=$?
    echo "STAGE unlinker_death$i rc=$rc wall=$(( $(date +%s) - T0 ))s $(grep -a '^RESULT' "$EV/deaths.txt" | head -1 | cut -c1-160)"
    grep -a 'production defaults\|POLICY-REFUSED\|quarantin\|FAIL' "$EV/deaths.txt" | head -4 | cut -c1-160
    grep -aq '^RESULT: PASS' "$EV/deaths.txt" && oud_pass=$((oud_pass+1))
  done
  echo "OUD_STREAK pass=$oud_pass of $N_OUD"
  ndr_pass=0
  for lap in $(seq 1 $N_NDR); do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_ndr$lap rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; break; fi
    T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
    ok=1; for l in shared single; do v=$(grep -a '^VERDICT' $D/$l.log 2>/dev/null | head -1 | cut -c1-160); echo "LAP$lap $l: $v"; echo "$v" | grep -q 'VERDICT PASS' || ok=0; done
    [ $ok = 1 ] && ndr_pass=$((ndr_pass+1))
    echo "LAP$lap f4truth: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ao 'truth=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
  done
  echo "NDR_STREAK pass=$ndr_pass of $N_NDR"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
