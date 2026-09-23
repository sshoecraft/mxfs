#!/bin/bash
# sess460 chain 87: D-FOREIGN-REPLAY-UNGATED-IMAGES disposition evidence on the
# build that carries BOTH halves of that record's fix — the token gate (false-
# APPLY, default-on since 0.54.0) and the class-gated bypass of the cross-slice
# on-disk-LSN veto (false-SKIP, 0.61.4 / D-0517) — under production defaults:
#   node_death_replay x N_NDR (each lap: prep + the board's death row =
#   tmpfile_churn_kill auto:shared then auto:single, no harness arming),
#   then the FULL 32/caw board, then a prep.
# Gated on chain 86 (tests/sess460_chain86_review6_conditions.sh) DONE — chain
# 86 built 0.61.6 production; no rebuild here.  Any FAIL resets the streak.
# budget: per NDR lap prep 300 + row 500 (measured 342-392 s); board ~12 min
# (per-row budgets from the manifest); prep 300.
cd /src/mxfs || exit 1
LABEL=${1:-s460b}; N_NDR=${2:-6}
GATE=${GATE:-tests/evidence/sess460_chain86_review6_s460a.log}
LOG=tests/evidence/sess460_chain87_ndr_streak_$LABEL.log
while ! grep -q "^DONE" "$GATE" 2>/dev/null; do sleep 30; done
{
  echo "=== sess460 chain87 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) override_string=$(strings -a mxfs.ko | grep -c 'OVERRIDE-APPLY') ==="
  if [ "$(strings -a mxfs.ko | grep -c 'OVERRIDE-APPLY')" = 0 ]; then echo "ABORT: mxfs.ko lacks the 0.61.4 buffer-LSN bypass"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  ndr_pass=0
  for lap in $(seq 1 $N_NDR); do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_ndr$lap rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; break; fi
    T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
    ok=1; for l in shared single; do v=$(grep -a '^VERDICT' $D/$l.log 2>/dev/null | head -1 | cut -c1-160); echo "LAP$lap $l: $v"; echo "$v" | grep -q 'VERDICT PASS' || ok=0; done
    [ $ok = 1 ] && ndr_pass=$((ndr_pass+1))
    echo "LAP$lap f4truth: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ao 'truth=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
    echo "LAP$lap buflsn: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -ao 'buflsn_skips=[0-9]* buflsn_overrides=[0-9]*' | sort | uniq -c | tr '\n' ' ') verdicts: $(cat $D/*/recov_test*.txt 2>/dev/null | grep -a 'P-FR-BUF-LSN' | grep -ao 'verdict=[A-Z-]*' | sort | uniq -c | tr '\n' ' ')"
  done
  echo "NDR_STREAK pass=$ndr_pass of $N_NDR"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_board rc=$?"
  T0=$(date +%s); ./run.sh 32 caw > tests/evidence/sess460_chain87_board_$LABEL.log 2>&1; echo "STAGE board rc=$? wall=$(( $(date +%s) - T0 ))s"
  grep -a 'Total:\|FAIL \|POLICY' tests/evidence/sess460_chain87_board_$LABEL.log | tail -n 8 | cut -c1-200
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
