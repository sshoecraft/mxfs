#!/bin/bash
# sess446 chain 49 (0.53.0): node_death_replay re-run x2 after the board row
# FAILed on 0.53.0 (run 20260829T113042Z: single lap — victims test4 slot 20 +
# test5 slot 24 killed 6 s apart; slot 20 replayed at +96 s, slot 24 sealed and
# FENCED but its foreign replay never started within 95 s; lap hit its 270 s
# bound; 10 prior PASSes on 0.51.x).  tmpfile_churn_kill.sh now keeps every
# survivor's recovery trail (recov_testN.txt) so a recurrence names the stage.
# budget: per lap prep (300) + row (500); x2.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess446_chain48_0356_umount_quarantine_s446e.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s446f}
LOG=tests/evidence/sess446_chain49_ndr_repro_$LABEL.log
{
  echo "=== sess446 chain49 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  for lap in 1 2; do
    timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep$lap rc=$prc"
    if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; break; fi
    T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay$lap rc=$? wall=$(( $(date +%s) - T0 ))s"
    D=$(ls -dt tests/evidence/board_*_node_death_replay | head -1); echo "EVIDENCE $D"
    for l in shared single; do echo "LAP $l: $(grep -a '^VERDICT\|WAIT ' $D/$l.log 2>/dev/null | head -2 | cut -c1-160 | tr '\n' ' ')"; done
  done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep_final rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
