#!/bin/bash
# sess447 chain 57: the 7 rows chain 55's board wrapper (900 s, too short:
# measured summed walls ~509 s + 12 s x 19 overhead + preflight/prep) left
# PENDING on the 0.54.0 production-default board: ag_strand_repair (240),
# sustained_load (180), dirent_publish_integrity (60), dirent_type_integrity
# (60), dlm_lock_correctness, open_defects (30; policy-red by design), and the
# node_death_replay row (chains 55/56 run it separately).  budget: budgets sum
# 570 + 12 x 6 + 15 => wrapper 660 s.
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess447_chain56_default_on_streak_s447f.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447g}
LOG=tests/evidence/sess447_chain57_pending_rows_$LABEL.log
{
  echo "=== sess447 chain57 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 660 ./run.sh 32 caw ag_strand_repair sustained_load dirent_publish_integrity dirent_type_integrity dlm_lock_correctness open_defects; echo "STAGE rows rc=$? wall=$(( $(date +%s) - T0 ))s"
  ./showstat.sh 32 caw 2>/dev/null | grep -a 'PASS\|FAIL\|SKIP\|PENDING\|Total' | cut -c1-140
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
