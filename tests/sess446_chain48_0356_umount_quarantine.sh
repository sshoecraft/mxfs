#!/bin/bash
# sess446 chain 48 (0.53.0): D-UMOUNT-QUARANTINE-TIMEOUT-DIRTY-WITHDRAW-356 —
# first measurement of the sess356 shape on the current tree: forced IN-CLOSURE
# refusal (root EX frozen), then 31 clean umounts.  Expect clean departures
# (no 'DLM inode lock unrecoverable', no shutdown/withdraw, no P302/P301).
# budget: prep (300); umount_under_quarantine ~520 s (600); prep2 (300).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess446_chain47_0512_Aprime_arms3_s446d.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s446e}
LOG=tests/evidence/sess446_chain48_0356_umount_quarantine_$LABEL.log
{
  echo "=== sess446 chain48 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 600 tests/umount_under_quarantine.sh $LABEL 32 test2; echo "STAGE umount_under_quarantine rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
