#!/bin/bash
# sess447 chain 51: BUILD 0.53.1 (D-0515 namespace quarantine gate + clean-txn
# backstops) once chain 50 has released the rig, then the D-0515 verification
# lap: tests/umount_under_quarantine.sh with the four-op namespace probe
# (create/mkdir/unlink/rename must be refused rc!=0 on BOTH probed survivors
# with P240-QUAR-NSOP-REFUSE), which is also the D-356 umount face on 0.53.1.
# budget: build ~120 s (bound 300); prep (300); harness ~520 s (660); prep2 (300).
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess446_chain50_owncrash_nosurvivor2_s446g.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s447a}
LOG=tests/evidence/sess447_chain51_0515_nsop_verify_$LABEL.log
{
  echo "=== sess447 chain51 start $(date -u +%FT%TZ) pre-build sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') VERSION=$(cat VERSION) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 300 make modules > tests/evidence/sess447_chain51_build_$LABEL.log 2>&1; brc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "STAGE build rc=$brc old_sv=$OLD new_sv=$NEW errors=$(grep -c 'error:' tests/evidence/sess447_chain51_build_$LABEL.log) warnings=$(grep -c 'warning:' tests/evidence/sess447_chain51_build_$LABEL.log)"
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 660 tests/umount_under_quarantine.sh $LABEL 32 test2; echo "STAGE umount_under_quarantine rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
