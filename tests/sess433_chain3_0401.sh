#!/bin/bash
# sess433 chain 3: build 0.40.1 (D-0357 CAW release gate on a poisoned
# departure + chk_mxfs guard classification + P300 text), prep 32/caw, then:
#   lone_mount_create fixed            (D-0353 regression, 60 s)
#   d379b_dirty_depart_peer_fence      (expect kind16 + replay complete + file=1; 240 s)
#   d379b again with A=test3 B=test4   (second lap, 240 s)
#   full armed 32/caw board via tests/sess432_board_03913.sh pattern is NOT
#   run here (rig time); node_death_replay is exercised by the next board.
# the budget rule bounds = each harness's own.  Fleet is left mounted after prep (the
# arms sweep-umount, so a prep is queued at the end for the next board).
cd /src/mxfs || exit 1
LABEL=${1:-s433d}
LOG=tests/evidence/sess433_chain3_0401_$LABEL.log
{
  echo "=== sess433 chain3 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess433_build3_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess433_build3_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess433_build3_$LABEL.txt | sed 's/^/build errors=/'
  grep -n 'warning:' tests/evidence/sess433_build3_$LABEL.txt | grep -v 'BTF' | head -5
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 60  tests/lone_mount_create.sh ${LABEL}_fixed test1 32 fixed;               echo "STAGE fixed rc=$?"
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b test1 test2 32;  echo "STAGE d379b rc=$?"
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b2 test3 test4 32; echo "STAGE d379b_lap2 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
