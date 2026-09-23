#!/bin/bash
# sess434 chain 6: the rig is idle (chains 1-5 DONE).  Build 0.41.1:
#   - P308 incarnation boundary after mount recovery (xfs_log.c)
#   - P310 provenance-certified pre-incarnation skip (FEAT_ADOPTED ->
#     RECOV_F_VICTIM_ADOPTED -> TXNV_PREINC), P309 log-tail diagnostics
#   - unconditional BAST polling (dlm_caw.c), MXFS_PROTO_GEN 11
#   - recov_forge descriptor v3, chk_mxfs guard verification
# then verify in dependency order:
#   chk_guard_inprogress_verify   D-379 item 5 (90 s; unmounts the fleet itself)
#   prep 32/caw
#   d513_forged_record_checks valid  proves the v3 forge reaches the kernel's shape path (120 s)
#   lone_mount_create fixed          D-0353 regression (60 s)
#   lone_crash_replay enforce1 x2    D-0354 closure arms (200 s each; virsh-destroys A)
#   d379b_dirty_depart_peer_fence    D-0357/D-379 regression (240 s)
#   lone_rsync_bench                 the budget rule (120 s)
#   prep 32/caw
cd /src/mxfs || exit 1
LABEL=${1:-s434i}
LOG=tests/evidence/sess434_chain6_0411_$LABEL.log
{
  echo "=== sess434 chain6 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess434_build6_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess434_build6_$LABEL.txt 2>&1; trc=$?
  ( cd tools && timeout 60 gcc -Wall -Wextra -O2 -I../include -o recov_forge recov_forge.c ) >> tests/evidence/sess434_build6_$LABEL.txt 2>&1; frc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc FORGE_RC=$frc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess434_build6_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 90  tests/chk_guard_inprogress_verify.sh ${LABEL}_gip 5 test1 32;          echo "STAGE chk_guard_inprogress rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 120 tests/d513_forged_record_checks.sh valid 40 test32;                     echo "STAGE d513_valid rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep1b rc=$?"
  timeout 60  tests/lone_mount_create.sh ${LABEL}_fixed test1 32 fixed;               echo "STAGE fixed rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1 test1 test2 32 enforce1;         echo "STAGE crash_enforce1 rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test1 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1b test5 test6 32 enforce1;        echo "STAGE crash_enforce1b rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test5 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b test3 test4 32;   echo "STAGE d379b rc=$?"
  timeout 120 tests/lone_rsync_bench.sh ${LABEL}_b1 test1 32;                         echo "STAGE bench1 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
