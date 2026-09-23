#!/bin/bash
# sess433 chain: wait for the detached 0.39.13 board to finish (it insmods
# the tree's mxfs.ko over NFS — NEVER rebuild while it runs), then build
# 0.40.0 (D-379(B)/D-0355 PR-key retention + plain-REGISTER predecessor
# guard), prep 32/caw, and run the directed arms in dependency order:
#   lone_mount_create fixed            (D-0353 regression, 60 s)
#   lone_mount_create remount_refused  (P302 + P305-PRESENT, refused; 100 s)
#   lone_mount_create remount_snx      (P302 + P305-REPLACED + replay; 100 s)
#   d379b_dirty_depart_peer_fence      (peer fences RETAINED key, kind 16; 240 s)
#   lone_crash_replay enforce1/enforce0 (D-0354; 200 s each; virsh-destroys A — LAST)
# budget: every bound is the harness's own derived budget; the board wait is
# node_death_replay's 470 s budget + sweep 60 s from its start.
cd /src/mxfs || exit 1
LABEL=${1:-s433a}
LOG=tests/evidence/sess433_chain_0400_$LABEL.log
BOARD=tests/evidence/sess432_board_03913_s432b.log
{
  echo "=== sess433 chain start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 60); do grep -q '^DONE' "$BOARD" && break; sleep 10; done
  grep -q '^DONE' "$BOARD" || { echo "ABORT: board not DONE after 600 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "board DONE seen $(date -u +%FT%TZ)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > tests/evidence/sess433_build_$LABEL.txt 2>&1; brc=$?
  timeout 120 make tools >> tests/evidence/sess433_build_$LABEL.txt 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  grep -c 'error:' tests/evidence/sess433_build_$LABEL.txt | sed 's/^/build errors=/'
  if [ "$brc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 60  tests/lone_mount_create.sh ${LABEL}_fixed test1 32 fixed;             echo "STAGE fixed rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_snx test1 32 remount_snx;         echo "STAGE remount_snx rc=$?"
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b test1 test2 32; echo "STAGE d379b rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e1 test1 test2 32 enforce1;       echo "STAGE crash_enforce1 rc=$?"
  timeout 200 tests/lone_crash_replay.sh ${LABEL}_e0 test1 test2 32 enforce0;       echo "STAGE crash_enforce0 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
