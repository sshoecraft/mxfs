#!/bin/bash
# sess433 chain 4 (0.40.1 already on the fleet): waits for chain 3's DONE and
# for the marker that says tests/d379b_dirty_depart_peer_fence.sh has been
# re-armed (enforcement knobs on B — the sess407 harness trap), then:
#   d379b x2 (test1/test2, test5/test6)      D-0357 + D-379 item 4; 240 s each
#   d_mount_window_death_verify window        D-MOUNT-WINDOW owed rerun; 220 s
#   d_mount_window_death_verify control       160 s
#   prep 32/caw                               leave the fleet mounted
cd /src/mxfs || exit 1
LABEL=${1:-s433e}
LOG=tests/evidence/sess433_chain4_0401_$LABEL.log
{
  echo "=== sess433 chain4 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 90); do grep -q '^DONE' tests/evidence/sess433_chain3_0401_s433d.log 2>/dev/null && [ -f tests/evidence/.s433_d379b_armed ] && break; sleep 10; done
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b test1 test2 32;  echo "STAGE d379b rc=$?"
  timeout 240 tests/d379b_dirty_depart_peer_fence.sh ${LABEL}_d379b2 test5 test6 32; echo "STAGE d379b_lap2 rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep1 rc=$?"
  timeout 220 tests/d_mount_window_death_verify.sh ${LABEL}_mw window;  echo "STAGE mwindow_window rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  timeout 160 tests/d_mount_window_death_verify.sh ${LABEL}_mwc control; echo "STAGE mwindow_control rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep3 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
