#!/bin/bash
# sess434 chain 2c (0.40.1 on the fleet): waits for chain 2b's DONE, then runs
# the D-MOUNT-WINDOW record's item-3 arm — window_lone: every survivor is
# unmounted, B alone stays a member, A mounts under the barrier hold, B is
# destroyed; A must fold the late death and replay B's slice INLINE
# (late=<B bit> replayed>=1, A publishes exactly once).  Leaves the fleet
# prepped.
#   d_mount_window_death_verify window_lone   220 s (window budget + 60 s sweep)
#   prep 32/caw                               300 s
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s434f}
LOG=tests/evidence/sess434_chain2c_0401_$LABEL.log
{
  echo "=== sess434 chain2c start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 180); do grep -q '^DONE' tests/evidence/sess434_chain2b_0401_s434c.log 2>/dev/null && break; sleep 10; done
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 280 tests/d_mount_window_death_verify.sh ${LABEL}_mwl window_lone;  echo "STAGE mwindow_lone rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
