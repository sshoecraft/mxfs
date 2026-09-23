#!/bin/bash
# sess434 chain 2 (0.40.1 on the fleet): waits for sess434 chain 1's DONE and
# for the marker that says tests/d_mount_window_death_verify.sh has been fixed
# (sess434: late-mask check only on the A-replayed branch; cluster-wide
# publication count via journalctl --since, not a kmsg MARK the 30 other
# nodes never received), then re-runs the D-MOUNT-WINDOW window arm.
#   d_mount_window_death_verify window   measured 130 s (s433e), budget 220 s
#   prep 32/caw                          300 s
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s434b}
LOG=tests/evidence/sess434_chain2_0401_$LABEL.log
{
  echo "=== sess434 chain2 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  for t in $(seq 1 120); do grep -q '^DONE' tests/evidence/sess434_chain1_0401_s434a.log 2>/dev/null && [ -f tests/evidence/.s434_mwindow_fixed ] && break; sleep 10; done
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  timeout 220 tests/d_mount_window_death_verify.sh ${LABEL}_mw window;  echo "STAGE mwindow_window rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
