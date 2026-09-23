#!/bin/bash
# sess434 chain 5: waits for chain 4's DONE (0.41.0 on the fleet, prepped), then
# re-runs the D-MOUNT-WINDOW window_lone arm with the sweep fix (A left to the
# arm's own unmount step) for a clean RESULT, plus the window arm once more on
# 0.41.0 (its barrier calls mxfs_dlm_invalidate_cached_views, changed in
# candidate A), and re-preps.
#   d_mount_window_death_verify window_lone   280 s
#   d_mount_window_death_verify window        220 s
#   prep 32/caw x2                            300 s each
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s434h}
LOG=tests/evidence/sess434_chain5_0410_$LABEL.log
GATE=tests/evidence/sess434_chain4_0410_s434g.log
{
  echo "=== sess434 chain5 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 420); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain4 not DONE after 4200 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 280 tests/d_mount_window_death_verify.sh ${LABEL}_mwl window_lone;  echo "STAGE mwindow_lone rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  timeout 220 tests/d_mount_window_death_verify.sh ${LABEL}_mw window;  echo "STAGE mwindow_window rc=$?"
  for t in $(seq 1 20); do timeout 10 tools/mxfs_sshpass.sh test8 "uptime" >/dev/null 2>&1 && break; sleep 10; done
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
