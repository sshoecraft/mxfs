#!/bin/bash
# sess444 chain 36 (0.51.1): D-PURGE-NODE-FULL-TABLE-SECTOR-SCAN-0511 — the
# per-dead-node completion cost (mxfs_disklock_purge_node read 65536 sectors
# one at a time: ~8 s per victim, 265 s of chain 32's 545 s bootstrap mount,
# and on every ordinary death).  0.51.1 batches the scan (128 records per
# read) and prints P-PURGE-DONE scan_ms/total_ms + P-COMPLETE-TIMING per
# step.  Measurement: bootstrap_full_restart mount wall (bound 540; chain 32
# measured 545 with ~8.5 s per completion) and the board's node_death_replay
# row (343 s on 0.50.x).
#   build 0.51.1 (bound 500) + tools (120)
#   prep; bootstrap_full_restart (bound 1080)
#   prep; run.sh node_death_replay (row budget 470 + 12 + 15 = 497 -> bound 500)
#   prep2
cd /src/mxfs || exit 1
while ! grep -q "^DONE" tests/evidence/sess444_chain35_0510_takeover_composite_s444d.log 2>/dev/null; do sleep 30; done
LABEL=${1:-s444e}
LOG=tests/evidence/sess444_chain36_0511_purge_pace_$LABEL.log
EV=tests/evidence/sess444_chain36_0511_purge_pace_$LABEL
mkdir -p "$EV"
{
  echo "=== sess444 chain36 start $(date -u +%FT%TZ) ==="
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  echo "build errors=$(grep -c 'error:\|ERROR:' "$EV/build.txt")"
  grep -a 'error:\|ERROR:' "$EV/build.txt" | cut -c1-200 | head -10
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on $(cat VERSION)"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 1080 tests/bootstrap_full_restart.sh $LABEL 32 test1; echo "STAGE bootstrap_full_restart rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep_before_ndr rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed before node_death_replay"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  T0=$(date +%s); timeout 500 ./run.sh 32 caw node_death_replay; echo "STAGE node_death_replay rc=$? wall=$(( $(date +%s) - T0 ))s"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
