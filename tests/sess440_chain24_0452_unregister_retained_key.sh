#!/bin/bash
# sess440 chain 24: build 0.45.2 (mxfs_scsipr_unregister refuses when the key
# is not this context's live registration — err_scsipr was unregistering the
# P302-retained same-boot fence target unconditionally; chain 23 s440b
# measured keyheld=0 after the refusal), deploy, verify:
#   prep              32/32 regression gate
#   remount_refused   lone_mount_create: refusal + P302-PR-UNREGISTER-SKIPPED
#                     + key STILL on the LU after the refusal (keyheld>=1)
#   prep2             the fleet re-preps cleanly after the retained key
# Gated on chain 23 DONE.  Budgets: build ~3 min (bound 500), tools 120,
# prep 66-95 s (bound 300), remount_refused bound 100.
cd /src/mxfs || exit 1
LABEL=${1:-s440c}
LOG=tests/evidence/sess440_chain24_0452_unregister_retained_key_$LABEL.log
EV=tests/evidence/sess440_chain24_0452_unregister_retained_key_$LABEL
GATE=tests/evidence/sess440_chain23_0451_dm_rollback_key_retention_s440b.log
mkdir -p "$EV"
{
  echo "=== sess440 chain24 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 120); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain23 not DONE"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t)"
  OLD=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  timeout 500 make modules > "$EV/build.txt" 2>&1; brc=$?
  timeout 120 make tools >> "$EV/build.txt" 2>&1; trc=$?
  NEW=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')
  echo "BUILD_RC=$brc TOOLS_RC=$trc VERSION=$(cat VERSION) sv_old=$OLD sv_new=$NEW"
  echo "build errors=$(grep -c 'error:\|ERROR:' "$EV/build.txt")"
  grep -a 'error:\|ERROR:' "$EV/build.txt" | cut -c1-200 | head -10
  if [ "$brc" -ne 0 ] || [ "$trc" -ne 0 ] || [ "$NEW" = "$OLD" ]; then echo "ABORT: build failed or srcversion unchanged"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 300 ./run.sh 32 caw prep_cluster; prc=$?; echo "STAGE prep rc=$prc"
  if [ "$prc" -ne 0 ]; then echo "ABORT: prep failed on 0.45.2"; echo "DONE $(date -u +%FT%TZ)"; exit 1; fi
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
