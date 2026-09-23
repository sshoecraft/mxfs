#!/bin/bash
# sess434 chain 7: waits for chain 6's DONE (0.41.1 on the fleet, prepped), then
# runs the lone-remount arms on 0.41.1 — D-0355/D-379 regression, and the
# runtime capture of the rewritten P300-CLAIM-WITHDRAWN operator text (D-379
# item 2; lone_mount_create.sh now keeps P300-/P274-/P308-/P309- lines).
#   lone_mount_create remount_refused   100 s
#   lone_mount_create remount_snx       100 s
#   prep 32/caw                         300 s
# NEVER `make modules` before this prints DONE.
cd /src/mxfs || exit 1
LABEL=${1:-s434k}
LOG=tests/evidence/sess434_chain7_0411_$LABEL.log
GATE=tests/evidence/sess434_chain6_0411_s434j.log
{
  echo "=== sess434 chain7 start $(date -u +%FT%TZ) ==="
  for t in $(seq 1 240); do grep -q '^DONE' "$GATE" 2>/dev/null && break; sleep 10; done
  grep -q '^DONE' "$GATE" || { echo "ABORT: chain6 not DONE after 2400 s"; echo "DONE $(date -u +%FT%TZ)"; exit 1; }
  echo "gate passed at $(date -u +%FT%TZ) (iter $t) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}')"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_snx test1 32 remount_snx;         echo "STAGE remount_snx rc=$?"
  timeout 300 ./run.sh 32 caw prep_cluster; echo "STAGE prep rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
