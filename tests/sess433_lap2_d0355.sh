#!/bin/bash
# sess433: second clean lap of the D-0355 LUN arms on 0.40.0 (defect-bar closure
# needs the cause-exercising tests to pass cleanly, not once).  Bounds = each
# arm's own derived budget (60/100/100 s).  Leaves the fleet unmounted on the
# LUN (arms sweep-umount first) — run a prep before any board.
cd /src/mxfs || exit 1
LABEL=${1:-s433c}
LOG=tests/evidence/sess433_lap2_d0355_$LABEL.log
{
  echo "=== lap2 start $(date -u +%FT%TZ) sv=$(modinfo mxfs.ko | awk '/srcversion/{print $2}') ==="
  timeout 60  tests/lone_mount_create.sh ${LABEL}_fixed test1 32 fixed;             echo "STAGE fixed rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused test1 32 remount_refused; echo "STAGE remount_refused rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_snx test1 32 remount_snx;         echo "STAGE remount_snx rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_refused2 test2 32 remount_refused; echo "STAGE remount_refused_test2 rc=$?"
  timeout 100 tests/lone_mount_create.sh ${LABEL}_snx2 test2 32 remount_snx;         echo "STAGE remount_snx_test2 rc=$?"
  echo "DONE $(date -u +%FT%TZ)"
} >> "$LOG" 2>&1
