#!/bin/bash
# queue_build_module.sh — build mxfs.ko in the tree as a lap-queue step.
#
# WHY IT IS A QUEUE STEP.  Every rig lap's prep insmods the tree's mxfs.ko, so
# the module may only be rebuilt while no lap queue is running.  A new build
# that must follow a running queue therefore goes at the head of the next
# queue (chained with tests/lap_queue_chain.sh): nothing can start the laps
# on the old module, and nothing can rebuild under a lap.
#
# Prints the version and srcversion it built and a RESULT line the queue log
# carries.  Budget: a full rebuild measured 33 s at -j16 on clyde; bound 300.
#
# Usage: scripts/queue_build_module.sh
set -u
cd "$(dirname "$0")/.." || exit 2
make modules -j"$(nproc)" > tests/evidence/queue_build_module.log 2>&1
rc=$?
warn=$(grep 'warning:' tests/evidence/queue_build_module.log | grep -vc 'compiler differs\|Clock skew')
grep -E 'warning:|error:' tests/evidence/queue_build_module.log | grep -v 'compiler differs\|Clock skew' | head -20
v=$(modinfo -F version mxfs.ko 2>/dev/null)
sv=$(modinfo -F srcversion mxfs.ko 2>/dev/null)
if [ "$rc" = 0 ] && [ "$warn" = 0 ] && [ "$v" = "$(cat VERSION)" ]; then
    echo "RESULT: PASS build version=$v srcversion=$sv warnings=0"
    exit 0
fi
echo "RESULT: FAIL build rc=$rc version=$v (VERSION $(cat VERSION)) srcversion=$sv warnings=$warn"
exit 1
