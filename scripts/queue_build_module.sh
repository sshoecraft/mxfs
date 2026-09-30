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
# MXFS_KCFLAGS (default none) is handed to the kernel build as KCFLAGS, for a
# control build that compiles a test switch in
# (MXFS_KCFLAGS=-DMXFS_TEST_NO_THREAD_REAP).  The flags are not part of the
# srcversion, so a control build and the build it is compared with carry the
# same one: the RESULT line names the flags and the file's sha256, which is
# what tells two such builds apart.  A change of flags rebuilds every object,
# so the build after a control build is a whole one again.
#
# Usage: [MXFS_KCFLAGS=...] scripts/queue_build_module.sh
set -u
cd "$(dirname "$0")/.." || exit 2
make modules -j"$(nproc)" ${MXFS_KCFLAGS:+KCFLAGS="$MXFS_KCFLAGS"} > tests/evidence/queue_build_module.log 2>&1
rc=$?
warn=$(grep 'warning:' tests/evidence/queue_build_module.log | grep -vc 'compiler differs\|Clock skew')
grep -E 'warning:|error:' tests/evidence/queue_build_module.log | grep -v 'compiler differs\|Clock skew' | head -20
v=$(modinfo -F version mxfs.ko 2>/dev/null)
sv=$(modinfo -F srcversion mxfs.ko 2>/dev/null)
sha=$(sha256sum mxfs.ko 2>/dev/null | cut -c1-16)
# every module a queue builds is kept: the next build overwrites the tree's
# file and the next prep overwrites the copy on the nodes, and the return
# addresses of a guest's panic can only be read against the file that ran
if [ "$rc" = 0 ] && [ -n "$sha" ]; then
    mkdir -p tests/evidence/modules
    cp mxfs.ko "tests/evidence/modules/mxfs_${v}_${sha}.ko"
fi
if [ "$rc" = 0 ] && [ "$warn" = 0 ] && [ "$v" = "$(cat VERSION)" ]; then
    echo "RESULT: PASS build version=$v srcversion=$sv sha256=$sha kcflags=[${MXFS_KCFLAGS:-}] warnings=0"
    exit 0
fi
echo "RESULT: FAIL build rc=$rc version=$v (VERSION $(cat VERSION)) srcversion=$sv sha256=$sha kcflags=[${MXFS_KCFLAGS:-}] warnings=$warn"
exit 1
