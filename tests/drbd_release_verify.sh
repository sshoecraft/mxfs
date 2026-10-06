#!/bin/bash
#
# drbd_release_verify.sh — everything a release that claims 2/net/mesh/drbd
# must pass on the build being released, in one run, detached.
#
# 2/net/mesh/drbd has no pool LUN to share and no SCSI fence, so it is not a
# column of the board the other configurations are graded on; it is verified
# by its own rig (scripts/drbd_rig.sh) and its own board
# (tests/evidence/drbd_rig/criteria.trial.json).  That made it easy to leave
# out: 0.90.42 and the first run of 0.90.48 re-verified sixteen configurations
# and never ran this one.  scripts/release.sh --publish now refuses a version
# whose evidence file from this script does not end in a PASS
# (data/configurations.json, released_by_own_rig).
#
# Usage: [MXFS_GROUP=g2] tests/drbd_release_verify.sh VERSION
#
# Steps, each a scripts/drbd_rig.sh subcommand with its own bounds, each
# logged with its exit code; a failing step does not stop the run, so one run
# shows every failure:
#   up                 two VMs, a LUN each, DRBD dual-primary, the fence authority
#   mxfs + suite       the cluster suite on /dev/drbd0 (its own board)
#   remount-test       clean unmount/remount, a crash-cut retirement, a whole-cluster restart
#   death-test         a node destroyed with MXFS mounted: fenced, certified, replayed, rejoined
#   fence-test         the replication link cut: one node powers the other off and resumes
#   split-test         the link cut on both sides at once: exactly one winner
#   resolve-test       /dev/drbd0 is never resolved to its backing disk; a loop mount is refused
#   outage-test        both nodes die at once and the pair recovers every fsynced file
#   takeover-test      a pair outage whose recovery owner fails: taken over by itself, and by the peer
#   down               unmount, DRBD down, both LUNs returned
# `mxfs` (load, mkfs, mount on both) runs before every test, so each starts
# from a formed pair whatever the test before it left.
#
# The module verified is the tree's mxfs.ko; its srcversion is on the first
# line, and the verdict line names it.
#
# Output: tests/evidence/drbd_release_verify_<VERSION>.out, last line
#   DRBD_RELEASE_VERIFY PASS|FAIL version=<V> srcversion=<S> failed=[...]
#
# Never run beside a board on the same rig group: run.sh treats this rig's
# lock holders as orphans of a dead run and kills them.
#
set -u
V="${1:?usage: tests/drbd_release_verify.sh VERSION}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
O="tests/evidence/drbd_release_verify_$V.out"
SV=$(modinfo -F srcversion mxfs.ko 2>/dev/null)
MV=$(modinfo -F version mxfs.ko 2>/dev/null)
: > "$O"
echo "=== $(date -u +%FT%TZ) drbd_release_verify version=$V module_version=$MV srcversion=$SV group=${MXFS_GROUP:-g2} ===" >> "$O"
[ "$MV" = "$V" ] || { echo "DRBD_RELEASE_VERIFY FAIL version=$V srcversion=$SV failed=[the tree's mxfs.ko is version '$MV', not $V]" >> "$O"; exit 1; }
failed=""
step() {  # step <label> <drbd_rig args...>
    local label=$1 rc
    shift
    echo "=== $(date -u +%FT%TZ) STEP $label: scripts/drbd_rig.sh $* ===" >> "$O"
    scripts/drbd_rig.sh "$@" >> "$O" 2>&1
    rc=$?
    echo "=== STEP $label rc=$rc ($(date -u +%FT%TZ)) ===" >> "$O"
    [ "$rc" = 0 ] || failed="$failed $label"
    return $rc
}
if step up up; then
    step mxfs-suite mxfs && step suite suite
    for t in remount-test death-test fence-test split-test resolve-test outage-test; do
        step "mxfs-$t" mxfs && step "$t" "$t"
    done
    for who in self foreign; do
        step "mxfs-takeover-$who" mxfs && step "takeover-$who" takeover-test "$who"
    done
fi
step down down
if [ -z "$failed" ]; then
    echo "DRBD_RELEASE_VERIFY PASS version=$V srcversion=$SV failed=[]" >> "$O"
    exit 0
fi
echo "DRBD_RELEASE_VERIFY FAIL version=$V srcversion=$SV failed=[${failed# }]" >> "$O"
exit 1
