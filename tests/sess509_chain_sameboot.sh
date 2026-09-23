#!/bin/bash
# sess509_chain_sameboot.sh — the 0.75.3 verification chain on the 2-node TCP
# rig (QNAP LUN, test1/test2): the same-boot remount harness and the
# transport-conformance harness, each behind its own prep.  Builds NOTHING:
# the tree's mxfs.ko must already be the build under test.
#
#   1  prep 2/tcp                          300 s (measured 45 s)
#   2  tests/sameboot_remount.sh           200 s (7 mount/umount cycles)
#   3  prep 2/tcp (step 2 leaves both unmounted)
#   4  tests/transport_conformance.sh      240 s
#
# Usage: tests/sess509_chain_sameboot.sh <label> [steps=1,2,3,4]
# Env:   MXFS_DEV (default: the QNAP LUN by-path), MXFS_NODE_LIST (test1,test2)
set -u
LABEL=${1:?label}
STEPS=${2:-1,2,3,4}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
LOG=tests/evidence/sess509_chain_sameboot_${LABEL}.log
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
want() { case ",$STEPS," in *",$1,"*) return 0;; *) return 1;; esac; }
stage() { say "STAGE $1 rc=$2 wall=$3s $(date -u +%T)"; }
fails=0
say "=== sess509_chain_sameboot label=$LABEL steps=$STEPS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') dev=$MXFS_DEV $(date -u +%FT%TZ) ==="

prep() {   # <bound>
    local s=$(date +%s)
    MXFS_FORCE_PREP=1 timeout "$1" ./run.sh 2 tcp prep_cluster >> "$LOG" 2>&1
    local rc=$?; stage "prep" $rc $(( $(date +%s) - s )); return $rc
}

if want 1; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi

if want 2; then
    s=$(date +%s); timeout 200 tests/sameboot_remount.sh "$LABEL" test1 test2 2>&1 | tee -a "$LOG" | grep -aE '^  FAIL|^  INFO|^===|^INFRA|^---'
    rc=${PIPESTATUS[0]}; stage "sameboot_remount" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
fi

if want 3; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi

if want 4; then
    s=$(date +%s); timeout 240 tests/transport_conformance.sh "$LABEL" test1 test2 2>&1 | tee -a "$LOG" | grep -aE '^  FAIL|^  INFO|^===|^INFRA|^---'
    rc=${PIPESTATUS[0]}; stage "transport_conformance" $rc $(( $(date +%s) - s )); [ $rc = 0 ] || fails=$((fails+1))
fi

say "DONE label=$LABEL fails=$fails $(date -u +%FT%TZ)"
exit $fails
