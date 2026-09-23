#!/bin/bash
# sess510_chain_0755.sh — the 0.75.5 verification chain on the 2-node TCP
# rig (QNAP LUN, test1/test2).  Builds NOTHING: the tree's mxfs.ko must be
# the build under test (every prep copies it).
#
#   1  prep 2/tcp                          300 s (measured 42-45 s)
#   2  tests/rejoin_residue.sh             250 s (armed low + armed high + plain; 300 s with RR_HELD_ARM=1)
#   3  tests/sameboot_remount.sh           200 s (now on TCP: 7 cycles)
#   4  prep 2/tcp (step 3 leaves both unmounted)
#   5  tests/transport_conformance.sh      240 s
#
# Usage: tests/sess510_chain_0755.sh <label> [steps=1,2,3,4,5]
set -u
LABEL=${1:?label}
STEPS=${2:-1,2,3,4,5}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
LOG=tests/evidence/sess510_chain_0755_${LABEL}.log
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
want() { case ",$STEPS," in *",$1,"*) return 0;; *) return 1;; esac; }
stage() { say "STAGE $1 rc=$2 wall=$3s $(date -u +%T)"; }
fails=0
say "=== sess510_chain_0755 label=$LABEL steps=$STEPS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') dev=$MXFS_DEV $(date -u +%FT%TZ) ==="

prep() {   # <bound>
    local s=$(date +%s)
    MXFS_FORCE_PREP=1 timeout "$1" ./run.sh 2 tcp prep_cluster >> "$LOG" 2>&1
    local rc=$?; stage "prep" $rc $(( $(date +%s) - s )); return $rc
}
run_step() {  # <name> <bound> <cmd...>
    local name=$1 bound=$2; shift 2
    local s=$(date +%s)
    timeout "$bound" "$@" 2>&1 | tee -a "$LOG" | grep -aE '^  FAIL|^  INFO|^===|^INFRA|^---|^RESULT'
    local rc=${PIPESTATUS[0]}; stage "$name" $rc $(( $(date +%s) - s ))
    [ $rc = 0 ] || fails=$((fails+1))
    return $rc
}

if want 1; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi
if want 2; then run_step rejoin_residue $([ "${RR_HELD_ARM:-0}" = 1 ] && echo 220 || echo 150) tests/rejoin_residue.sh "$LABEL" test1 test2 || { grep -q '^INFRA' "$LOG" && { say "ABORT: a mount hung; the rig needs recovery"; exit 1; }; }; fi
if want 3; then run_step sameboot_remount 200 tests/sameboot_remount.sh "$LABEL" test1 test2; fi
if want 4; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi
if want 5; then run_step transport_conformance 240 tests/transport_conformance.sh "$LABEL" test1 test2; fi

say "DONE label=$LABEL fails=$fails $(date -u +%FT%TZ)"
exit $fails
