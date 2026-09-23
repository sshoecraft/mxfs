#!/bin/bash
# sess511_chain_0756.sh — the whole-cluster-restart chain on the 2-node TCP
# rig (QNAP LUN, test1/test2).  Builds NOTHING: the tree's mxfs.ko must be
# the build under test (every prep copies it).
#
#   1  prep 2/tcp                                  300 s (measured 42-45 s)
#   2  tests/sameboot_remount.sh ARMS=1             200 s (healthy ~60 s; the
#                                                    s510b shape hangs the
#                                                    join 60 s and cascades)
#   3  scripts/vm_cycle.sh --if-loaded test1 test2  600 s (only nodes that
#                                                    still hold mxfs)
#   4  prep 2/tcp
#   5  tests/sameboot_remount.sh (all arms)          200 s
#   6  scripts/vm_cycle.sh --if-loaded test1 test2
#   7  prep 2/tcp
#   8  tests/transport_conformance.sh                240 s
#   9  prep 2/tcp
#  10  tests/rejoin_residue.sh                       150 s
#  11  (optional) prep + rejoin_residue RR_HELD_ARM=1 400 s
#  12  (optional) prep + sameboot arm 1, B's join held 12 s  250 s
#
# Usage: tests/sess511_chain_0756.sh <label> [steps=1,2,3,4,5,6,7,8,9,10]
set -u
LABEL=${1:?label}
STEPS=${2:-1,2,3,4,5,6,7,8,9,10}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
LOG=tests/evidence/sess511_chain_0756_${LABEL}.log
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
want() { case ",$STEPS," in *",$1,"*) return 0;; *) return 1;; esac; }
stage() { say "STAGE $1 rc=$2 wall=$3s $(date -u +%T)"; }
fails=0
say "=== sess511_chain_0756 label=$LABEL steps=$STEPS sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') dev=$MXFS_DEV $(date -u +%FT%TZ) ==="

prep() {   # <bound>
    local s=$(date +%s)
    MXFS_FORCE_PREP=1 timeout "$1" ./run.sh 2 tcp prep_cluster >> "$LOG" 2>&1
    local rc=$?; stage "prep" $rc $(( $(date +%s) - s )); return $rc
}
run_step() {  # <name> <bound> <cmd...>
    local name=$1 bound=$2; shift 2
    local s=$(date +%s)
    timeout "$bound" "$@" 2>&1 | tee -a "$LOG" | grep -aE '^  FAIL|^  INFO|^===|^INFRA|^---|^RESULT|^\[vm_cycle\]'
    local rc=${PIPESTATUS[0]}; stage "$name" $rc $(( $(date +%s) - s ))
    [ $rc = 0 ] || fails=$((fails+1))
    return $rc
}
cycle() {  # <bound>
    local s=$(date +%s)
    timeout "$1" scripts/vm_cycle.sh --if-loaded test1 test2 2>&1 | tee -a "$LOG" | grep -a '^\[vm_cycle\]'
    local rc=${PIPESTATUS[0]}; stage "vm_cycle" $rc $(( $(date +%s) - s ))
    [ $rc = 0 ] || { say "ABORT: the rig could not be recovered"; exit 1; }
}

if want 1; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi
if want 2; then ARMS=1 run_step sameboot_arm1 200 tests/sameboot_remount.sh "${LABEL}a1" test1 test2; fi
if want 3; then cycle 600; fi
if want 4; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi
if want 5; then run_step sameboot_remount 200 tests/sameboot_remount.sh "$LABEL" test1 test2; fi
if want 6; then cycle 600; fi
if want 7; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi
if want 8; then run_step transport_conformance 240 tests/transport_conformance.sh "$LABEL" test1 test2; fi
if want 9; then prep 300 || { say "ABORT: prep failed"; exit 1; }; fi
if want 10; then run_step rejoin_residue 150 tests/rejoin_residue.sh "$LABEL" test1 test2; fi
# Optional steps (not in the default list):
#  11  prep + rejoin_residue with the planted arm 4 (RR_HELD_ARM=1, both
#      parities since 0.75.16): the phantom the P109-EDEADLK-NL arm must
#      heal                                                      400 s
#  12  prep + sameboot arm 1 with B's join held 12 s so A's takeover of its
#      predecessor's pages completes alone (the D-0906 hand-on hole)  250 s
if want 11; then prep 300 || { say "ABORT: prep failed"; exit 1; }; RR_HELD_ARM=1 run_step rejoin_residue_held 400 tests/rejoin_residue.sh "${LABEL}h" test1 test2; fi
if want 12; then prep 300 || { say "ABORT: prep failed"; exit 1; }; ARMS=1 SAMEBOOT_ARM1_DELAY_S=12 run_step sameboot_arm1_delayed 250 tests/sameboot_remount.sh "${LABEL}dly" test1 test2; fi

say "DONE label=$LABEL fails=$fails $(date -u +%FT%TZ)"
exit $fails
