#!/bin/bash
# sess570_chain_ghost.sh — the verification chain for the mount-barrier
# admission hold on frozen foreign heartbeat records (0.75.80).
#
# The defect it exercises: both nodes of the two-node TCP rig destroyed with
# their mounts in flight, then brought back onto the same LUN with no mkfs and
# no operator action.  Before 0.75.80 the barrier called the empty cut clean
# eight seconds in, admitted, and the root-inode read then failed EIO because
# AG 0's ledger page named a dead incarnation as its authority
# (tests/evidence/20260909T011714Z_ghost_s567).
#
# Shape, per lap: fresh prep (mkfs + mount both) -> cross-grant workload so both
# slices are dirty and both nodes hold live grants -> ghost probe (destroys both
# VMs mid-mount, restarts, concurrent join).  Two laps, because one clean join
# proves the path once and the shape is a race.
#
# EVERY LAP RE-PREPS, and that is not tidiness.  The probe leaves ACTIVE
# heartbeat records behind only when the mounts it destroys had SUCCEEDED; a lap
# chained onto a failed one starts from an empty table and measures nothing.
# s570b did exactly that (hb-before: 0 ACTIVE) and reported a near-pass over a
# shape it never reproduced.
#
# the budget rule (derived, measured 2026-09-09): prep 47 s (bound 300); workload 11 s
# (bound 120); a ghost probe is VM restart 153 s + join <= 300 s + journal
# capture ~30 s, measured 252 s and 435 s -> bound 480.  Per lap 900 s; two
# laps 1800 s.  A lap that hits its own bound is a FAILURE, not a slow pass.
#
# Usage: tests/sess570_chain_ghost.sh <label>
# Env:   LAPS (default 2)
set -u
LABEL=${1:?label}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
LAPS=${LAPS:-2}
OUT=tests/evidence/$(date -u +%Y%m%dT%H%M%SZ)_chain_$LABEL
mkdir -p "$OUT"
SV=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p')
echo "=== sess570_chain_ghost label=$LABEL sv=$SV laps=$LAPS $(date -u +%FT%TZ) ==="
echo "=== evidence $OUT"
fails=0

lap=1
while [ $lap -le "$LAPS" ]; do
    tag=$(printf '%s%c' "$LABEL" "$(printf "\\$(printf '%03o' $((96 + lap)))")")

    t=$(date +%s)
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "$OUT/prep$lap.log" 2>&1
    rc=$?
    echo "STAGE lap$lap prep rc=$rc wall=$(( $(date +%s) - t ))s  $(grep -am1 'prep_cluster OK\|FAIL' "$OUT/prep$lap.log" | cut -c1-160)"
    [ $rc = 0 ] || { echo "RESULT: FAIL label=$LABEL lap=$lap stage=prep evidence=$OUT"; exit 2; }

    t=$(date +%s)
    timeout 120 tests/cross_grant_workload.sh "${tag}w" 300 > "$OUT/work$lap.log" 2>&1
    rc=$?
    echo "STAGE lap$lap work rc=$rc wall=$(( $(date +%s) - t ))s"
    grep -a 'PASS\|FAIL\|XGRANT-MEASURE\|RESULT' "$OUT/work$lap.log" | sed 's/^/    /'
    [ $rc = 0 ] || fails=$((fails+1))

    t=$(date +%s)
    timeout 480 tests/ghost_slot_restart_probe.sh "$tag" > "$OUT/lap$lap.log" 2>&1
    rc=$?
    echo "STAGE lap$lap probe rc=$rc wall=$(( $(date +%s) - t ))s"
    cat "$OUT/lap$lap.log"
    [ $rc = 0 ] || fails=$((fails+1))

    lap=$((lap+1))
done

if [ $fails = 0 ]; then
    echo "RESULT: PASS label=$LABEL laps=$LAPS evidence=$OUT"
    exit 0
fi
echo "RESULT: FAIL label=$LABEL laps=$LAPS fails=$fails evidence=$OUT"
exit 1
