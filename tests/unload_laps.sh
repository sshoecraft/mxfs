#!/bin/bash
# unload_laps.sh — N laps of {prep, idle, unmount+unload with the kernel
# window captured} on the two-node TCP rig, to sample a leak that does not
# reproduce on every unload.  The mxfs_buf slab leak (D-0924) showed on three
# consecutive unloads of test1 on one build and on none of the next build's
# single lap; one lap decides nothing.
#
# Each lap: prep_cluster (deploys the tree's mxfs.ko, re-mkfs, mounts), IDLE
# seconds of nothing, then tests/fleet_unload_check.sh <label>N in MODE.
# The rig is left UNMOUNTED after the last lap (run prep afterwards if the
# next work needs a mount).
#
# the budget rule (derived): prep 45-70 s + idle + unload 12-15 s per lap.
#
# Usage: tests/unload_laps.sh <label> [laps=3] [mode=parallel] [idle_s=30]
# Env:   WORKLOAD=<harness> run between prep and unload (see below);
#        MXFS_EXTRA_MODARGS='buf_slab_track=1' loads the module with SLUB
#        allocation tracking on the buffer cache, so a leaking unload prints
#        each remaining object's allocation stack and age.
set -u
LABEL=${1:?label}
LAPS=${2:-3}
MODE=${3:-parallel}
IDLE=${4:-30}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
LOG=tests/evidence/unload_laps_${LABEL}.log
: > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }
say "=== unload_laps label=$LABEL laps=$LAPS mode=$MODE idle=${IDLE}s sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ==="
leaks=0
fails=0
for i in $(seq 1 "$LAPS"); do
    s=$(date +%s)
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster > "tests/evidence/unload_laps_${LABEL}_prep$i.log" 2>&1
    prc=$?
    say "LAP $i prep rc=$prc wall=$(( $(date +%s) - s ))s"
    if [ $prc != 0 ]; then say "RESULT: FAIL label=$LABEL lap=$i prep rc=$prc"; exit 2; fi
    # Two of the three leaking unloads followed the AG-meta leak reproducer;
    # every clean lap was an idle mount.  WORKLOAD runs a harness between the
    # prep and the unload so the sample matches the leaking shape
    # (e.g. WORKLOAD='tests/agmeta_stale_leak_2node.sh' — the lap label is
    # appended; bound 120 s, its own healthy wall is ~14 s).
    if [ -n "${WORKLOAD:-}" ]; then
        ws=$(date +%s)
        timeout 120 $WORKLOAD "${LABEL}w$i" > "tests/evidence/unload_laps_${LABEL}_work$i.log" 2>&1
        wrc=$?
        say "LAP $i workload rc=$wrc wall=$(( $(date +%s) - ws ))s $(grep -a '^RESULT:' "tests/evidence/unload_laps_${LABEL}_work$i.log" | head -1)"
    fi
    sleep "$IDLE"
    out=$(MODE=$MODE timeout 130 tests/fleet_unload_check.sh "${LABEL}$i" 2>&1)
    rc=$?
    echo "$out" >> "$LOG"
    res=$(echo "$out" | grep -a '^RESULT:')
    ev=$(echo "$res" | grep -ao 'evidence=[^ ]*' | cut -d= -f2)
    n1=$(grep -ac 'Object 0x' "$ev/unload_test1.txt" 2>/dev/null)
    n2=$(grep -ac 'Object 0x' "$ev/unload_test2.txt" 2>/dev/null)
    # The tripwire line starts 'mxfs: P-BUF-FREE-LATE daddr='; the two
    # P-BUF-LEAKED-TOTAL lines merely mention the name in their prose.
    late=$(cat "$ev"/unload_test*.txt 2>/dev/null | grep -ac 'P-BUF-FREE-LATE daddr=')
    reg=$(cat "$ev"/unload_test*.txt 2>/dev/null | grep -a 'P-BUF-LEAKED-TOTAL' | grep -ao 'stage=[a-z-]* live=[0-9]*' | tr '\n' ' ')
    say "LAP $i unload rc=$rc objects_test1=${n1:-?} objects_test2=${n2:-?} free_late=$late registry=[${reg}] $(echo "$out" | grep -a 'UNLOAD-MEASURE' | sed 's/^ *//')"
    [ "${n1:-0}" != 0 ] || [ "${n2:-0}" != 0 ] && leaks=$((leaks+1))
    [ $rc = 0 ] || fails=$((fails+1))
done
say "UNLOAD-LAPS-MEASURE label=$LABEL laps=$LAPS mode=$MODE leaking_laps=$leaks failing_laps=$fails"
if [ $fails = 0 ]; then say "RESULT: PASS label=$LABEL laps=$LAPS"; else say "RESULT: FAIL label=$LABEL laps=$LAPS fails=$fails leaking=$leaks"; fi
exit $fails
