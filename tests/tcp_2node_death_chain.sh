#!/bin/bash
# tcp_2node_death_chain.sh — form the 2-node TCP cluster on the shared LUN
# from the tree's current mxfs.ko and run the dirty-death replay oracle
# (tests/tcp_death_replay.sh).  One invocation = one lap; the oracle leaves
# the victim unmounted, so every lap re-forms the cluster first.
#
# the budget rule (derived): prep 2/tcp on the QNAP LUN measured 48 s wall incl.
# preflight (2026-09-04), manifest budget 300 s; the oracle's own bound is
# 240 s.  Chain bound = 300 + 240 + 15 s harness = 555 s per lap.
#
# Usage: tests/tcp_2node_death_chain.sh <label> [laps=1]
# Env:   MXFS_DEV (default: the QNAP TS-453 Pro LUN by-path), MXFS_NODE_LIST
#        (default test1,test2), TDR_* passed through to the oracle.
set -u
LABEL=${1:?label}
LAPS=${2:-1}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
W=${MXFS_NODE_LIST%%,*}
V=${MXFS_NODE_LIST##*,}
LOG=tests/evidence/tcp2dc_${LABEL}.log
: > "$LOG"
echo "=== tcp_2node_death_chain label=$LABEL laps=$LAPS nodes=$MXFS_NODE_LIST dev=$MXFS_DEV sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ===" | tee -a "$LOG"
fails=0
for lap in $(seq 1 "$LAPS"); do
    s=$(date +%s)
    # The previous lap restarted the victim; a prep that reaches it while
    # pam_nologin is still active reads the boot banner as its srcversion
    # ('PREP FAIL: bad nodes: test2(build="System is booting up..."')',
    # s528m/s528n).  Wait, bounded, until every node has finished booting.
    for n in $W $V; do
        w=0
        until [ "$(timeout 15 tools/mxfs_sshpass.sh "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 24 ]; do
            w=$((w+1)); sleep 5
        done
        echo "STAGE boot-wait lap=$lap node=$n polls=$w" | tee -a "$LOG"
    done
    echo "--- lap $lap: prep_cluster 2/tcp $(date -u +%T) ---" | tee -a "$LOG"
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh 2 tcp prep_cluster >> "$LOG" 2>&1
    prc=$?
    echo "STAGE prep lap=$lap rc=$prc wall=$(( $(date +%s) - s ))s" | tee -a "$LOG"
    if [ $prc != 0 ]; then fails=$((fails+1)); echo "STAGE abort: prep failed" | tee -a "$LOG"; break; fi
    s=$(date +%s)
    # 240 s for the plain lap; the RECOVERY_BLOCKED arm (TDR_BLOCK_INJECT=1)
    # adds its 120 s block bound + one 30 s re-drive: pass TDR_LAP_BOUND=400.
    timeout "${TDR_LAP_BOUND:-240}" tests/tcp_death_replay.sh "${LABEL}_l${lap}" "$W" "$V" 2>&1 | tee -a "$LOG"
    trc=${PIPESTATUS[0]}
    echo "STAGE death_replay lap=$lap rc=$trc wall=$(( $(date +%s) - s ))s" | tee -a "$LOG"
    [ $trc = 0 ] || fails=$((fails+1))
done
echo "DONE label=$LABEL laps=$LAPS fails=$fails $(date -u +%FT%TZ)" | tee -a "$LOG"
exit $fails
