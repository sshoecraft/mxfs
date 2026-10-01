#!/bin/bash
# tcp_2node_death_chain.sh — form the TCP cluster on the shared LUN from the
# tree's current mxfs.ko and run the dirty-death replay oracle
# (tests/tcp_death_replay.sh).  One invocation = one lap; the oracle leaves
# the victim unmounted, so every lap re-forms the cluster first.
#
# The cluster is MXFS_NODE_LIST (default test1,test2): N = its length, the
# first node is the survivor W, the last the victim V.  With more than two
# nodes the middle ones are mounted members that take no role unless an arm
# names them (TDR_PROBE_NODES=<middle nodes> with TDR_BLOCK_INJECT=1 is the
# D-0904 open leg: a non-prover's path op on the victim's directory while the
# recovery is blocked).
#
# the budget rule (derived): prep 2/net/mesh/direct measured 48 s wall incl. preflight
# (2026-09-04), prep 4/net/mesh/direct 65 s (the 2026-09-28 board); manifest budget 300 s;
# the oracle's own bound is 240 s (TDR_LAP_BOUND for the arms).  Chain bound =
# 300 + TDR_LAP_BOUND + 15 s harness per lap.
#
# Usage: tests/tcp_2node_death_chain.sh <label> [laps=1]
# Env:   MXFS_DEV (default: the rig LUN by identity), MXFS_NODE_LIST
#        (default test1,test2), TDR_* passed through to the oracle.
set -u
LABEL=${1:?label}
LAPS=${2:-1}
cd "$(dirname "$0")/.." || exit 2
export MXFS_NODE_LIST=${MXFS_NODE_LIST:-test1,test2}
# the LUN is resolved by identity BEFORE the prep, when nothing is mounted, so
# the resolver needs the transport to know which rig device to look for
# every mounted member, for the oracle: at 3+ nodes the prover and the
# replayer can be any survivor, so it reads every survivor's kernel log
export TDR_MEMBERS=${TDR_MEMBERS:-$MXFS_NODE_LIST}
N=$(echo "$MXFS_NODE_LIST" | tr ',' '\n' | grep -c .)
export MXFS_CONFIG=${MXFS_CONFIG:-$N/net/mesh/direct}
MXFS_CONFIG=$(python3 tools/configuration.py parse "$MXFS_CONFIG") || exit 2
[ "${MXFS_CONFIG%%/*}" = "$N" ] || { echo "MXFS_CONFIG=$MXFS_CONFIG names ${MXFS_CONFIG%%/*} nodes; MXFS_NODE_LIST has $N"; exit 2; }
[ "$N" -ge 2 ] || { echo "MXFS_NODE_LIST needs at least two nodes (got '$MXFS_NODE_LIST')" >&2; exit 2; }
# the device under test by identity, not by path: the LUN this rig declares
# (data/rigs.json), verified by its WWID on the node, and the node's live mxfs
# mount when it has one; MXFS_DEV names a candidate that must be that LUN.
# mxfs_dev_resolve (tests/lib/rig.sh) ABORTs on anything else, never defaults
. "$(dirname "$0")/lib/rig.sh"
mxfs_dev_resolve "${MXFS_NODE_LIST%%,*}"; export MXFS_DEV=$MXFS_DEV_RESOLVED
W=${MXFS_NODE_LIST%%,*}
V=${MXFS_NODE_LIST##*,}
LOG=tests/evidence/tcp${N}dc_${LABEL}.log
: > "$LOG"
echo "=== tcp_2node_death_chain label=$LABEL laps=$LAPS n=$N nodes=$MXFS_NODE_LIST W=$W V=$V probes=${TDR_PROBE_NODES:-none} dev=$MXFS_DEV sv=$(modinfo mxfs.ko | sed -n 's/^srcversion: *//p') $(date -u +%FT%TZ) ===" | tee -a "$LOG"
fails=0
for lap in $(seq 1 "$LAPS"); do
    s=$(date +%s)
    # The previous lap restarted the victim; a prep that reaches it while
    # pam_nologin is still active reads the boot banner as its srcversion
    # ('PREP FAIL: bad nodes: test2(build="System is booting up..."')',
    # s528m/s528n).  Wait, bounded, until every node has finished booting.
    for n in ${MXFS_NODE_LIST//,/ }; do
        w=0
        until [ "$(timeout 15 tools/mxfs_sshpass.sh "$n" 'test -e /run/nologin && echo booting || echo ready' 2>/dev/null | grep -a 'booting\|ready' | tail -1)" = ready ] || [ $w -ge 24 ]; do
            w=$((w+1)); sleep 5
        done
        echo "STAGE boot-wait lap=$lap node=$n polls=$w" | tee -a "$LOG"
    done
    echo "--- lap $lap: prep_cluster $N/tcp $(date -u +%T) ---" | tee -a "$LOG"
    MXFS_FORCE_PREP=1 timeout 300 ./run.sh "$MXFS_CONFIG" prep_cluster >> "$LOG" 2>&1
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
