#!/bin/bash
# tests/mpath/laps.sh — repeat the path-fault rows on one mpath configuration.
#
# One board run is one sample of a fault whose outcome depends on where the
# fault lands in the lock traffic.  This re-prepares the cluster once, then
# runs the named rows LAPS times through run.sh (so every result lands on the
# board with its evidence and each row keeps its own budget), and after each
# lap prints how often each node took the wait-behind-a-live-party path
# (P-LKWAIT-LIVE), the counter that says a lap actually reached the window the
# yield-target fix covers.
#
# Usage: tests/mpath/laps.sh <config> <group> <laps> [<row>...]
#   tests/mpath/laps.sh 2/disk/caw/mpath g2b 5
#   tests/mpath/laps.sh 2/net/mesh/mpath g2 5 path_failover path_fabric
# Default rows: path_failover path_fabric path_flap.
set -u
cd "$(dirname "$0")/../.." || exit 2
CFG=${1:?config} G=${2:?group} LAPS=${3:?laps}
shift 3
ROWS=${*:-path_failover path_fabric path_flap}
MXFS_FORCE_PREP=1 ./run.sh "$CFG" --group "$G" prep_cluster 2>&1 | grep -aE 'prep OK|attach|PREP FAIL|ERROR|rc='
NODES=$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1])).get("node_list") or "").replace(",", " "))' ".cluster_marker.$G.json" 2>/dev/null)
pass=0; fail=0
for i in $(seq 1 "$LAPS"); do
    L0=$(date '+%Y-%m-%d %H:%M:%S')
    for r in $ROWS; do
        ./run.sh "$CFG" --group "$G" "$r" 2>&1 | grep -aE "(PASS|FAIL|SKIP|UNKNOWN)  $r" | cut -c1-80
        D=$(ls -dt tests/evidence/board_*"${G}_$r" 2>/dev/null | head -1)
        res=$(grep -aE '^RESULT' "$D/row.log" 2>/dev/null | tail -1)
        echo "lap $i $r: ${res:0:260}"
        case "$res" in "RESULT: PASS"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); grep -a '  FAIL' "$D/row.log" 2>/dev/null | head -6 | cut -c1-220 ;; esac
    done
    lk=""
    for n in $NODES; do
        lk="$lk $n=$(timeout 40 tools/mxfs_sshpass.sh "$n" "journalctl -k --since '$L0' --no-pager | grep -c 'P-LKWAIT-LIVE'" 2>/dev/null | tail -1)"
    done
    echo "lap $i lkwait_live:$lk"
done
echo "LAPS_DONE config=$CFG rows_pass=$pass rows_fail=$fail"
[ "$fail" = 0 ]
