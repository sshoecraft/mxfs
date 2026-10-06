#!/bin/bash
#
# ag_phantom_laps.sh — laps of the stranded-AG repair row on a net/mesh
# cluster, counting what the repair leaves behind on each node.
#
# Measured on 8/net/mesh/mpath (0.90.48): after ag_strand_repair one node kept
# a cached hint for an AG whose grant it had released, and 38 s later allocated
# data blocks there beside the AG's real holder (13 acknowledged files held
# another file's data).  The row itself passed.  This drives that row
# repeatedly and reads, per node and per lap, the module's own totals:
#
#   ag_cached_phantom_total   cached AG hints found with no grant behind them
#                             (dropped at the next acquire; each one is a hint
#                             the node would otherwise have allocated from)
#   ag_unlock_rearm_total     AG releases that ended "still held" and re-armed
#   ag_release_dup_total      runs of the release function that found the
#                             committed release already owned by another runner
#   ag_release_nogrant_total  finishers that reached the wire unlock with no
#                             grant of the node's in its table
#
# The totals are module parameters, so they survive the kernel log rotating
# (a node's log holds about two minutes under this load).  A lap is the row
# twice: the second burst is what reaches into the AGs the first one's
# repairs touched.
#
# Usage: [DELAY=<ms>] tests/ag_phantom_laps.sh CONFIG GROUP LAPS LABEL
#   e.g. tests/ag_phantom_laps.sh 8/net/mesh/direct g8 10 b1
#   ROW    the suite row to lap (default ag_strand_repair).  The release
#          function gains extra runners from threads on the slow inode-lock
#          road, which the path rows' create/remove load takes constantly and
#          the strand row's mkdir burst does not: ROW=path_failover on an
#          mpath configuration is the load the corruption was measured under
#   TWIN   sets the test-only ag_release_twin on every node before each row
#   DELAY  sets the test-only ag_prepass_delay_ms on every node before each
#          row, so the release function's runners overlap on every release
# Output: tests/evidence/ag_phantom_laps_<LABEL>_<group>.out, last line
#   AG_PHANTOM_LAPS_DONE laps=<n> phantom=<sum> rearm=<sum> dup=<sum> nogrant=<sum> row_fail=<n>
#
# run.sh enforces each row's own budget; nothing here wraps it in a timeout.
#
set -u
CFG="${1:?usage: tests/ag_phantom_laps.sh CONFIG GROUP LAPS LABEL}"
GROUP="${2:?group}"
LAPS="${3:?laps}"
LABEL="${4:?label}"
ROW="${ROW:-ag_strand_repair}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE" || exit 1
O="tests/evidence/ag_phantom_laps_${LABEL}_${GROUP}.out"
NODES=$(tools/mxfs_lab.sh group "$GROUP")
: > "$O"
echo "=== $(date -u +%FT%TZ) ag_phantom_laps cfg=$CFG group=$GROUP laps=$LAPS row=$ROW delay=${DELAY:-0} srcversion=$(modinfo -F srcversion mxfs.ko) nodes=[$NODES] ===" >> "$O"
scripts/lab_power.sh up "group:$GROUP" >> "$O" 2>&1
./run.sh "$CFG" --group "$GROUP" prep_cluster >> "$O" 2>&1
echo "PREP_RC $?" >> "$O"
read_totals() {  # <tag>: one line per node, then the sums
    local n d tp=0 tr=0 td=0 tg=0 p r du ng
    d=$(mktemp -d)
    for n in $NODES; do
        ( timeout 20 tools/mxfs_sshpass.sh "$n" 'echo "$(cat /sys/module/mxfs/parameters/ag_cached_phantom_total 2>/dev/null || echo x) $(cat /sys/module/mxfs/parameters/ag_unlock_rearm_total 2>/dev/null || echo x) $(cat /sys/module/mxfs/parameters/ag_release_dup_total 2>/dev/null || echo x) $(cat /sys/module/mxfs/parameters/ag_release_nogrant_total 2>/dev/null || echo x) $(cat /sys/module/mxfs/srcversion 2>/dev/null) $(grep -c " mxfs " /proc/mounts)"' > "$d/$n" 2>/dev/null; echo "rc=$?" >> "$d/$n" ) &
    done
    wait
    for n in $NODES; do
        p=$(sed -n 1p "$d/$n" | cut -d' ' -f1); r=$(sed -n 1p "$d/$n" | cut -d' ' -f2)
        du=$(sed -n 1p "$d/$n" | cut -d' ' -f3); ng=$(sed -n 1p "$d/$n" | cut -d' ' -f4)
        echo "TOTALS $1 $n phantom=$p rearm=$r dup=$du nogrant=$ng $(sed -n 1p "$d/$n" | cut -d' ' -f5-) $(tail -1 "$d/$n")" >> "$O"
        case "$p" in ''|x|*[!0-9]*) ;; *) tp=$((tp + p));; esac
        case "$r" in ''|x|*[!0-9]*) ;; *) tr=$((tr + r));; esac
        case "$du" in ''|x|*[!0-9]*) ;; *) td=$((td + du));; esac
        case "$ng" in ''|x|*[!0-9]*) ;; *) tg=$((tg + ng));; esac
    done
    echo "SUM $1 phantom=$tp rearm=$tr dup=$td nogrant=$tg" >> "$O"
    SUM_P=$tp; SUM_R=$tr; SUM_D=$td; SUM_G=$tg
}
fail=0
SUM_P=0; SUM_R=0; SUM_D=0; SUM_G=0
for i in $(seq 1 "$LAPS"); do
    for half in a b; do
        # DELAY=<ms>: hold every release runner between its pre-COMMIT pass
        # and the COMMIT decision (set again before each row: the row's own
        # prep may reload the module, which resets it)
        # TWIN=1: the test-only ag_release_twin, a second runner beside the
        # queued worker whenever a slow inode-lock acquire comes by
        if [ -n "${TWIN:-}" ]; then
            for n in $NODES; do ( timeout 20 tools/mxfs_sshpass.sh "$n" "echo $TWIN > /sys/module/mxfs/parameters/ag_release_twin" >/dev/null 2>&1 ) & done; wait
        fi
        if [ -n "${DELAY:-}" ]; then
            for n in $NODES; do ( timeout 20 tools/mxfs_sshpass.sh "$n" "echo $DELAY > /sys/module/mxfs/parameters/ag_prepass_delay_ms" >/dev/null 2>&1 ) & done; wait
        fi
        ./run.sh "$CFG" --group "$GROUP" "$ROW" > "tests/evidence/ag_phantom_laps_${LABEL}_${GROUP}_lap${i}${half}.log" 2>&1
        rc=$?
        v=$(grep -a "^  \(PASS\|FAIL\)  $ROW" "tests/evidence/ag_phantom_laps_${LABEL}_${GROUP}_lap${i}${half}.log" | head -1 | cut -c1-200)
        echo "LAP $i$half $(date -u +%FT%TZ) rc=$rc $v" >> "$O"
        case "$v" in *PASS*) ;; *) fail=$((fail + 1));; esac
    done
    read_totals "lap$i"
done
echo "AG_PHANTOM_LAPS_DONE laps=$LAPS phantom=$SUM_P rearm=$SUM_R dup=$SUM_D nogrant=$SUM_G row_fail=$fail" >> "$O"
