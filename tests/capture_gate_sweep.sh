#!/bin/bash
# tests/capture_gate_sweep.sh — one healthy lap of the capture-contract gate
# per invocation, and the fleet restore between laps, each bounded so that a
# driver (a person or a delegated runner) issues one call per step and never
# waits on anything longer than the manifest's own bound.
#
# The gate (tests/capture_fault_gate.sh) runs a manifest's entries inside a
# single process; a chunk of entries whose bounds sum past the tool's 600 s
# cap cannot be driven that way, and a kill-arm or shutdown-producing
# harness leaves the fleet in a state the NEXT entry would ABORT on
# ("mounted but not writable", s58h).  So this runs ONE entry through the
# gate with --only, bounded by that entry's healthy timeout plus the gate's
# own overhead, then reports each node's mount and writability so the
# driver knows whether a restore is due before the next lap.
#
#   tests/capture_gate_sweep.sh lap    <label> <harness>   one healthy lap; prints
#                                                          the GATE/RESULT lines and
#                                                          FLEET node=.. mounted=.. writable=..
#   tests/capture_gate_sweep.sh fleet  <label> <tag>       the FLEET lines only
#   tests/capture_gate_sweep.sh ensure <label> <tag>       wait (<= 180 s) for both
#                                                          nodes' ssh, then prep_cluster
#                                                          ONCE if either node is not
#                                                          mounted-and-writable
#
# Evidence: tests/evidence/gate_<label>/<harness>.log (the gate's own output;
# the lap's evidence directory is named in its RESULT line),
# tests/evidence/gate_<label>/ensure_<tag>.log for a restore.
# Exit: lap -> the gate's status (0 OK, 1 BROKEN, 124 the bound); ensure ->
# 0 restored or nothing to do, 1 prep failed or a node never answered.
set -u
MODE=${1:?lap|fleet|ensure}; LABEL=${2:?label}; ARG=${3:?harness or tag}
cd "$(dirname "$0")/.." || exit 2
MANIFEST=${MANIFEST:-tests/capture_gate.manifest}
NODES=${NODES:-"test1 test2"}
OUT=tests/evidence/gate_$LABEL; mkdir -p "$OUT"

# each node's mount and a real write through it: a filesystem that has shut
# down is still listed in /proc/mounts, and the next lap would ABORT on it
fleet() {
    local n m w
    for n in $NODES; do
        m=$(timeout 15 tools/mxfs_sshpass.sh "$n" "grep -c ' /mnt/shared mxfs ' /proc/mounts" 2>/dev/null | grep -a '^[0-9]' | tail -1)
        w=0
        [ "${m:-0}" = 1 ] && w=$(timeout 20 tools/mxfs_sshpass.sh "$n" "f=/mnt/shared/.sweep_probe_$n; ( : > \$f && rm -f \$f ) 2>/dev/null && echo 1 || echo 0" 2>/dev/null | grep -a '^[01]$' | tail -1)
        echo "FLEET node=$n mounted=${m:-none} writable=${w:-0}"
    done
}

case $MODE in
lap)
    h=$ARG
    th=$(grep -a "^$h *|" "$MANIFEST" | head -1 | cut -d'|' -f3 | tr -d ' ')
    tf=$(grep -a "^$h *|" "$MANIFEST" | head -1 | cut -d'|' -f2 | tr -d ' ')
    [ -n "$th" ] || th=$tf
    case $th in ''|*[!0-9]*) echo "ABORT: no healthy bound for $h in $MANIFEST"; exit 2 ;; esac
    s=$(date +%s)
    timeout $((th + 30)) tests/capture_fault_gate.sh "$LABEL-$h" --healthy-only --only "$h" > "$OUT/$h.log" 2>&1
    rc=$?
    echo "LAP $h rc=$rc wall=$(( $(date +%s) - s ))s bound=${th}s log=$OUT/$h.log"
    grep -a '^GATE \|^RESULT\|^      ' "$OUT/$h.log" | cut -c1-400
    fleet
    exit $rc ;;
fleet)
    fleet ;;
ensure)
    tag=$ARG; log=$OUT/ensure_$tag.log
    for n in $NODES; do
        up=0
        for i in $(seq 1 18); do
            timeout 10 tools/mxfs_sshpass.sh "$n" "uptime" > /dev/null 2>&1 && { up=1; break; }
            sleep 10
        done
        [ "$up" = 1 ] || { echo "ENSURE $tag: $n never answered ssh in 180 s"; exit 1; }
    done
    st=$(fleet)
    echo "$st"
    if echo "$st" | grep -qa 'mounted=[^1]\|writable=0'; then
        s=$(date +%s)
        timeout 240 env MXFS_FORCE_PREP=1 ./run.sh 2 tcp prep_cluster > "$log" 2>&1
        rc=$?
        echo "ENSURE $tag: prep_cluster rc=$rc wall=$(( $(date +%s) - s ))s log=$log"
        grep -a 'PREP FAIL\|ABORT\|NODE_PREP_OK\|srcversion' "$log" | tail -4 | cut -c1-200
        fleet
        exit $rc
    fi
    echo "ENSURE $tag: nothing to do"
    exit 0 ;;
*)  echo "usage: $0 lap|fleet|ensure <label> <harness|tag>"; exit 2 ;;
esac
