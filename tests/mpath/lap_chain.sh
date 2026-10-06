#!/bin/bash
# tests/mpath/lap_chain.sh — run path-row laps (or one host row directly) on a
# rig group as ONE plain command, so a launch never needs an inline
# environment assignment, a sleep, a `cd` or a backgrounded subshell typed at
# the prompt (each of those stops an unattended session on an approval
# prompt).  Everything a launch varies is an argument.
#
#   tests/mpath/lap_chain.sh laps <config> <group> <tag> <count> [options]
#       --prep            MXFS_FORCE_PREP=1 ./run.sh <config> --group <group>
#                         prep_cluster first (needed after a rebuild)
#       --delay <s>       wait <s> seconds before starting (stagger groups)
#       --knobs "<k=v> …" test-only module parameters every path row sets
#                         (PF_KNOBS)
#       --rows <csv>      rows of a lap (default: every path row, then
#                         alloc_witness and chk_clean)
#       --sampler <node>  run tests/mpath/load_sampler.sh on <node> beside
#                         each lap (starts 60 s in, 2100 s long)
#     Lap i is tests/board_4node_chain.sh <tag><a,b,c…> <config>:<rows>@<group>,
#     its log tests/evidence/chain_<tag><letter>.log.  Every row keeps its
#     kernel logs (PF_KEEP_KMSG=1).
#
#   tests/mpath/lap_chain.sh row <config> <group> <run_id> <script> --budget <s> [--knobs …]
#     runs a host row script (e.g. tests/mpath/fenced_takeover_stop.sh)
#     directly on the group's prepared cluster, its node list read from
#     .cluster_marker.<group>.json; log tests/evidence/<script>_<run_id>.log.
#
# Prints one line per step: prep_rc=, <tag><letter>_rc=, row_rc= and the
# row's RESULT line.
set -u
cd "$(dirname "$0")/../.." || exit 2
mode=${1:?mode: laps|row}; shift

marker_nodes() {  # <group> -> node list csv from the group's cluster marker
    python3 -c "import json,sys; print(json.load(open('.cluster_marker.$1.json'))['node_list'])"
}

case "$mode" in
laps)
    config=${1:?config}; group=${2:?group}; tag=${3:?tag}; count=${4:?count}; shift 4
    prep=0; delay=0; knobs=""; sampler=""
    rows=path_failover,path_fabric,path_flap,path_mount_degraded,path_fence_degraded,path_fenced_return,path_all_lost,path_peer_withdrawn,alloc_witness,chk_clean
    while [ $# -gt 0 ]; do
        case "$1" in
        --prep) prep=1; shift ;;
        --delay) delay=$2; shift 2 ;;
        --knobs) knobs=$2; shift 2 ;;
        --rows) rows=$2; shift 2 ;;
        --sampler) sampler=$2; shift 2 ;;
        *) echo "unknown option $1"; exit 2 ;;
        esac
    done
    [ "$delay" -gt 0 ] && sleep "$delay"
    export PF_KEEP_KMSG=1
    [ -n "$knobs" ] && export PF_KNOBS="$knobs"
    if [ "$prep" = 1 ]; then
        MXFS_FORCE_PREP=1 ./run.sh "$config" --group "$group" prep_cluster \
            > "tests/evidence/prep_${tag}_${group}.log" 2>&1
        rc=$?; echo "prep_rc=$rc"
        [ "$rc" = 0 ] || exit "$rc"
    fi
    letters=abcdefghijklmnopqrstuvwxyz
    for ((i = 0; i < count; i++)); do
        l=${letters:i:1}
        spid=""
        if [ -n "$sampler" ]; then
            ( sleep 60; tests/mpath/load_sampler.sh "$sampler" 2100 \
                "tests/evidence/load_sampler_${tag}${l}_${sampler}.txt" ) &
            spid=$!
        fi
        tests/board_4node_chain.sh "$tag$l" "$config:$rows@$group" \
            > "tests/evidence/chain_$tag$l.log" 2>&1
        echo "$tag${l}_rc=$?"
        [ -n "$spid" ] && wait "$spid"
    done
    ;;
row)
    config=${1:?config}; group=${2:?group}; run=${3:?run_id}; script=${4:?script}; shift 4
    knobs=""; budget=""
    while [ $# -gt 0 ]; do
        case "$1" in
        --knobs) knobs=$2; shift 2 ;;
        --budget) budget=$2; shift 2 ;;   # the row's derived wall bound, s
        *) echo "unknown option $1"; exit 2 ;;
        esac
    done
    [ -n "$budget" ] || { echo "row_rc=2 --budget <s> is required: the row's derived wall bound"; exit 2; }
    nodes=$(marker_nodes "$group") || { echo "row_rc=2 no marker for $group"; exit 2; }
    n=$(tr ',' '\n' <<<"$nodes" | grep -c .)
    [ -n "$knobs" ] && export PF_KNOBS="$knobs"
    log="tests/evidence/$(basename "$script" .sh)_$run.log"
    MXFS_NODES=$n MXFS_NODE_LIST=$nodes MXFS_CONFIG=$config MXFS_RUN_ID=$run \
        timeout "$budget" "$script" > "$log" 2>&1
    rc=$?; echo "row_rc=$rc"
    grep -a '^RESULT' "$log" | cut -c1-300
    exit "$rc"
    ;;
*) echo "mode: laps|row"; exit 2 ;;
esac
