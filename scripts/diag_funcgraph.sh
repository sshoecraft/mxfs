#!/bin/bash
# diag_funcgraph.sh — RULE 4 instrumentation: function_graph trace of a
# target function (+children) during the multi-node parallel rsync
# workload, filtered to invocations slower than a duration threshold.
# Shows WHERE inside a slow call the time goes (which child blocked).
#
# Usage: scripts/diag_funcgraph.sh [NODES...]   (default test1 test2)
# Env:   MXFS_GRAPH_FUNC='fn1 fn2'   set_graph_function list
#                                    (default both ag drain variants)
#        MXFS_GRAPH_THRESH_US=N      only log calls slower than this
#                                    (default 100000 = 100ms)
#        MXFS_GRAPH_DEPTH=N          max_graph_depth (default 6)
#        MXFS_SET_PARAMS="k=v ..."   module params to set post-mount
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || NODES=(test1 test2)
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diagfg.$$
mkdir -p "$OUT"
GFUNCS="${MXFS_GRAPH_FUNC:-mxfs_dlm_ag_drain_alloc_buflist*}"
THRESH="${MXFS_GRAPH_THRESH_US:-100000}"
DEPTH="${MXFS_GRAPH_DEPTH:-6}"
TRACEFS=/sys/kernel/debug/tracing

stamp "=== teardown + fresh ${#NODES[@]}-node cluster ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "${NODES[@]}" || { echo "MOUNT FAIL"; exit 1; }

if [ -n "${MXFS_SET_PARAMS:-}" ]; then
    for h in "${NODES[@]}"; do
        for kv in $MXFS_SET_PARAMS; do
            ssh_node "$h" "echo ${kv#*=} > /sys/module/mxfs/parameters/${kv%%=*}"
        done
    done
fi

for h in "${NODES[@]}"; do
    ssh_node "$h" "
        echo 0 > $TRACEFS/tracing_on
        echo nop > $TRACEFS/current_tracer
        echo > $TRACEFS/trace
        echo > $TRACEFS/set_graph_function
        for f in $GFUNCS; do echo \"\$f\" >> $TRACEFS/set_graph_function; done
        echo $DEPTH > $TRACEFS/max_graph_depth
        echo $THRESH > $TRACEFS/tracing_thresh
        echo function_graph > $TRACEFS/current_tracer
        echo 65536 > $TRACEFS/buffer_size_kb
        echo 1 > $TRACEFS/tracing_on
    "
done

ssh_node "${NODES[0]}" "rm -rf $MXFS_MOUNT/scale; mkdir -p $MXFS_MOUNT/scale; touch $MXFS_MOUNT/scale/.go; sync"

stamp "=== parallel rsync on ${NODES[*]} ==="
pids=()
for i in "${!NODES[@]}"; do
    h="${NODES[$i]}"
    id=$((i + 1))
    (
        ssh_node "$h" "
            for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/scale/.go ] && break; sleep 0.5; done
            mkdir -p $MXFS_MOUNT/scale/n${id}
            t0=\$(date +%s%N)
            rsync -a --no-i-r $SRC/ $MXFS_MOUNT/scale/n${id}/ >/dev/null 2>&1
            sync
            t1=\$(date +%s%N)
            echo WALL_MS=\$(( (t1 - t0) / 1000000 ))
        " | tail -1 > "$OUT/$h.ms"
    ) & pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done

for h in "${NODES[@]}"; do
    ssh_node "$h" "
        echo 0 > $TRACEFS/tracing_on
        cat $TRACEFS/trace
        echo nop > $TRACEFS/current_tracer
        echo 0 > $TRACEFS/tracing_thresh
        echo > $TRACEFS/set_graph_function
    " > "$OUT/$h.graph" 2>/dev/null
done

echo
echo "=== per-node wall ==="
for h in "${NODES[@]}"; do echo "$h: $(cat "$OUT/$h.ms")"; done
echo
echo "=== slow-call graph excerpts (first 80 trace lines per node) ==="
for h in "${NODES[@]}"; do
    echo "--- $h ($(grep -c '!' "$OUT/$h.graph" 2>/dev/null) marked-slow lines) ---"
    grep -vE "^#|^$" "$OUT/$h.graph" | head -80
done
echo
echo "raw data: $OUT"
