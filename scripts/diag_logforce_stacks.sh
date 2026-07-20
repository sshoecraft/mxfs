#!/bin/bash
# diag_logforce_stacks.sh — RULE 4 instrumentation for the scaling_curve
# residual: aggregate the call stacks of a target function (default
# xfs_log_force) on every node during the 2-node parallel rsync workload.
# Uses the ftrace function tracer with func_stack_trace, then collapses
# identical stacks and prints them by frequency.
#
# Usage: scripts/diag_logforce_stacks.sh [NODES...]   (default test1 test2)
# Env:   MXFS_STACK_FUNC=<func>     function to trace (default xfs_log_force)
#        MXFS_SET_PARAMS="k=v ..."  module params to set post-mount
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || NODES=(test1 test2)
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diaglf.$$
mkdir -p "$OUT"
FUNC="${MXFS_STACK_FUNC:-xfs_log_force}"
TRACEFS=/sys/kernel/debug/tracing

stamp "=== teardown + fresh ${#NODES[@]}-node cluster ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "${NODES[@]}" || { echo "MOUNT FAIL"; exit 1; }

if [ -n "${MXFS_SET_PARAMS:-}" ]; then
    for h in "${NODES[@]}"; do
        for kv in $MXFS_SET_PARAMS; do
            ssh_node "$h" "echo ${kv#*=} > /sys/module/mxfs/parameters/${kv%%=*} && echo \"$h ${kv%%=*}=\$(cat /sys/module/mxfs/parameters/${kv%%=*})\""
        done
    done
fi

for h in "${NODES[@]}"; do
    ssh_node "$h" "
        echo 0 > $TRACEFS/tracing_on
        echo nop > $TRACEFS/current_tracer
        echo > $TRACEFS/trace
        echo $FUNC > $TRACEFS/set_ftrace_filter
        echo function > $TRACEFS/current_tracer
        echo 1 > $TRACEFS/options/func_stack_trace
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
        echo 0 > $TRACEFS/options/func_stack_trace
        cat $TRACEFS/trace
        echo nop > $TRACEFS/current_tracer
        echo > $TRACEFS/set_ftrace_filter
    " > "$OUT/$h.trace" 2>/dev/null
done

echo
echo "=== per-node wall ==="
for h in "${NODES[@]}"; do echo "$h: $(cat "$OUT/$h.ms")"; done
echo
echo "=== $FUNC caller stacks by frequency (top 15 per node) ==="
for h in "${NODES[@]}"; do
    echo "--- $h (total events: $(grep -c "$FUNC" "$OUT/$h.trace")) ---"
    awk '
        /<stack trace>/ { instack=1; stack=""; next }
        instack && /=>/ {
            gsub(/^.*=> /, ""); sub(/\+0x.*/, "")
            stack = stack (stack ? "<-" : "") $0
            depth++
            if (depth >= 6) { count[stack]++; instack=0; depth=0 }
            next
        }
        instack { if (stack) count[stack]++; instack=0; depth=0 }
    ' "$OUT/$h.trace" | true
    awk '
        /<stack trace>/ { if (stack) count[stack]++; instack=1; stack=""; depth=0; next }
        instack && /=>/ {
            line=$0; gsub(/^.*=> /, "", line); sub(/\+0x.*/, "", line)
            if (depth < 7) stack = stack (stack ? " <- " : "") line
            depth++
            next
        }
        instack && !/=>/ { if (stack) count[stack]++; instack=0; stack="" }
        END { if (stack) count[stack]++
              for (s in count) printf "%8d  %s\n", count[s], s }
    ' "$OUT/$h.trace" | sort -rn | head -15
done
echo
echo "raw data: $OUT"
