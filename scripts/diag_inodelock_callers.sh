#!/bin/bash
# diag_inodelock_callers.sh — RULE 4 instrumentation for the scaling_curve
# 16-node penalty (sess28 of run 14d31183).  The ftrace function profiler
# showed mxfs_v5_dlm_inode_lock is the dominant per-node wall contributor
# at 16 nodes (~850 calls x ~2.7 ms avg, all-slow — the fast path never
# enters the function).  This script stack-traces EVERY call on one
# observer node during a full parallel rsync across all given nodes, then
# summarizes the unique caller stacks so the syscall path that still pays
# a synchronous disk-CAW per directory is named exactly.
#
# Usage: scripts/diag_inodelock_callers.sh OBSERVER [NODES...]
#        (default observer test4, default nodes test1..test16)
# Env:   MXFS_TRACE_FUNC  function to trace (default mxfs_v5_dlm_inode_lock)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

OBSERVER="${1:-test4}"
shift 2>/dev/null || true
NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || NODES=(test1 test2 test3 test4 test5 test6 test7 test8
                                   test9 test10 test11 test12 test13 test14 test15 test16)
TFUNC="${MXFS_TRACE_FUNC:-mxfs_v5_dlm_inode_lock}"
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diagilc.$$
mkdir -p "$OUT"
TRACEFS=/sys/kernel/debug/tracing

stamp "=== teardown + fresh ${#NODES[@]}-node cluster (observer $OBSERVER) ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "${NODES[@]}" || { echo "MOUNT FAIL"; exit 1; }

ssh_node "$OBSERVER" "
    echo 0 > $TRACEFS/tracing_on
    echo nop > $TRACEFS/current_tracer
    echo 20480 > $TRACEFS/buffer_size_kb
    echo $TFUNC > $TRACEFS/set_ftrace_filter
    echo function > $TRACEFS/current_tracer
    echo 1 > $TRACEFS/options/func_stack_trace
    echo > $TRACEFS/trace
    echo 1 > $TRACEFS/tracing_on
"

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

ssh_node "$OBSERVER" "
    echo 0 > $TRACEFS/tracing_on
    echo 0 > $TRACEFS/options/func_stack_trace
    echo nop > $TRACEFS/current_tracer
    echo > $TRACEFS/set_ftrace_filter
    cat $TRACEFS/trace
" > "$OUT/trace" 2>/dev/null

echo
echo "=== per-node wall ==="
for h in "${NODES[@]}"; do echo "$h: $(cat "$OUT/$h.ms")"; done
echo
echo "=== $TFUNC call count on $OBSERVER ==="
grep -c ": $TFUNC" "$OUT/trace" 2>/dev/null
echo
echo "=== unique caller stacks (top frames after the traced fn) ==="
# Each event: a line with the fn, then '<stack trace>' block of ' => frame'
awk '
    /<stack trace>/ { instack=1; sig=""; depth=0; next }
    instack && /=>/ {
        gsub(/^.*=> /, ""); gsub(/\+0x[0-9a-f\/x]+/, "");
        if (depth < 7) sig = sig "|" $0
        depth++
        next
    }
    instack { if (sig != "") count[sig]++; instack=0 }
    END { for (s in count) printf "%6d  %s\n", count[s], s }
' "$OUT/trace" | sort -rn | head -25
echo
echo "raw data: $OUT"
