#!/bin/bash
# diag_logforce_profile.sh — RULE 4 step 2 for the scaling_curve
# multi-node penalty.  Hypothesis (from diag_par_rsync.sh stack
# samples): the extra ~2 s per node in any >=2-node parallel rsync is
# synchronous per-op durability work on the multi-node path —
# xfs_log_force/xlog_wait_on_iclog + AG drain at transaction free
# (mxfs_trans_drain_ag_unlocks -> mxfs_ag_dlm_unlock) and per-create
# inode-cluster barriers (mxfs_dlm_dir_inode_durable ->
# mxfs_inode_cluster_durable).
#
# Uses the ftrace function profiler on every node to get call COUNT and
# TOTAL TIME for those functions over the same parallel rsync workload
# scaling_curve.sh runs.  Compare a 1-node run vs a 2-node run.
#
# Usage: scripts/diag_logforce_profile.sh [NODES...]   (default test1 test2)
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

TRACEFS=/sys/kernel/debug/tracing
FUNCS="xfs_log_force
xlog_wait_on_iclog
xfs_buf_iowait
mxfs_ag_dlm_unlock*
mxfs_trans_drain_ag_unlocks
mxfs_dlm_ag_drain_alloc_buflist
mxfs_inode_cluster_durable
mxfs_dlm_dir_inode_durable
mxfs_dir_data_durable
mxfs_ag_dlm_lock*
mxfs_dlm_lock
mxfs_dlm_unlock"

stamp "=== teardown + fresh ${#NODES[@]}-node cluster ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "${NODES[@]}" || { echo "MOUNT FAIL"; exit 1; }

for h in "${NODES[@]}"; do
    ssh_node "$h" "
        echo 0 > $TRACEFS/function_profile_enabled 2>/dev/null
        echo > $TRACEFS/set_ftrace_filter
        while read f; do echo \"\$f\" >> $TRACEFS/set_ftrace_filter 2>/dev/null; done <<'EOF'
$FUNCS
EOF
        echo 1 > $TRACEFS/function_profile_enabled
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
        echo 0 > $TRACEFS/function_profile_enabled
        for c in $TRACEFS/trace_stat/function*; do cat \$c; done
    " > "$OUT/$h.prof" 2>/dev/null
done

echo
echo "=== per-node wall ==="
for h in "${NODES[@]}"; do echo "$h: $(cat "$OUT/$h.ms")"; done
echo
echo "=== function profile (summed across CPUs; time in us) ==="
for h in "${NODES[@]}"; do
    echo "--- $h ---"
    awk 'NR>2 && $1 ~ /^[a-z]/ { cnt[$1]+=$2; t[$1]+=$3 } END { for (f in cnt) printf "%-40s calls=%-8d total_ms=%.1f\n", f, cnt[f], t[f]/1000 }' "$OUT/$h.prof" | sort -t= -k3 -rn
done
echo
echo "raw data: $OUT"
