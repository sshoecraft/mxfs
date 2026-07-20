#!/bin/bash
# diag_vnop_profile.sh — RULE 4 step 2 (continued) for the scaling_curve
# multi-node penalty.  Profiles the VFS entry points (xfs_vn_*) on every
# node over the scaling_curve rsync workload via the ftrace function
# profiler.  These functions run only in the calling task's syscall
# context, so their per-op totals attribute the wall gap to a syscall
# class without strace's ~5x ptrace overhead.
#
# Usage: scripts/diag_vnop_profile.sh [NODES...]   (default test1 test2)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || NODES=(test1 test2)
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diagvn.$$
mkdir -p "$OUT"

TRACEFS=/sys/kernel/debug/tracing
# Override the profiled function set with MXFS_PROF_FUNCS (newline-separated,
# supports ftrace globs like 'mxfs_*') to drill below the vnop layer.
FUNCS="${MXFS_PROF_FUNCS:-xfs_vn_setattr
xfs_vn_rename
xfs_vn_lookup
xfs_vn_mkdir
xfs_vn_create
xfs_generic_create
xfs_vn_getattr
xfs_file_write_iter
xfs_file_fsync
xfs_file_open
xfs_dir_open
xfs_file_release
xfs_readdir}"

stamp "=== teardown + fresh ${#NODES[@]}-node cluster ==="
teardown_all "${NODES[*]}"
fresh_cluster_mount "${NODES[@]}" || { echo "MOUNT FAIL"; exit 1; }

# Optional runtime module-param overrides, applied on every node after
# mount.  MXFS_SET_PARAMS is a space-separated list of name=value pairs
# written to /sys/module/mxfs/parameters/<name> (0644 params only).
if [ -n "${MXFS_SET_PARAMS:-}" ]; then
    for h in "${NODES[@]}"; do
        for kv in $MXFS_SET_PARAMS; do
            ssh_node "$h" "echo ${kv#*=} > /sys/module/mxfs/parameters/${kv%%=*} && echo \"$h ${kv%%=*}=\$(cat /sys/module/mxfs/parameters/${kv%%=*})\""
        done
    done
fi

for h in "${NODES[@]}"; do
    ssh_node "$h" "
        echo 0 > $TRACEFS/function_profile_enabled 2>/dev/null
        # sess28: after rmmod/insmod a still-active tracer makes filter
        # writes fail silently — reset it first.
        echo nop > $TRACEFS/current_tracer 2>/dev/null
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
            rsync -a --no-i-r --max-size=64k $SRC/ $MXFS_MOUNT/scale/n${id}/ >/dev/null 2>&1
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
echo "=== vnop profile (summed across CPUs; time in ms) ==="
for h in "${NODES[@]}"; do
    echo "--- $h ---"
    awk 'NR>2 && $1 ~ /^[a-z]/ { cnt[$1]+=$2; t[$1]+=$3 } END { for (f in cnt) printf "%-28s calls=%-8d total_ms=%.1f avg_us=%.0f\n", f, cnt[f], t[f]/1000, (cnt[f]?t[f]/cnt[f]:0) }' "$OUT/$h.prof" | sort -t= -k3 -rn
done
echo
echo "raw data: $OUT"
