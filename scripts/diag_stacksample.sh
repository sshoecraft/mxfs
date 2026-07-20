#!/bin/bash
# diag_stacksample.sh — RULE 4 instrumentation: off-CPU profile of the
# scaling_curve rsync workload by sampling /proc/<pid>/stack of every
# rsync process (and optionally xfsaild + mxfs workers) at ~50 ms
# intervals on every node.  The slow node's dominant blocked-stack IS
# the stall, with no tracer setup fragility and no pre-chosen function.
#
# Usage: scripts/diag_stacksample.sh [NODES...]   (default test1 test2)
# Env:   MXFS_SET_PARAMS="k=v ..."  module params to set post-mount
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${MXFS_SSH_TIMEOUT:=600}"
source "$SCRIPT_DIR/../tests/criteria/lib.sh"
stamp() { echo "[$(date +%H:%M:%S)] $*"; }

NODES=("$@")
[ "${#NODES[@]}" -ge 1 ] || NODES=(test1 test2)
SRC=/root/open-gpu-kernel-modules
OUT=/tmp/diagss.$$
mkdir -p "$OUT"

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

ssh_node "${NODES[0]}" "rm -rf $MXFS_MOUNT/scale; mkdir -p $MXFS_MOUNT/scale; touch $MXFS_MOUNT/scale/.go; sync"

stamp "=== parallel rsync + stack sampler on ${NODES[*]} ==="
pids=()
for i in "${!NODES[@]}"; do
    h="${NODES[$i]}"
    id=$((i + 1))
    (
        ssh_node "$h" "
            rm -f /tmp/ss.out /tmp/ss.done
            (
                while [ ! -e /tmp/ss.done ]; do
                    for p in \$(pgrep -x rsync); do
                        s=\$(cat /proc/\$p/stack 2>/dev/null | tr '\n' '|')
                        [ -n \"\$s\" ] && echo \"\$s\" >> /tmp/ss.out
                    done
                    sleep 0.05
                done
            ) &
            SAMPLER=\$!
            for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/scale/.go ] && break; sleep 0.5; done
            mkdir -p $MXFS_MOUNT/scale/n${id}
            t0=\$(date +%s%N)
            rsync -a --no-i-r $SRC/ $MXFS_MOUNT/scale/n${id}/ >/dev/null 2>&1
            sync
            t1=\$(date +%s%N)
            touch /tmp/ss.done
            wait \$SAMPLER 2>/dev/null
            echo WALL_MS=\$(( (t1 - t0) / 1000000 ))
        " | tail -1 > "$OUT/$h.ms"
    ) & pids+=($!)
done
for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done

for h in "${NODES[@]}"; do
    ssh_node "$h" "cat /tmp/ss.out 2>/dev/null" > "$OUT/$h.stacks"
done

echo
echo "=== per-node wall ==="
for h in "${NODES[@]}"; do echo "$h: $(cat "$OUT/$h.ms")"; done
echo
echo "=== top blocked stacks per node (samples ~= 50ms each) ==="
for h in "${NODES[@]}"; do
    echo "--- $h (total samples: $(wc -l < "$OUT/$h.stacks")) ---"
    sed 's/+0x[0-9a-f]*\/0x[0-9a-f]*//g' "$OUT/$h.stacks" | sort | uniq -c | sort -rn | head -8
done
echo
echo "raw data: $OUT"
