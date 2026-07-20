#!/bin/bash
# Criterion: No kernel BUG/oops/panic on any documented operation.
# Verifier: drive a brief representative workload, scan dmesg on every
# node for BUG:/Oops/Call Trace/WARNING:/Kernel panic since the start
# of the run.  Threshold: 0 hits across all nodes.
#
# This is the "fail-fast" check.  Other criteria scripts can also call
# node_dmesg_dirty_count from lib.sh to fail their own runs on the same
# patterns.

set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"
result_init "dmesg_clean"
set_script_timeout 120

parse_common_args "$@"
[ "${#NODES[@]}" -gt 4 ] && NODES=("${NODES[@]:0:4}")
NODE0="${NODES[0]}"
REST=("${NODES[@]:1}")

teardown_all "${NODES[*]}"

# Stamp a marker into dmesg on each node so we can scope the scan to
# the workload window only.
MARKER="MXFS_DMESG_CRITERION_$(date +%s)_$$"
parallel_ssh_quiet "${NODES[*]}" "echo '$MARKER' > /dev/kmsg 2>/dev/null"

fresh_cluster_mount "$NODE0" "${REST[@]}" \
    || result_fail "n/a" "0-hits" "cluster mount failed"

# Representative workload: parallel mkdir + touch + write + unlink storm
ssh_node_quiet "$NODE0" "rm -rf $MXFS_MOUNT/dmesg_test; mkdir -p $MXFS_MOUNT/dmesg_test; touch $MXFS_MOUNT/dmesg_test/.go; sync"
wl_pids=()
for i in "${!NODES[@]}"; do
    NODE_ID=$((i + 1))
    HOST="${NODES[$i]}"
    ( ssh_node_quiet "$HOST" "
        for try in \$(seq 1 60); do [ -e $MXFS_MOUNT/dmesg_test/.go ] && break; sleep 0.5; done
        D=$MXFS_MOUNT/dmesg_test/n${NODE_ID}
        mkdir -p \$D
        for k in \$(seq 1 50); do
            mkdir \$D/d\$k 2>/dev/null
            echo data > \$D/f\$k
        done
        sync
        for k in \$(seq 1 50); do
            rm -f \$D/f\$k
            rmdir \$D/d\$k 2>/dev/null
        done
        sync
    " ) &
    wl_pids+=($!)
done
for p in "${wl_pids[@]}"; do wait "$p" 2>/dev/null; done

# Clean umount — parallel so 4 nodes don't serialise the 60s per-SSH timeout
parallel_ssh_quiet "${NODES[*]}" "umount $MXFS_MOUNT 2>/dev/null; rmmod mxfs 2>/dev/null"

# Scan dmesg on each node from the marker forward — parallel
total_hits=0
dirty_nodes=""
scan_tmp=$(mktemp -d)
scan_pids=()
for n in "${NODES[@]}"; do
    ( ssh_node "$n" "
        dmesg | awk '/$MARKER/{seen=1;next} seen' \
              | grep -cE 'BUG:|Oops|Call Trace|general protection|WARNING:|Kernel panic|kernel NULL pointer'
    " | tail -1 | tr -d ' \r\n' > "$scan_tmp/${n}.hits" ) &
    scan_pids+=($!)
done
for p in "${scan_pids[@]}"; do wait "$p" 2>/dev/null; done
for n in "${NODES[@]}"; do
    hits=$(cat "$scan_tmp/${n}.hits" 2>/dev/null); hits=${hits:-0}
    if [ "$hits" -gt 0 ]; then
        dirty_nodes="$dirty_nodes ${n}=${hits}"
    fi
    total_hits=$((total_hits + hits))
done

[ "$total_hits" = "0" ] || result_fail "hits=$total_hits" "0-hits" "dirty:$dirty_nodes"
result_pass "hits=0" "0-hits"
