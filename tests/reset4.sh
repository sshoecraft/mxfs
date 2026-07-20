#!/bin/bash
# Fast 4-node cluster reset+mount using the criteria-lib helpers.
# Usage: tests/reset4.sh [N]   (default 4 nodes: test1..testN)
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/criteria/lib.sh"
N=${1:-4}
# sess46: MXFS_HOST_OFFSET skips broken nodes — e.g. =1 uses test2..test(N+1)
# (skip a write-wedged test1).  Default 0 = test1..testN, unchanged.  Pair with
# the same MXFS_HOST_OFFSET on run_tests (tests/lib/cluster.sh get_node_hostname).
NODES=("${DEFAULT_NODES[@]:${MXFS_HOST_OFFSET:-0}:$N}")
export MXFS_NODE_OFFSET=16
echo "teardown ${NODES[*]} ..."
teardown_all "${NODES[*]}"
echo "fresh mount ..."
NODE0="${NODES[0]}"; REST=("${NODES[@]:1}")
if fresh_cluster_mount "$NODE0" "${REST[@]}"; then
    echo "RESET_OK: ${#NODES[@]} nodes mounted"
else
    echo "RESET_FAIL"; exit 1
fi
