#!/bin/bash
# MXFS Test Framework — mxfs_test.sh
# Per-node test executor. Runs ON each test node (via SSH from orchestrator).
#
# Usage:
#   mxfs_test.sh --test TEST_NAME --node-id N --total-nodes N --mount /mnt/shared [--phase PHASE]
#
# Environment set for the test script:
#   NODE_ID        — this node's ID (1-based)
#   TOTAL_NODES    — number of nodes in this test run
#   MOUNT_POINT    — shared filesystem mount point
#   DEVICE         — block device
#   TEST_DIR       — working directory for this test ($MOUNT_POINT/.mxfs_test)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- Parse arguments ----------
TEST_NAME=""
NODE_ID=""
TOTAL_NODES=""
MOUNT_POINT="/mnt/shared"
DEVICE="/dev/sdb"
PHASE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --test)       TEST_NAME="$2"; shift 2 ;;
        --node-id)    NODE_ID="$2"; shift 2 ;;
        --total-nodes) TOTAL_NODES="$2"; shift 2 ;;
        --mount)      MOUNT_POINT="$2"; shift 2 ;;
        --device)     DEVICE="$2"; shift 2 ;;
        --phase)      PHASE="$2"; shift 2 ;;
        --no-color)   export MXFS_NO_COLOR=1; shift ;;
        --debug)      export MXFS_DEBUG=1; shift ;;
        *)            echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$TEST_NAME" ] || [ -z "$NODE_ID" ] || [ -z "$TOTAL_NODES" ]; then
    echo "Usage: mxfs_test.sh --test NAME --node-id N --total-nodes N [--mount PATH]" >&2
    exit 1
fi

# ---------- Export environment for test scripts ----------
export NODE_ID TOTAL_NODES MOUNT_POINT DEVICE
export TEST_DIR="${MOUNT_POINT}/.mxfs_test"
export RESULTS_DIR="${MOUNT_POINT}/.mxfs_results/node${NODE_ID}"

# ---------- Source common library ----------
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/cluster.sh"

# ---------- Prepare results directory ----------
mkdir -p "$RESULTS_DIR" 2>/dev/null

# ---------- Find and run the test script ----------
find_test_script() {
    local name="$1"
    # Search in phase directory first if specified
    if [ -n "$PHASE" ] && [ -f "${SCRIPT_DIR}/${PHASE}/${name}.sh" ]; then
        echo "${SCRIPT_DIR}/${PHASE}/${name}.sh"
        return 0
    fi
    # Search all phase directories
    for dir in single cluster stress; do
        if [ -f "${SCRIPT_DIR}/${dir}/${name}.sh" ]; then
            echo "${SCRIPT_DIR}/${dir}/${name}.sh"
            return 0
        fi
    done
    return 1
}

test_script=$(find_test_script "$TEST_NAME") || {
    echo "ERROR: Test script not found: ${TEST_NAME}" >&2
    write_result "$TEST_NAME" "ERROR" "Script not found"
    exit 1
}

log_info "Node ${NODE_ID}/${TOTAL_NODES}: running ${TEST_NAME}"

# Run the test
rc=0
source "$test_script" || rc=$?

# Write result based on exit code
case $rc in
    0) write_result "$TEST_NAME" "PASS" ;;
    2) write_result "$TEST_NAME" "SKIP" ;;
    *) write_result "$TEST_NAME" "FAIL" "exit_code=$rc" ;;
esac

exit $rc
