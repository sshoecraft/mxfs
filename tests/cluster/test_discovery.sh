#!/bin/bash
# Cluster test: verify UDP discovery finds all peers
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "discovery"

ts_disc=$(time_op)

# Wait for discovery to stabilize
sleep 3

# Verify mount is functional (basic smoke test that discovery led to working cluster)
ls "$MOUNT_POINT" > /dev/null 2>&1
assert_zero "$?" "Can list mount point after discovery"

# Authoritative, transport-agnostic peer-discovery check.
#
# The previous implementation grepped dmesg for "peer discovered" strings
# that MXFS never emits (the CAW disk transport announces nothing matching
# that pattern, and the UDP discovery messages are DEBUG-level) — so the
# peer count was always 0 and the assertion always failed, regardless of
# whether discovery actually worked.  Instead, prove discovery directly:
# every node publishes a marker into a shared dir, and every node must then
# see all TOTAL_NODES markers.  A node only sees its peers' markers if
# discovery + cluster membership + cross-node coherency are all working.
mkdir -p "$MOUNT_POINT/.mxfs_test/discovery" 2>/dev/null
touch "$MOUNT_POINT/.mxfs_test/discovery/node${NODE_ID}_ok"

# Barrier: every node has published its marker
barrier_signal "discovery_done"
barrier_wait "discovery_done" "$TOTAL_NODES"

if [ "$TOTAL_NODES" -eq 1 ]; then
    assert_true "Single node, no peer discovery needed"
else
    # Each node independently verifies it can see all peers' markers.
    marker_count=$(ls "$MOUNT_POINT/.mxfs_test/discovery"/node*_ok 2>/dev/null | wc -l)
    marker_count=$(echo "$marker_count" | tr -d ' ')
    if [ "$marker_count" -lt "$TOTAL_NODES" ]; then
        log_info "Only ${marker_count}/${TOTAL_NODES} peer markers visible, waiting 5s more..."
        sleep 5
        marker_count=$(ls "$MOUNT_POINT/.mxfs_test/discovery"/node*_ok 2>/dev/null | wc -l)
        marker_count=$(echo "$marker_count" | tr -d ' ')
    fi
    assert_equals "$TOTAL_NODES" "$marker_count" "Discovered all ${TOTAL_NODES} peers (markers visible from node ${NODE_ID})"
fi

log_timing "discover_peers" "$(time_elapsed_ms "$ts_disc")"

test_end
