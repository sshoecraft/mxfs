#!/bin/bash
# Cluster test: verify TCP mesh connections between all node pairs
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "tcp_mesh"

# This test verifies the TCP DLM transport mesh.  MXFS forms a new cluster
# on CAW (disk-based) transport by default and only uses TCP when CAW is
# unavailable / force_transport=1 (see CLAUDE.md transport-selection rules).
# On a CAW cluster there is NO TCP DLM listener bound on port 7600 and no
# TCP peer activity — the feature under test is simply not in use, so this
# test is not applicable.  Detect that by the absence of a 7600 listener
# (a TCP-transport cluster always binds one) and SKIP rather than FAIL.
if [ "$TOTAL_NODES" -gt 1 ]; then
    tcp_listener=$(ss -tln '( sport = 7600 )' 2>/dev/null | grep -v '^State' | grep -c 7600)
    tcp_listener=$(echo "$tcp_listener" | tr -d ' ')
    if [ "${tcp_listener:-0}" -eq 0 ]; then
        test_skip "cluster is using CAW transport (no TCP DLM listener on 7600) — TCP mesh not applicable"
    fi
fi

ts_mesh=$(time_op)

# Check for established TCP connections on DLM port (7600)
dlm_connections=$(ss -tn state established '( sport = 7600 or dport = 7600 )' 2>/dev/null | grep -v '^State' | wc -l)
dlm_connections=$(echo "$dlm_connections" | tr -d ' ')

expected=$((TOTAL_NODES - 1))

if [ "$TOTAL_NODES" -eq 1 ]; then
    assert_true "Single node, no TCP mesh expected"
else
    # Give TCP connections time to establish
    if [ "$dlm_connections" -lt "$expected" ]; then
        log_info "Only ${dlm_connections}/${expected} connections, waiting 5s..."
        sleep 5
        dlm_connections=$(ss -tn state established '( sport = 7600 or dport = 7600 )' 2>/dev/null | grep -v '^State' | wc -l)
        dlm_connections=$(echo "$dlm_connections" | tr -d ' ')
    fi

    assert_ge "$dlm_connections" "$expected" "At least ${expected} TCP connections on port 7600 (found ${dlm_connections})"
fi

log_timing "verify_tcp_mesh" "$(time_elapsed_ms "$ts_mesh")"

# Also verify via dmesg that peer connections were established
if [ "$TOTAL_NODES" -gt 1 ]; then
    tcp_msgs=$(dmesg | grep -c "mxfs.*TCP\|mxfs.*peer.*connect\|mxfs.*accepted" 2>/dev/null || echo "0")
    tcp_msgs=$(echo "$tcp_msgs" | tr -d ' ')
    assert_ge "$tcp_msgs" "1" "Kernel log shows TCP peer activity"
fi

# Barrier sync
barrier_signal "tcp_mesh_done"
barrier_wait "tcp_mesh_done" "$TOTAL_NODES"

test_end
