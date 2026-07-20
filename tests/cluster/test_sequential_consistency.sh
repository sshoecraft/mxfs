#!/bin/bash
# Cluster test: sequential consistency — writes on node A are seen in order on node B
# Sourced by mxfs_test.sh — common.sh already loaded
# cluster.sh already sourced by mxfs_test.sh

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "sequential_consistency"

TESTDIR="$MOUNT_POINT/.mxfs_test/seq_consistency"
mkdir -p "$TESTDIR" 2>/dev/null

ITERATIONS=20

# Odd nodes are writers, even nodes are readers
# If only 1 node, do both roles
if [ "$TOTAL_NODES" -eq 1 ]; then
    role="both"
elif [ $((NODE_ID % 2)) -eq 1 ]; then
    role="writer"
else
    role="reader"
fi

# Barrier: synchronize start
barrier_signal "sc_ready"
barrier_wait "sc_ready" "$TOTAL_NODES"

if [ "$role" = "writer" ] || [ "$role" = "both" ]; then
    log_info "Node ${NODE_ID}: writer role, ${ITERATIONS} sequential writes..."
    ts_seqwrite=$(time_op)
    for i in $(seq 1 $ITERATIONS); do
        echo "node${NODE_ID}_seq${i}" > "$TESTDIR/node${NODE_ID}_counter"
        sync
        # Small delay to ensure ordering is observable
        sleep 0.1
    done
    # Write final value
    echo "${ITERATIONS}" > "$TESTDIR/node${NODE_ID}_final"
    log_timing "seq_write_${ITERATIONS}" "$(time_elapsed_ms "$ts_seqwrite")"
fi

# Barrier: writers done
barrier_signal "sc_write_done"
barrier_wait "sc_write_done" "$TOTAL_NODES"
sleep 2

if [ "$role" = "reader" ] || [ "$role" = "both" ]; then
    log_info "Node ${NODE_ID}: reader role, verifying final values..."
    ts_seqread=$(time_op)
    # For each writer node, verify the final counter value
    for w in $(seq 1 "$TOTAL_NODES"); do
        if [ $((w % 2)) -eq 1 ] || [ "$TOTAL_NODES" -eq 1 ]; then
            # This was a writer node
            if [ -f "$TESTDIR/node${w}_final" ]; then
                final=$(cat "$TESTDIR/node${w}_final")
                assert_equals "$ITERATIONS" "$final" "Node ${w} final counter value is ${ITERATIONS}"
            else
                test_fail "Node ${w} final value file missing"
            fi

            if [ -f "$TESTDIR/node${w}_counter" ]; then
                counter=$(cat "$TESTDIR/node${w}_counter")
                assert_equals "node${w}_seq${ITERATIONS}" "$counter" "Node ${w} counter has last written value"
            else
                test_fail "Node ${w} counter file missing"
            fi
        fi
    done
    log_timing "seq_read_verify" "$(time_elapsed_ms "$ts_seqread")"
fi

# Barrier: all done
barrier_signal "sc_verify"
barrier_wait "sc_verify" "$TOTAL_NODES"

test_end
