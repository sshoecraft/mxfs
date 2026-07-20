#!/bin/bash
# Cluster test (DIAGNOSTIC): faithful clone of test_cross_visibility.sh that,
# on a visibility MISS, discriminates H1 (in-core stale / on-disk correct) vs
# H2 (on-disk lost-update) by dropping caches and re-checking.
#
# Phase 1 timing is IDENTICAL to test_cross_visibility (create+sync+barrier)
# so the bug-inducing concurrency is preserved.  Discrimination is added only
# AFTER a miss is detected.  Run via:
#   run_tests.sh --nodes 4 --phase cluster --test test_cv_disc ...
#
# Sourced by mxfs_test.sh — common.sh + cluster.sh already loaded.

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "cv_disc"

TESTDIR="$MOUNT_POINT/.mxfs_test/cross_visibility"
mkdir -p "$TESTDIR" 2>/dev/null

# Phase 1: Each node creates a unique file (identical to the real test)
echo "hello from node ${NODE_ID}" > "$TESTDIR/node${NODE_ID}.txt"
sync

# Barrier: wait for all nodes to finish writing
barrier_signal "cv_write_done"
barrier_wait "cv_write_done" "$TOTAL_NODES"

# Small settle time for cache invalidation
sleep 2

# Phase 2: verify visibility; on a miss, discriminate H1 vs H2
missing=0
for n in $(seq 1 "$TOTAL_NODES"); do
    F="$TESTDIR/node${n}.txt"
    if [ ! -f "$F" ]; then
        test_fail "Node ${NODE_ID} cannot see node${n}.txt"
        missing=$((missing + 1))
        # --- DISCRIMINATE ---
        # Drop local caches to force a fresh on-disk (FUA) re-read via the
        # MXFS DLM acquire+reload path, then re-check.
        sync
        echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
        sleep 1
        if [ -f "$F" ]; then
            log_info "DISC node${NODE_ID} miss node${n}.txt => H1 (in-core stale; ON-DISK PRESENT after drop_caches)"
        else
            log_info "DISC node${NODE_ID} miss node${n}.txt => H2 (ON-DISK LOST even after drop_caches)"
        fi
        # also dump what the dir actually contains now
        log_info "DISC node${NODE_ID} dir-listing: $(ls -1 "$TESTDIR" 2>/dev/null | tr '\n' ' ')"
        # sess58: the dirent may be PRESENT (ls shows it) yet stat fails =>
        # child-inode resolution miss (stale inode-cluster buffer), NOT a
        # dirent lost-update.  Capture inode numbers (ls -li, readdir-only)
        # and the exact stat error to discriminate.
        log_info "DISC node${NODE_ID} ls-li: $(ls -li "$TESTDIR" 2>/dev/null | tr '\n' '|')"
        log_info "DISC node${NODE_ID} stat-err: $(stat "$F" 2>&1 | tr '\n' ' ')"
    fi
done

# Barrier: all done verifying
barrier_signal "cv_verify_done"
barrier_wait "cv_verify_done" "$TOTAL_NODES"

test_end
