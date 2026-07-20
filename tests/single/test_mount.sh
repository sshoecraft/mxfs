#!/bin/bash
# Single-node test: verify mxfs mounts and basic mount state is correct
# Sourced by mxfs_test.sh — common.sh already loaded

if [ -z "$NODE_ID" ]; then
    echo "ERROR: Must be run via mxfs_test.sh on a node" >&2
    exit 1
fi

test_begin "mount"

# The mount should already be done by the orchestrator.
# Verify mount point exists and is a mountpoint
assert_dir_exists "$MOUNT_POINT" "Mount point directory exists"

mountpoint -q "$MOUNT_POINT" || {
    test_fail "Not a mountpoint: $MOUNT_POINT"
    test_end
    exit 1
}

# Verify it shows as mxfs in /proc/mounts
mount_type=$(grep " ${MOUNT_POINT} " /proc/mounts | awk '{print $3}' | head -1)
assert_equals "mxfs" "$mount_type" "Filesystem type is mxfs"

# Verify we can stat the mount point
stat_out=$(stat -f "$MOUNT_POINT" 2>&1) || {
    test_fail "stat -f failed on mount point"
    test_end
    exit 1
}

# Verify df works
df_out=$(df "$MOUNT_POINT" 2>&1) || {
    test_fail "df failed on mount point"
    test_end
    exit 1
}

# Verify the device matches
mount_dev=$(grep " ${MOUNT_POINT} " /proc/mounts | awk '{print $1}' | head -1)
assert_equals "$DEVICE" "$mount_dev" "Mounted device matches"

# Verify we can list the root directory
ls "$MOUNT_POINT" > /dev/null 2>&1 || {
    test_fail "Cannot list mount point root directory"
    test_end
    exit 1
}

test_end
